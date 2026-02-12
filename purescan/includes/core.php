<?php
/**
 * PureScan Core
 * Central orchestrator: loads modules, hooks, assets, security, and admin menu.
 *
 * @package PureScan
 */
namespace PureScan;

if (!defined('ABSPATH')) {
    exit;
}

class Core {

    // === Neutralization Constants ===
    const NEUTRALIZATION_NONE               = 'none';
    const NEUTRALIZATION_PROCEDURAL         = 'php-procedural-return';
    const NEUTRALIZATION_CLASS_STUB         = 'php-class-stub';
    const NEUTRALIZATION_FULL_STUB          = 'php-full-namespace-stub';
    const NEUTRALIZATION_JS_WRAPPER         = 'js-safe-wrapper';
    const NEUTRALIZATION_HTML_SANITIZE      = 'html-sanitize';
    const NEUTRALIZATION_CSS_CLEAN          = 'css-clean';

    const RISK_THRESHOLD_CRITICAL = 90;
    const RISK_THRESHOLD_HIGH     = 70;

    /**
     * Paths to critical WordPress core files that should never be automatically neutralized.
     *
     * @var array
     */
    private $critical_paths = [
        'wp-config.php',
        'wp-settings.php',
        'wp-load.php',
        'wp-blog-header.php',
        'index.php',
        '.htaccess',
        'wp-admin/admin.php',
        'wp-admin/load-scripts.php',
        'wp-admin/load-styles.php',
        'wp-includes/functions.php',
        'wp-includes/class-wp-hook.php',
        'wp-includes/plugin.php',
        'wp-includes/default-filters.php',
    ];

    /** @var string Current active admin tab */
    private $current_tab = 'deep-scan';

    /**
     * Constructor.
     * Initializes all hooks, loads required modules, and sets up the plugin core.
     */
    public function __construct() {

        // === Load External Scan Modules ===
        require_once PURESCAN_DIR . 'includes/external/class-external-policy.php';
        require_once PURESCAN_DIR . 'includes/external/class-external-zero-risk-trait.php';
        require_once PURESCAN_DIR . 'includes/runtime-guard.php';
        require_once PURESCAN_DIR . 'includes/ai-client.php';
        require_once PURESCAN_DIR . 'includes/ai/ai-scanner.php';
        require_once PURESCAN_DIR . 'includes/ai/ai-scan-ui.php';
        require_once PURESCAN_DIR . 'includes/help/class-help-ui.php';
        require_once PURESCAN_DIR . 'includes/email-notifier.php';
        require_once PURESCAN_DIR . 'includes/integrity.php';
        require_once PURESCAN_DIR . 'includes/scan/class-spamvertising-checker.php';

        // Core hooks
        add_action('admin_menu', [$this, 'register_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('admin_notices', [$this, 'show_scheduled_scan_indicator']);

        // File view and tab routing (priority ensures correct order)
        add_action('admin_init', [$this, 'handle_file_view_requests'], 5);
        add_action('admin_init', [$this, 'handle_tab_routing'], 10);

        // AJAX handlers
        add_action('wp_ajax_purescan_scan_start', ['PureScan\Scan\Scan_Ajax', 'start_scan']);
        add_action('wp_ajax_purescan_scan_cancel', ['PureScan\Scan\Scan_Ajax', 'cancel_scan']);
        add_action('wp_ajax_purescan_scan_progress', ['PureScan\Scan\Scan_Ajax', 'get_progress']);
        add_action('wp_ajax_purescan_scan_clear', ['PureScan\Scan\Scan_Ajax', 'clear_results']);
        add_action('wp_ajax_purescan_scan_single', ['PureScan\Scan\Scan_Ajax', 'scan_single_file']);
        add_action('wp_ajax_purescan_scan_load_snippets', ['PureScan\Scan\Scan_Result', 'load_snippets']);
        add_action('wp_ajax_purescan_search_live', ['PureScan\Search\Search_Ajax', 'live_search']);
        add_action('wp_ajax_purescan_search_scan_file', ['PureScan\Search\Search_Ajax', 'scan_file_from_search']);
        add_action('wp_ajax_purescan_settings_save', ['PureScan\Settings\Settings_Handler', 'save_settings']);
        add_action('wp_ajax_purescan_test_openrouter', ['\PureScan\Settings\Settings_Handler', 'test_openrouter_connection']);
        add_action('wp_ajax_purescan_ai_scan_file', ['PureScan\AI\AI_Scanner', 'scan_file_via_ai']);
        add_action('wp_ajax_purescan_ai_scan_batch', ['PureScan\AI\AI_Scanner', 'process_ai_batch']);
        add_action('wp_ajax_purescan_ai_get_status', ['PureScan\AI\AI_Scanner', 'get_ai_scan_status']);
        add_action('wp_ajax_purescan_ai_scan_code', ['PureScan\AI\AI_Scanner', 'scan_file_via_ai']);
        add_action('wp_ajax_purescan_force_ai_analysis', ['PureScan\AI\AI_Scanner', 'force_ai_analysis']);
        add_action('wp_ajax_purescan_quarantine_file', [$this, 'ajax_quarantine_file']);
        add_action('wp_ajax_purescan_restore_file', [$this, 'ajax_restore_file']);
        add_action('wp_ajax_purescan_ignore_file', [$this, 'ajax_ignore_file']);
        add_action('wp_ajax_purescan_unignore_file', [$this, 'ajax_unignore_file']);
        add_action('wp_ajax_purescan_non_ai_scan_code', ['PureScan\AI\AI_Scanner', 'non_ai_scan_code']);

        // Cleanup scheduled actions
        add_action('purescan_cleanup_old_results', ['PureScan\Scan\Scan_Result', 'cleanup_old_results']);
        add_action('purescan_cleanup_ai_queue', ['PureScan\AI\AI_Scanner', 'cleanup_stale_queue']);

        // Real-time connection & integrity status check
        add_action('wp_ajax_purescan_check_connection_status', [$this, 'ajax_check_connection_status']);

        // Scheduled Automatic Scan Hook
        add_action('purescan_scheduled_scan', ['\PureScan\Settings\Settings_Handler', 'run_scheduled_scan_callback']);

        // Dismiss missed scheduled scan notice
        add_action('wp_ajax_purescan_dismiss_missed_notice', function () {
            check_ajax_referer(PURESCAN_NONCE, 'nonce');
            if (current_user_can('manage_options')) {
                delete_option('purescan_last_scheduled_missed');
            }
            wp_die();
        });

        // ==================================================================
        // Hybrid Background Execution for Scheduled Scans (Shared-Hosting Friendly)
        // ==================================================================
        add_action('admin_init', [$this, 'maybe_run_background_chunk']);
        add_action('admin_head', [$this, 'maybe_run_background_chunk']);
        add_action('wp_login', [$this, 'maybe_run_background_chunk']);
        add_action('wp_ajax_heartbeat', [$this, 'maybe_run_background_chunk']);
        add_action('wp_ajax_nopriv_heartbeat', [$this, 'maybe_run_background_chunk']);
        add_action('wp_head', [$this, 'maybe_run_background_chunk']);

        // Plugin upgrade handling
        add_action('upgraded_plugin_' . PURESCAN_BASENAME, [$this, 'handle_upgrade']);
    }

    /**
     * Retrieve all important counters in one place.
     * Used for badge counts in menu and sidebar.
     *
     * @return array {
     *     @type int $threats     Number of suspicious findings.
     *     @type int $quarantine  Number of quarantined files.
     *     @type int $ignored     Number of ignored files.
     * }
     */
    private function get_counters(): array {
        $state            = get_option(PURESCAN_STATE, []);
        $threat_count     = (int) ($state['suspicious'] ?? 0);
        $quarantined_files = get_option('purescan_bne_quarantined', []);
        $quarantine_count  = count($quarantined_files);
        $ignored_files     = get_option('purescan_ignored_files', []);
        $ignored_count     = count($ignored_files);

        return [
            'threats'    => $threat_count,
            'quarantine' => $quarantine_count,
            'ignored'    => $ignored_count,
        ];
    }

    /**
     * Render a colored badge for counters.
     *
     * Displays a visual badge with the count when greater than zero.
     * Used in admin menu and sidebar for threats, quarantine, and ignored items.
     *
     * @param string $type  Type of badge: 'threats', 'quarantine', or 'ignored'.
     * @param int    $count The numeric count to display.
     *
     * @return string HTML for the badge, or empty string if count is zero.
     */
    private function render_counter_badge( string $type, int $count ): string {
        if ( $count <= 0 ) {
            return '';
        }
    
        // Determine extra CSS class based on type
        $extra_class = $type === 'quarantine' ? 'purescan-quarantine-badge' :
                       ( $type === 'ignored' ? 'purescan-ignored-badge' : '' );
    
        // Determine background color based on type
        $bg_color = $type === 'ignored' ? '#fcb214' : '#d63638';
    
        // Build the badge HTML directly (no translation needed)
        return '<span class="awaiting-mod ' . esc_attr( $extra_class ) . ' count-' . (int) $count . '" style="background:' . esc_attr( $bg_color ) . ';">' .
               '<span class="purescan-threat-count">' . number_format_i18n( $count ) . '</span>' .
               '</span>';
    }

    /**
     * Register the main admin menu and hidden submenus.
     *
     * Creates the top-level menu item and hidden submenu pages for clean,
     * tab-based URLs. Badges are dynamically added to relevant menu items.
     */
    public function register_admin_menu(): void {
        $counters = $this->get_counters();
        $menu_label = esc_html__( 'PureScan', 'purescan' ) . $this->render_counter_badge( 'threats', $counters['threats'] );
    
        // Main menu item
        add_menu_page(
            esc_html__( 'PureScan', 'purescan' ), // Page title
            $menu_label, // Menu title with badge
            'manage_options', // Capability
            'purescan', // Menu slug
            [ $this, 'render_page' ], // Callback
            'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTEiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMSAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik01LjUgMEM1LjcxNjAzIDAgNS45MzEyIDAuMDY1NTA0MSA2LjEzNzI0IDAuMTQyNTMzQzYuMzQ5NjMgMC4yMjE5NDMgNi42MTQ1MyAwLjMzODczNSA2Ljk0MDQ3IDAuNDgyMTQyQzcuNDA5MzIgMC42ODg0MzcgNy45OTUzNCAwLjkxNDAxMyA4LjY1ODYxIDEuMTAwODlDOS4xNTQyNSAxLjI0MDU0IDkuNTYxNDIgMS4zNTQ2OSA5Ljg3MDE0IDEuNDczMzRDMTAuMTc1NCAxLjU5MDY5IDEwLjQ3MDMgMS43NDI0NyAxMC42NzE2IDIuMDA2NTFDMTAuODY1NSAyLjI2MTA4IDEwLjkzNyAyLjU1NDkzIDEwLjk2OTIgMi44NTY0OUMxMS4wMDA3IDMuMTUxNTEgMTEgMy41MjEwNyAxMSAzLjk1OTQ5VjUuNTUxOTZDMTEgNy4yNjE2OSAxMC4yMjA3IDguNjE0OCA5LjI4NjIyIDkuNjE4MjJDOC40MTM0MiAxMC41NTU0IDcuMzg1NzcgMTEuMjEwMiA2LjY2MTA3IDExLjYwMkw2LjUyMDMxIDExLjY3NjlDNi4xOTk1OCAxMS44NDQ2IDUuOTIxNjYgMTIgNS41IDEyQzUuMDc4MzQgMTIgNC44MDA0MyAxMS44NDQ2IDQuNDc5NyAxMS42NzY5QzMuNzUxOTMgMTEuMjk2MiAyLjY0NDc0IDEwLjYxNzggMS43MTM3OSA5LjYxODIyQzAuNzkzODYgOC42MzA0NyAwLjAyNDQzMSA3LjMwMzg3IDAuMDAwNjExMDg5IDUuNjMxODFMMy4wNDA1NGUtMDYgNS41NTE5NlYzLjgwMjQ5Qy0xLjYxNTI2ZS0wNiAzLjM2OTM3IC0wLjAwMDg5MDE2IDMuMDMyMzggMC4wMzE5MjU2IDIuNzcwNDFDMC4wNjg2NjgyIDIuNDc3MTIgMC4xNTEwNzYgMi4yMzk0IDAuMzI4NTUyIDIuMDA2NTFDMC41Mjk3NzkgMS43NDI0OCAwLjgyNDY2MyAxLjU5MDY4IDEuMTI5OTYgMS40NzMzNEMxLjQzODY3IDEuMzU0NyAxLjg0NTc4IDEuMjQwNTMgMi4zNDEzOSAxLjEwMDg5QzMuMDA0NjcgMC45MTQwMDggMy41OTA2NiAwLjY4ODQzOSA0LjA1OTUzIDAuNDgyMTQyTDQuMjkyNzIgMC4zNzk3ODdDNC41MTQ2NiAwLjI4MjczNSA0LjcwMzQ4IDAuMjAyMDg4IDQuODYyNzcgMC4xNDI1MzNDNS4wNjg4IDAuMDY1NTA0MiA1LjI4Mzk3IDcuNDY5MzZlLTA3IDUuNSAwWk01LjUgNS45OTk5NUgxLjA2MDEzQzEuMTc4MDQgNy4xNzIzNyAxLjc1MDA5IDguMTQwNzkgMi40NzYyOCA4LjkyMDUyQzMuMjk2NTYgOS44MDEyOCA0LjI5MDg1IDEwLjQxNTEgNC45NjQwMSAxMC43NjcyQzUuMjcxMzUgMTAuOTI4IDUuMzU0MjIgMTAuOTYzNyA1LjQ1NTAxIDEwLjk3MDFMNS41IDEwLjk3MTRWNS45OTk5NUg5LjkzOTg3QzkuOTU0NTYgNS44NTM4IDkuOTYyMjYgNS43MDQ0OCA5Ljk2MjI2IDUuNTUxOTZWMy45NTk0OUM5Ljk2MjI2IDMuNDk4MzEgOS45NjE2MSAzLjE5MzAzIDkuOTM3MjMgMi45NjQ4N0M5LjkxNjUxIDIuNzcwOTQgOS44ODI5NiAyLjY4NzAzIDkuODU1MDQgMi42NDMwNEw5Ljg0MzQ5IDIuNjI2NDdDOS44MjEwNyAyLjU5NzA0IDkuNzUxMTcgMi41MzA4MSA5LjQ5NDg4IDIuNDMyM0M5LjI0MiAyLjMzNTExIDguODkwNTYgMi4yMzU1OCA4LjM3NDg1IDIuMDkwMjhDNy42NTYxNSAxLjg4Nzc5IDcuMDIzODUgMS42NDQxOCA2LjUxOTM5IDEuNDIyMjJDNi4xODE4MyAxLjI3MzcgNS45NDkwMSAxLjE3MTQ3IDUuNzcwOTkgMS4xMDQ5MUM1LjYwOTY3IDEuMDQ0NiA1LjUzNzQzIDEuMDMxMzMgNS41MDk0MyAxLjAyODk3TDUuNSAxLjAyODU3VjUuOTk5OTVaTTEuOTcxNyAyLjYwNTY3QzEuNTcwNTEgMi42MDU2OCAxLjI0NTI5IDIuOTI4MDMgMS4yNDUyOSAzLjMyNTY3QzEuMjQ1MjkgMy43MjMzMSAxLjU3MDUxIDQuMDQ1NjcgMS45NzE3IDQuMDQ1NjdDMi4zNzI4OSA0LjA0NTY3IDIuNjk4MTIgMy43MjMzMiAyLjY5ODEyIDMuMzI1NjdDMi42OTgxMiAyLjkyODAzIDIuMzcyODkgMi42MDU2NyAxLjk3MTcgMi42MDU2N1oiIGZpbGw9IndoaXRlIi8+Cjwvc3ZnPgo=',
            65
        );
    
        // Base tabs (Deep Scan and Live Search always first)
        $tabs = [
            'deep-scan' => esc_html__( 'Deep Scan', 'purescan' ),
            'live-search' => esc_html__( 'Live Search', 'purescan' ),
        ];

        // Add AI Scan immediately after Live Search if Pro is active
        if ( $this->is_pro() ) {
            $tabs['ai-scan'] = esc_html__( 'AI Scan', 'purescan' );
        }

        // Remaining standard tabs (in fixed order)
        $tabs += [
            'quarantine' => esc_html__( 'Quarantine', 'purescan' ),
            'ignored' => esc_html__( 'Ignored', 'purescan' ),
            'settings' => esc_html__( 'Settings', 'purescan' ),
            'help' => esc_html__( 'Help & Documentation', 'purescan' ),
        ];

        // Create hidden submenu pages for each tab (clean URLs)
        foreach ( $tabs as $tab => $title ) {
            $submenu_title = $title;
   
            // Add badge to specific tabs
            if ( $tab === 'deep-scan' ) {
                $submenu_title .= $this->render_counter_badge( 'threats', $counters['threats'] );
            }
            if ( $tab === 'quarantine' || $tab === 'ignored' ) {
                $badge_type = $tab === 'ignored' ? 'ignored' : 'quarantine';
                $badge_count = $tab === 'ignored' ? $counters['ignored'] : $counters['quarantine'];
                $submenu_title .= $this->render_counter_badge( $badge_type, $badge_count );
            }
   
            add_submenu_page(
                'purescan', // Parent slug
                $title, // Page title
                $submenu_title, // Menu title (with badge if applicable)
                'manage_options', // Capability
                'purescan-tab-' . $tab, // Menu slug
                '__return_false' // No callback needed (handled by routing)
            );
        }
    
        // Remove the default submenu item that duplicates the main menu
        remove_submenu_page( 'purescan', 'purescan' );
    
        // Scripts for real-time badge updates (only counters now)
        add_action( 'admin_head', [ $this, 'inject_badge_updater_script' ] );
    
        // Late menu badge update (for dynamic changes on other admin pages)
        add_action( 'admin_menu', [ $this, 'update_menu_badge_late' ], 9999 );
    }

    /**
     * Updates the main admin menu badge dynamically.
     *
     * Runs late in the 'admin_menu' hook to ensure the global $menu array is fully populated.
     * Updates the top-level PureScan menu item with the current threat count badge.
     */
    public function update_menu_badge_late(): void {
        global $menu;

        if ( ! current_user_can( 'manage_options' ) || ! is_array( $menu ) ) {
            return;
        }

        $counters = $this->get_counters();

        foreach ( $menu as $key => $item ) {
            if ( isset( $item[2] ) && $item[2] === 'purescan' ) {
                $menu[ $key ][0] = esc_html__( 'PureScan', 'purescan' ) . $this->render_counter_badge( 'threats', $counters['threats'] );
                break;
            }
        }
    }

    /**
     * Injects JavaScript to update menu and sidebar badges in real-time.
     *
     * Only counters are updated (patterns source badge completely removed).
     */
    public function inject_badge_updater_script(): void {
        if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
            return;
        }
    
        $counters = $this->get_counters();
        ?>
        <script type="text/javascript">
        document.addEventListener('DOMContentLoaded', function() {
            /* ============ Initial State ============ */
            let lastThreatCount = <?php echo (int) $counters['threats']; ?>;
            let lastQuarantineCount = <?php echo (int) $counters['quarantine']; ?>;
            let lastIgnoredCount = <?php echo (int) $counters['ignored']; ?>;
    
            /* ============ Admin Menu Badges ============ */
            function updateThreatBadge(newCount) {
                const mainMenuItem = document.querySelector('#adminmenu a.toplevel_page_purescan .wp-menu-name');
                if (mainMenuItem) {
                    const oldBadge = mainMenuItem.querySelector('.awaiting-mod');
                    if (oldBadge) oldBadge.remove();
    
                    if (newCount > 0) {
                        const badge = document.createElement('span');
                        badge.className = 'awaiting-mod count-' + newCount;
                        badge.innerHTML = '<span class="purescan-threat-count">' + newCount + '</span>';
                        mainMenuItem.appendChild(badge);
    
                        badge.style.animation = 'none';
                        badge.offsetHeight;
                        badge.style.animation = 'purescan-badge-pulse 1.2s ease-out';
                    }
                }
    
                const deepScanLink = document.querySelector('#adminmenu a[href*="purescan-tab-deep-scan"]');
                if (deepScanLink) {
                    let badge = deepScanLink.querySelector('.awaiting-mod');
                    if (newCount <= 0) {
                        if (badge) badge.remove();
                    } else {
                        if (badge) {
                            badge.innerHTML = '<span class="purescan-threat-count">' + newCount + '</span>';
                            badge.className = badge.className.replace(/count-\d+/, 'count-' + newCount);
                        } else {
                            badge = document.createElement('span');
                            badge.className = 'awaiting-mod count-' + newCount;
                            badge.innerHTML = '<span class="purescan-threat-count">' + newCount + '</span>';
                            deepScanLink.appendChild(badge);
                        }
                    }
                }
            }
    
            function updateQuarantineBadge(newCount) {
                const link = document.querySelector('#adminmenu a[href*="purescan-tab-quarantine"]');
                if (!link) return;
    
                let badge = link.querySelector('.awaiting-mod');
                if (newCount <= 0) {
                    if (badge) badge.remove();
                    return;
                }
    
                if (!badge) {
                    badge = document.createElement('span');
                    badge.className = 'awaiting-mod purescan-quarantine-badge count-' + newCount;
                    badge.innerHTML = '<span class="purescan-threat-count">' + newCount + '</span>';
                    link.appendChild(badge);
                } else {
                    badge.classList.add('purescan-quarantine-badge');
                    const span = badge.querySelector('.purescan-threat-count');
                    if (span) span.textContent = newCount;
                    badge.className = badge.className.replace(/count-\d+/, 'count-' + newCount);
                }
            }
    
            function updateIgnoredBadge(newCount) {
                const link = document.querySelector('#adminmenu a[href*="purescan-tab-ignored"]');
                if (!link) return;
    
                let badge = link.querySelector('.awaiting-mod');
                if (newCount <= 0) {
                    if (badge) badge.remove();
                    return;
                }
    
                if (!badge) {
                    badge = document.createElement('span');
                    badge.className = 'awaiting-mod purescan-ignored-badge count-' + newCount;
                    badge.style.background = '#fcb214';
                    badge.innerHTML = '<span class="purescan-threat-count">' + newCount + '</span>';
                    link.appendChild(badge);
                } else {
                    badge.classList.add('purescan-ignored-badge');
                    badge.style.background = '#fcb214';
                    const span = badge.querySelector('.purescan-threat-count');
                    if (span) span.textContent = newCount;
                    badge.className = badge.className.replace(/count-\d+/, 'count-' + newCount);
                }
            }
    
            /* ============ Internal Sidebar Badges ============ */
            function updateInternalThreatBadge(newCount) {
                const link = document.querySelector('.purescan-sidebar a[href*="&tab=deep-scan"]');
                if (!link) return;
                updateSidebarBadge(link, newCount, '#d63638');
            }
    
            function updateInternalQuarantineBadge(newCount) {
                const link = document.querySelector('.purescan-sidebar a[href*="&tab=quarantine"]');
                if (!link) return;
                updateSidebarBadge(link, newCount, '#d63638', 'purescan-quarantine-badge');
            }
    
            function updateInternalIgnoredBadge(newCount) {
                const link = document.querySelector('.purescan-sidebar a[href*="&tab=ignored"]');
                if (!link) return;
                updateSidebarBadge(link, newCount, '#fcb214', 'purescan-ignored-badge');
            }
    
            function updateSidebarBadge(link, newCount, bgColor, extraClass = '') {
                let badge = link.querySelector('.awaiting-mod');
                if (newCount <= 0) {
                    if (badge) badge.remove();
                    return;
                }
    
                if (!badge) {
                    badge = document.createElement('span');
                    badge.className = 'awaiting-mod ' + extraClass + ' count-' + newCount;
                    badge.style.background = bgColor;
                    badge.innerHTML = '<span class="purescan-threat-count">' + newCount + '</span>';
                    link.appendChild(badge);
                } else {
                    if (extraClass) badge.classList.add(extraClass);
                    badge.style.background = bgColor;
                    const span = badge.querySelector('.purescan-threat-count');
                    if (span) span.textContent = newCount;
                    badge.className = badge.className.replace(/count-\d+/, 'count-' + newCount);
                }
            }
    
            /* ============ Polling – Only counters ============ */
            setInterval(function() {
                fetch(ajaxurl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'action=purescan_scan_progress&nonce=<?php echo esc_js( wp_create_nonce( PURESCAN_NONCE ) ); ?>'
                })
                .then(response => {
                    if (!response.ok) throw new Error('Network error: ' + response.status);
                    return response.json();
                })
                .then(res => {
                    if (!res || !res.success || !res.data) return;
    
                    const data = res.data;
    
                    if (data.counters) {
                        const c = data.counters;
    
                        if (c.threats !== lastThreatCount) {
                            lastThreatCount = c.threats;
                            updateThreatBadge(c.threats);
                            updateInternalThreatBadge(c.threats);
                        }
                        if (c.quarantine !== lastQuarantineCount) {
                            lastQuarantineCount = c.quarantine;
                            updateQuarantineBadge(c.quarantine);
                            updateInternalQuarantineBadge(c.quarantine);
                        }
                        if (c.ignored !== lastIgnoredCount) {
                            lastIgnoredCount = c.ignored;
                            updateIgnoredBadge(c.ignored);
                            updateInternalIgnoredBadge(c.ignored);
                        }
                    }
                })
                .catch(err => {
                    console.warn('PureScan badge polling:', err.message);
                });
            }, 30000);
    
            /* ============ Initial Render ============ */
            updateThreatBadge(lastThreatCount);
            updateQuarantineBadge(lastQuarantineCount);
            updateIgnoredBadge(lastIgnoredCount);
            updateInternalThreatBadge(lastThreatCount);
            updateInternalQuarantineBadge(lastQuarantineCount);
            updateInternalIgnoredBadge(lastIgnoredCount);
        });
        </script>
        <?php
    }

    /**
     * Handle all view requests for files and content.
     *
     * Securely displays full file content, diff views, or database content (posts/comments).
     * Supports both internal WordPress files and external paths when applicable.
     * Exits after rendering to prevent further page processing.
     */
    public function handle_file_view_requests(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
    
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Secure admin viewer: capability checked above, no state change (only display).
        if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'purescan' ) {
            return;
        }
    
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Secure admin viewer: capability checked above, no state change (only display).
        $action = isset( $_GET['action'] ) ? sanitize_text_field( wp_unslash( $_GET['action'] ) ) : '';
    
        // === File viewers (full content or diff) ===
        if ( in_array( $action, [ 'view_full', 'view_diff' ], true ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Secure admin viewer: capability checked above, no state change (only display).
            $file = isset( $_GET['file'] ) ? sanitize_text_field( wp_unslash( $_GET['file'] ) ) : '';
    
            if ( empty( $file ) ) {
                return;
            }
    
            // Resolve real path with support for internal and external files
            $internal_candidate = ABSPATH . ltrim( $file, '/' );
            $real_path = realpath( $internal_candidate );
    
            if ( ! $real_path || ! is_file( $real_path ) ) {
                $external_candidate = '/' . ltrim( $file, '/' );
                $real_path = realpath( $external_candidate );
            }
    
            if ( ! $real_path || ! is_file( $real_path ) || ! is_readable( $real_path ) ) {
                wp_die( esc_html__( 'File not found or access denied.', 'purescan' ), esc_html__( 'Error', 'purescan' ), [ 'response' => 404 ] );
            }
    
            $content = file_get_contents( $real_path );
    
            if ( $action === 'view_full' ) {
                require_once PURESCAN_DIR . 'includes/file-viewer.php';
                purescan_render_file_viewer( $file, $content );
            } elseif ( $action === 'view_diff' ) {
                require_once PURESCAN_DIR . 'includes/file-diff.php';
                purescan_render_file_diff( $file, $content );
            }
    
            exit;
        }
    
        // === Database content viewer (posts/comments) ===
        if ( $action === 'view_content' ) {
            require_once PURESCAN_DIR . 'includes/content-viewer.php';
            purescan_render_content_viewer();
            exit;
        }
    }

    /**
     * Highlight suspicious lines in file content.
     *
     * Adds ">>>" marker to lines identified as dangerous in scan snippets.
     * Used for visual emphasis in file viewers.
     *
     * @param string $content  Full file content.
     * @param array  $snippets Scan findings with line information.
     *
     * @return string Modified content with highlighted lines.
     */
    private function highlight_suspicious_sections( string $content, array $snippets ): string {
        $lines           = explode( "\n", $content );
        $dangerous_lines = [];

        foreach ( $snippets as $snippet ) {
            if ( ! empty( $snippet['snippet_lines'] ) ) {
                foreach ( $snippet['snippet_lines'] as $l ) {
                    if ( ! empty( $l['dangerous'] ) ) {
                        $dangerous_lines[ $l['line'] ] = true;
                    }
                }
            }
        }

        foreach ( $lines as $i => $line ) {
            $line_num = $i + 1;
            if ( isset( $dangerous_lines[ $line_num ] ) ) {
                $lines[ $i ] = ">>> " . $line;
            }
        }

        return implode( "\n", $lines );
    }

    /**
     * Handle tab routing and redirect to canonical URLs.
     *
     * Ensures clean, consistent URLs for all tabs and prevents duplicate content.
     * Skips redirect for file/content view actions to avoid breaking them.
     */
    public function handle_tab_routing(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
    
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Secure admin routing: capability checked above, no state change (only redirect for clean URLs).
        if ( ! isset( $_GET['page'] ) ) {
            return;
        }
    
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Secure admin routing: capability checked above, no state change (only redirect for clean URLs).
        $page = sanitize_text_field( wp_unslash( $_GET['page'] ) );
    
        // Prevent redirect interference with file/content viewers
        $view_actions = [ 'view_suspicious', 'view_full', 'view_diff' ];
    
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Secure admin routing: capability checked above, no state change (only redirect for clean URLs).
        if ( $page === 'purescan' && ! empty( $_GET['action'] ) && in_array( $_GET['action'], $view_actions, true ) ) {
            return;
        }
    
        if ( strpos( $page, 'purescan-tab-' ) !== 0 && $page !== 'purescan' ) {
            return;
        }
    
        // Determine current tab
        if ( strpos( $page, 'purescan-tab-' ) === 0 ) {
            $tab = substr( $page, strlen( 'purescan-tab-' ) );
        } else {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Secure admin routing: capability checked above, no state change (only redirect for clean URLs).
            $tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'deep-scan';
        }
    
        // Base allowed tabs (always available in free version)
        $allowed_tabs = [
            'deep-scan',
            'live-search',
            'quarantine',
            'ignored',
            'settings',
            'help',
        ];
    
        // Add Pro-only tabs if Pro is active
        if ( $this->is_pro() ) {
            $allowed_tabs[] = 'ai-scan';
            $allowed_tabs[] = 'upgrade';
        }
    
        // Validate tab – fallback to deep-scan if invalid or Pro-only tab accessed without Pro
        $this->current_tab = in_array( $tab, $allowed_tabs, true ) ? $tab : 'deep-scan';
    
        // Redirect to canonical URL if needed
        $redirect_url = admin_url( 'admin.php?page=purescan&tab=' . $this->current_tab );
    
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Secure admin routing: capability checked above, no state change (only redirect for clean URLs).
        if ( $page !== 'purescan' || ! isset( $_GET['tab'] ) ) {
            wp_safe_redirect( $redirect_url );
            exit;
        }
    
        // Store current tab globally for use in rendering
        $GLOBALS['purescan_current_tab'] = $this->current_tab;
    }

    /**
     * Render the main admin page layout.
     *
     * Outputs the full admin interface with header, sidebar navigation,
     * and dynamic tab content. Includes version badge, license status,
     * and real-time counters in sidebar.
     */
    public function render_page(): void {
       
        $counters = $this->get_counters();
        ?>
        <div class="wrap purescan-admin-wrap">
            <h1 class="wp-heading-inline">
                <span class="purescan-logo-svg" style="display: inline-block; width: 36px; height: 36px; vertical-align: -10px; margin-right: 8px;">
                    <svg width="33" height="36" viewBox="0 0 33 36" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path fill-rule="evenodd" clip-rule="evenodd" d="M16.5 0C17.1481 0 17.7936 0.196512 18.4117 0.427599C19.0489 0.66583 19.8436 1.01621 20.8214 1.44642C22.228 2.06531 23.986 2.74204 25.9758 3.30267C27.4628 3.72162 28.6843 4.06407 29.6104 4.42003C30.5263 4.77206 31.411 5.2274 32.0147 6.01954C32.5966 6.78324 32.8109 7.6648 32.9076 8.56946C33.0021 9.45453 33 10.5632 33 11.8785V16.6559C33 21.7851 30.6622 25.8444 27.8586 28.8547C25.2403 31.6661 22.1573 33.6305 19.9832 34.8061L19.5609 35.0306C18.5987 35.5339 17.765 36 16.5 36C15.235 36 14.4013 35.5339 13.4391 35.0306C11.2558 33.8885 7.93423 31.8534 5.14136 28.8547C2.38158 25.8914 0.0732929 21.9116 0.00183327 16.8954L9.12162e-06 16.6559V11.4075C-4.84578e-06 10.1081 -0.00267048 9.09713 0.0957767 8.31122C0.206005 7.43137 0.453228 6.7182 0.985655 6.01954C1.58934 5.22744 2.47399 4.77205 3.38988 4.42003C4.31602 4.06409 5.53733 3.72159 7.02418 3.30267C9.014 2.74203 10.772 2.06532 12.1786 1.44642L12.8782 1.13936C13.544 0.848206 14.1104 0.606265 14.5883 0.427599C15.2064 0.196513 15.8519 2.24081e-06 16.5 0ZM16.5 17.9998H3.1804C3.53413 21.5171 5.25027 24.4224 7.42884 26.7616C9.88968 29.4038 12.8726 31.2453 14.892 32.3017C15.814 32.784 16.0627 32.8911 16.365 32.9104L16.5 32.9143V17.9998H29.8196C29.8637 17.5614 29.8868 17.1134 29.8868 16.6559V11.8785C29.8868 10.4949 29.8848 9.5791 29.8117 8.89461C29.7495 8.31282 29.6489 8.06109 29.5651 7.92912L29.5305 7.8794C29.4632 7.79112 29.2535 7.59242 28.4846 7.29691C27.726 7.00534 26.6717 6.70675 25.1246 6.27085C22.9684 5.66337 21.0715 4.93253 19.5582 4.26665C18.5455 3.82109 17.847 3.5144 17.313 3.31472C16.829 3.13379 16.6123 3.09399 16.5283 3.08691L16.5 3.08571V17.9998ZM5.9151 7.81702C4.71154 7.81703 3.73586 8.78409 3.73586 9.97701C3.73586 11.1699 4.71154 12.137 5.9151 12.137C7.11866 12.137 8.09435 11.1699 8.09435 9.97701C8.09435 8.78408 7.11866 7.81702 5.9151 7.81702Z" fill="#10B981"/>
                    </svg>
                </span>
                    <?php esc_html_e( 'PureScan', 'purescan' ); ?>
                    <span class="purescan-version">v<?php echo esc_html( PURESCAN_VERSION ); ?></span>
                    <?php
                    $is_pro = $this->is_pro();
                    $plugin_modified = get_option( 'purescan_plugin_files_modified', false );
             
                    if ( $is_pro ) {
                        $cache = get_transient( 'purescan_pro_status_' . md5( wp_parse_url( home_url(), PHP_URL_HOST ) ) );
                        $data = $cache ? maybe_unserialize( $cache ) : [];
                        $plan = $data['plan'] ?? '';
                        $main_text = esc_html__( 'Pro', 'purescan' ) . ( $plan ? ' (' . esc_html( $plan ) . ')' : '' );
                        $main_style = 'background:#10b981; color:white; border:none;';
                    } else {
                        $main_text = esc_html__( 'Lite', 'purescan' );
                        $main_style = 'background:#f59e0b; color:#fff; border:none;';
                    }
             
                    $tampered_text = esc_html__( 'Tampered', 'purescan' );
                    $tampered_style = 'background:#dc2626; color:white; border:none;';
                    ?>
                    <span class="purescan-status-badge" style="<?php echo esc_attr( $main_style ); ?>">
                        <?php echo esc_html( $main_text ); ?>
                    </span>
             
                    <?php if ( $plugin_modified ) : ?>
                    <span class="purescan-status-badge" style="<?php echo esc_attr( $tampered_style ); ?>">
                        <?php echo esc_html( $tampered_text ); ?>
                    </span>
                    <?php endif; ?>
                </h1>
            <hr class="wp-header-end">
            <div class="purescan-layout">
                <!-- Sidebar Navigation -->
                <div class="purescan-sidebar">
                    <ul class="purescan-nav">
                        <?php
                        // Base tabs (Deep Scan and Live Search always first)
                        $sidebar_tabs = [
                            'deep-scan',
                            'live-search',
                        ];
                        // Add AI Scan immediately after Live Search if Pro is active
                        if ( $this->is_pro() ) {
                            $sidebar_tabs[] = 'ai-scan';
                        }
                        // Remaining standard tabs (in fixed order)
                        $sidebar_tabs = array_merge($sidebar_tabs, [
                            'quarantine',
                            'ignored',
                            'settings',
                            'help',
                        ]);
                        // Add Upgrade tab at the end if Pro is active
                        if ( $this->is_pro() ) {
                            $sidebar_tabs[] = 'upgrade';
                        }
              
                        foreach ( $sidebar_tabs as $tab ) :
                            $link = admin_url( 'admin.php?page=purescan&tab=' . $tab );
                            $title = esc_html( $this->get_tab_title( $tab ) );
                            $is_active = $this->current_tab === $tab;
                            $badge = '';
              
                            // Add counter badges
                            if ( $tab === 'deep-scan' ) {
                                $badge = $this->render_counter_badge( 'threats', $counters['threats'] );
                            }
                            if ( $tab === 'quarantine' ) {
                                $badge = $this->render_counter_badge( 'quarantine', $counters['quarantine'] );
                            }
                            if ( $tab === 'ignored' ) {
                                $badge = $this->render_counter_badge( 'ignored', $counters['ignored'] );
                            }
              
                            // Special title for Upgrade tab
                            if ( $tab === 'upgrade' ) {
                                $title = esc_html__( 'Upgrade to Pro', 'purescan' );
                            }
                            ?>
                            <li>
                                <a href="<?php echo esc_url( $link ); ?>"
                                   class="<?php echo $is_active ? 'active' : ''; ?>">
                                    <span class="dashicons <?php echo esc_attr( $this->get_tab_icon( $tab ) ); ?>"></span>
                                    <?php echo $title . $badge; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                                </a>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
                <!-- Main Content Area -->
                <div class="purescan-content">
                    <?php $this->render_tab_content( $this->current_tab ); ?>
                </div>
            </div>
        <?php
    }

    /**
     * Render the content for the current active tab.
     *
     * Delegates rendering to the appropriate UI class based on the tab.
     *
     * @param string $tab Current tab slug.
     */
    private function render_tab_content( string $tab ): void {
        switch ( $tab ) {
            case 'deep-scan':
                \PureScan\Scan\Scan_UI::render();
                break;
            case 'live-search':
                \PureScan\Search\Search_UI::render();
                break;
            case 'ai-scan':
                \PureScan\AI\AI_Scan_UI::render();
                break;
            case 'quarantine':
                \PureScan\Scan\Quarantine_UI::render();
                break;
            case 'ignored':
                \PureScan\Scan\Ignored_UI::render();
                break;
            case 'settings':
                \PureScan\Settings\Settings_UI::render();
                break;
            case 'help':
                \PureScan\Help\Help_UI::render();
                break;
            case 'upgrade':
                if ( class_exists( '\PureScan\Pro\Upgrade_UI' ) ) {
                    \PureScan\Pro\Upgrade_UI::render();
                }
                break;
        }
    }

    /**
     * Get the human-readable title for a tab.
     *
     * @param string $tab Tab slug.
     *
     * @return string Translated tab title.
     */
    private function get_tab_title( string $tab ): string {
        $titles = [
            'deep-scan'   => esc_html__( 'Deep Scan', 'purescan' ),
            'live-search' => esc_html__( 'Live Search', 'purescan' ),
            'ai-scan'     => esc_html__( 'AI Scan', 'purescan' ),
            'quarantine'  => esc_html__( 'Quarantine', 'purescan' ),
            'ignored'     => esc_html__( 'Ignored', 'purescan' ),
            'settings'    => esc_html__( 'Settings', 'purescan' ),
            'help'        => esc_html__( 'Help & Documentation', 'purescan' ),
        ];

        return $titles[ $tab ] ?? '';
    }

    /**
     * Get the Dashicon class for a tab.
     *
     * @param string $tab Tab slug.
     *
     * @return string Dashicon class name.
     */
    private function get_tab_icon( string $tab ): string {
        $icons = [
            'deep-scan'   => 'dashicons-search',
            'live-search' => 'dashicons-admin-links',
            'ai-scan'     => 'dashicons-art',
            'quarantine'  => 'dashicons-trash',
            'ignored'     => 'dashicons-hidden',
            'settings'    => 'dashicons-admin-generic',
            'help'        => 'dashicons-book-alt',
            'upgrade'     => 'dashicons-star-filled',
        ];

        return $icons[ $tab ] ?? 'dashicons-admin-generic';
    }

    /**
     * Enqueue admin scripts and styles for PureScan pages.
     *
     * Loads core assets and tab-specific scripts. Localizes AJAX data.
     *
     * @param string $hook_suffix Current admin page hook.
     */
    public function enqueue_assets( string $hook_suffix ): void {
        if ( $hook_suffix !== 'toplevel_page_purescan' ) {
            return;
        }

        if ( ! function_exists( 'purescan_get_js_translations' ) ) {
            require_once PURESCAN_DIR . 'includes/i18n-js.php';
        }

        wp_enqueue_style( 'purescan-style', PURESCAN_URL . 'assets/css/style.css', [], PURESCAN_VERSION );

        $current_tab = $GLOBALS['purescan_current_tab'] ?? 'deep-scan';

        // Core script (always loaded)
        wp_enqueue_script( 'purescan-scan', PURESCAN_URL . 'assets/js/scan.js', [ 'jquery' ], PURESCAN_VERSION, true );

        // Tab-specific scripts
        if ( $current_tab === 'help' ) {
            wp_enqueue_script( 'purescan-help', PURESCAN_URL . 'assets/js/help.js', [ 'jquery' ], PURESCAN_VERSION, true );
        }
        if ( $current_tab === 'live-search' ) {
            wp_enqueue_script( 'purescan-search', PURESCAN_URL . 'assets/js/search.js', [ 'jquery', 'purescan-scan' ], PURESCAN_VERSION, true );
        } elseif ( $current_tab === 'settings' ) {
            wp_enqueue_script( 'purescan-settings', PURESCAN_URL . 'assets/js/settings.js', [ 'jquery' ], PURESCAN_VERSION, true );
        } elseif ( $current_tab === 'ai-scan' ) {
            wp_enqueue_script( 'purescan-ai-scan', PURESCAN_URL . 'assets/js/ai-scan.js', [ 'jquery', 'purescan-scan' ], PURESCAN_VERSION, true );
        }

        // JS translations and AJAX data
        $i18n = function_exists( 'purescan_get_js_translations' )
            ? purescan_get_js_translations()
            : [];

        $ajax_data = [
            'url'          => admin_url( 'admin-ajax.php' ),
            'nonce'        => wp_create_nonce( PURESCAN_NONCE ),
            'admin_url'    => admin_url(),
            'purescan_url' => admin_url( 'admin.php?page=purescan' ),
            'i18n'         => $i18n,
        ];

        $handles = [ 'purescan-scan' ];
        if ( $current_tab === 'live-search' ) $handles[] = 'purescan-search';
        if ( $current_tab === 'settings' )     $handles[] = 'purescan-settings';
        if ( $current_tab === 'ai-scan' )      $handles[] = 'purescan-ai-scan';
        if ( $current_tab === 'help' )         $handles[] = 'purescan-help';

        foreach ( $handles as $handle ) {
            if ( wp_script_is( $handle, 'enqueued' ) ) {
                wp_localize_script( $handle, 'PureScanAjax', $ajax_data );
            }
        }
    }

    /**
     * Handle plugin upgrade tasks.
     *
     * Updates the stored plugin version when a new version is detected.
     */
    public function handle_upgrade(): void {
        $current = get_option( 'purescan_version', '0.0.0' );

        if ( version_compare( $current, PURESCAN_VERSION, '<' ) ) {
            update_option( 'purescan_version', PURESCAN_VERSION );
        }
    }

    /**
     * Display a status badge next to the plugin version in the header.
     *
     * Shows a green badge when a scheduled scan is running,
     * or a red badge if a scheduled scan was missed.
     */
    public function show_scheduled_scan_indicator(): void {
        if ( ! current_user_can( 'manage_options' ) || ! is_admin() ) {
            return;
        }
    
        // Get current screen safely (no $_GET usage)
        $screen = get_current_screen();
        if ( ! is_object( $screen ) ) {
            return;
        }
    
        $state = get_option( PURESCAN_STATE, [] );
        $is_scheduled_running = (
            ! empty( $state['status'] ) &&
            $state['status'] === 'running' &&
            ! empty( $state['is_scheduled_scan'] )
        );
    
        $has_missed_schedule = get_option( 'purescan_last_scheduled_missed', false );
    
        // Clear missed flag only when visiting any PureScan admin page
        if ( $has_missed_schedule && strpos( $screen->id, 'purescan' ) !== false ) {
            delete_option( 'purescan_last_scheduled_missed' );
            $has_missed_schedule = false;
        }
    
        // No badge needed if nothing to show
        if ( ! $is_scheduled_running && ! $has_missed_schedule ) {
            return;
        }
    
        // Determine badge style and text
        if ( $is_scheduled_running ) {
            $bg_color   = '#ffffff';
            $text_color = '#10b981';
            $badge_text = esc_html__( 'Scheduled Active', 'purescan' );
        } else {
            $bg_color   = '#ffffff';
            $text_color = '#991b1b';
            $badge_text = esc_html__( 'Scheduled missed', 'purescan' );
        }
    
        // Only output the script if we are on a PureScan page (prevents unnecessary JS on other admin pages)
        if ( strpos( $screen->id, 'purescan' ) === false ) {
            return;
        }
        ?>
        <script type="text/javascript">
        document.addEventListener('DOMContentLoaded', function () {
            const header = document.querySelector('.wp-heading-inline');
            if (!header) return;
    
            const versionSpan = header.querySelector('.purescan-version');
            if (!versionSpan) return;
    
            // Remove any existing badge
            const oldBadge = document.querySelector('.purescan-scheduled-badge');
            if (oldBadge) oldBadge.remove();
    
            const badge = document.createElement('span');
            badge.className = 'purescan-scheduled-badge';
            badge.style.cssText = `
                margin: 0 8px 0 12px;
                padding: 5px 10px;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 600;
                background: <?php echo esc_js( $bg_color ); ?>;
                color: <?php echo esc_js( $text_color ); ?>;
                border: 1px solid <?php echo esc_js( $text_color ); ?>;
                display: inline-block;
                vertical-align: middle;
            `;
            badge.textContent = '<?php echo esc_js( $badge_text ); ?>';
    
            // Insert after version span
            versionSpan.parentNode.insertBefore(badge, versionSpan.nextSibling);
        });
        </script>
        <?php
    }

     /**
     * Opportunistic background execution for scheduled scans.
     *
     * Runs a single safe chunk of the scan when triggered by various hooks.
     * Includes comprehensive safety measures: locking, conflict prevention,
     * cleanup on completion/cancellation, and error handling.
     */
    public function maybe_run_background_chunk(): void
    {
        // First: enforce aggressive and repetitive cancel check
        $this->enforce_repetitive_cancel();
    
        // Prevent concurrent execution
        if (get_transient('purescan_bg_lock')) {
            return;
        }
    
        set_transient('purescan_bg_lock', 1, 10);
    
        try {
            $flag_time = get_option('purescan_background_flag');
            if (!$flag_time) {
                return;
            }
    
            $state = get_option(PURESCAN_STATE, []);
    
            // Safety: Stop if scan is already cancelled or completed
            if (!empty($state['status']) && in_array($state['status'], ['cancelled', 'completed'], true)) {
                delete_option('purescan_background_flag');
                return;
            }
    
            // Start a new scheduled scan if none is running
            if (empty($state['status']) || $state['status'] !== 'running') {
                $settings = \PureScan\Settings\Settings_Handler::get();
    
                if (empty($settings['scheduled_scan_enabled'])) {
                    delete_option('purescan_background_flag');
                    return;
                }
    
                // Initialize fresh scan state
                delete_option(PURESCAN_STATE);
    
                $state = [
                    'status'            => 'running',
                    'started'           => current_time('mysql'),
                    'scan_start_time'   => microtime(true),
                    'scanned'           => 0,
                    'suspicious'        => 0,
                    'progress'          => 0,
                    'findings'          => [],
                    'is_scheduled_scan' => true,
                    'is_manual_scan'    => false,
                    'current_folder'    => [
                        'short'  => 'Scheduled Scan',
                        'label'  => 'Automatic scheduled scan running in background',
                        'icon'   => 'clock',
                        'color'  => '#10b981',
                    ],
                    'initialized'       => true,
                    'chunk_start'       => 0,
                    'file_list'         => [],
                    'total_files'       => 0,
                ];
    
                update_option(PURESCAN_STATE, $state, false);
            }
    
            // Execute one chunk
            $settings = \PureScan\Settings\Settings_Handler::get();
            $engine   = new \PureScan\Scan\Scan_Engine($settings);
            $engine->execute();
    
            // Cleanup on completion
            $new_state = get_option(PURESCAN_STATE, []);
            if (!empty($new_state['status']) && $new_state['status'] === 'completed') {
                delete_option('purescan_background_flag');
    
                if (
                    !empty($settings['scheduled_scan_send_email']) &&
                    class_exists('\PureScan\Email_Notifier')
                ) {
                    \PureScan\Email_Notifier::send_scan_complete_email($new_state);
                }
            }
        } catch (\Throwable $e) {
            // Silent catch - log if needed in future
        } finally {
            delete_transient('purescan_bg_lock');
        }
    }   
    
    /**
     * Aggressive & repetitive cancel enforcer - strengthened version
     * More aggressive repetition + extra safety layers to catch even the toughest race conditions
     */
    public function enforce_repetitive_cancel()
    {
        static $cancel_attempts = 0;
    
        $force_cancel   = get_transient('purescan_force_cancel') === '1';
        $pending_cancel = get_option('purescan_cancel_pending', false);
    
        if (!$force_cancel && !$pending_cancel) {
            $cancel_attempts = 0;
            return;
        }
    
        $cancel_attempts++;
    
        // Increased max attempts + longer persistence
        if ($cancel_attempts > 12) {
            delete_transient('purescan_force_cancel');
            delete_option('purescan_cancel_pending');
            $cancel_attempts = 0;
            return;
        }
    
        $state = get_option(PURESCAN_STATE, []);
    
        // If still running OR status is missing (corrupted state) → force cancel
        $is_running = !empty($state['status']) && $state['status'] === 'running';
        $is_stuck   = empty($state['status']) && !empty($state['started']); // rare corrupted state
    
        if ($is_running || $is_stuck) {
    
            // Repeat 5 times instead of 3 - very aggressive but still lightweight
            for ($i = 0; $i < 5; $i++) {
                $state = get_option(PURESCAN_STATE, []); // always re-read
    
                $state['status']          = 'cancelled';
                $state['cancelled_at']    = current_time('mysql');
                $state['progress_frozen'] = true;
    
                // Force-remove ALL resumable/resumption keys
                unset(
                    $state['chunk_start'],
                    $state['file_list'],
                    $state['initialized'],
                    $state['discovery_phase'],
                    $state['malware_scan_phase'],
                    $state['adaptive_chunk'],
                    $state['core_phase'],
                    $state['plugin_phase'],
                    $state['external_industrial_phase'],
                    $state['database_deep_started'],
                    $state['spam_content_phase']
                );
    
                // Also force progress to 0 and add cancel flag
                $state['progress'] = 0;
                $state['force_cancelled'] = true;
    
                update_option(PURESCAN_STATE, $state, false);
                usleep(50000); // 50ms - still very fast, but gives more chance to flush
            }
    
            // Final UI message
            $state['final_message'] = [
                'text'   => 'Scan forcefully and permanently cancelled',
                'detail' => 'All processes stopped. No resumption possible.',
                'icon'   => 'warning',
                'color'  => '#f59e0b',
                'box_class' => 'cancelled',
            ];
    
            update_option(PURESCAN_STATE, $state, false);
        }
    
        // Nuclear cleanup - everything related to background & locks
        delete_transient('purescan_engine_lock');
        delete_transient('purescan_bg_lock');
        delete_transient('purescan_force_cancel');
        delete_option('purescan_background_flag');
        delete_option('purescan_cancel_pending');
    
        // Force clear object cache if available (some hosts have aggressive caching)
        wp_cache_delete(PURESCAN_STATE, 'options');
    
        if (is_admin() && !has_action('admin_notices', [$this, 'cancel_success_notice'])) {
            add_action('admin_notices', [$this, 'cancel_success_notice']);
        }
    
        if (wp_doing_ajax()) {
            wp_send_json_success([
                'message' => 'Cancel fully enforced - scan stopped in all layers.'
            ]);
        }
    }
    
    /**
     * Callback for admin notice after forceful cancel
     */
    public function cancel_success_notice()
    {
        ?>
        <div class="notice notice-warning is-dismissible">
            <p><strong>PureScan:</strong> The scan was successfully and permanently cancelled.</p>
        </div>
        <?php
    }
    /**
     * AJAX handler: Check real-time connection and integrity status.
     *
     * Returns connection status for AI/patterns loading.
     */
    public function ajax_check_connection_status(): void {
        check_ajax_referer( PURESCAN_NONCE, 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Unauthorized', 'purescan' ) ] );
        }

        $status  = 'ok';
        $message = '';

        // Check AI client connection
        if ( class_exists( '\PureScan\AI_Client' ) ) {
            $ai_client = new \PureScan\AI_Client();
            if ( ! $ai_client->is_connected() ) {
                $status  = 'connection';
                $message = esc_html__( 'Cannot connect to central server', 'purescan' );
            }
        }

        // Fallback: Check for patterns loading failure
        if ( $status === 'ok' ) {
            $patterns_failed = get_transient( 'purescan_patterns_remote_failed' );
            if ( $patterns_failed ) {
                $status  = 'connection';
                $message = esc_html__( 'Failed to load detection patterns', 'purescan' );
            }
        }

        wp_send_json_success( [
            'status'  => $status,
            'message' => $message,
        ] );
    }
    
    /**
     * AJAX handler: Restore a file from an uploaded quarantine backup.
     *
     * Validates the uploaded backup file, checks permissions, and restores
     * the original file content if everything is valid.
     */
    public function ajax_restore_backup(): void {
        check_ajax_referer( 'purescan_restore_backup', 'purescan_restore_nonce' );
    
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Permission denied', 'purescan' ) ] );
        }
    
        // Safely extract fields
        $upload_error = isset( $_FILES['purescan_backup_file']['error'] ) ? (int) $_FILES['purescan_backup_file']['error'] : UPLOAD_ERR_NO_FILE;
    
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- 'tmp_name' is a system-generated temporary path; it cannot be sanitized and is validated by is_uploaded_file() immediately after.
        $upload_tmp  = isset( $_FILES['purescan_backup_file']['tmp_name'] ) ? $_FILES['purescan_backup_file']['tmp_name'] : '';
    
        $upload_name = isset( $_FILES['purescan_backup_file']['name'] ) ? sanitize_file_name( $_FILES['purescan_backup_file']['name'] ) : '';
    
        // No file uploaded or upload error
        if ( $upload_error !== UPLOAD_ERR_OK || empty( $upload_tmp ) || empty( $upload_name ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Upload error.', 'purescan' ) ] );
        }
    
        // Critical security check: ensure it's a genuine uploaded file
        if ( ! is_uploaded_file( $upload_tmp ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Invalid uploaded file.', 'purescan' ) ] );
        }
    
        // Validate filename pattern (specific to PureScan backups)
        if ( ! preg_match( '/^(.+)\*\.(\d{8}-\d{6})\.quarantined\.bak\.purescan$/', $upload_name, $m ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Invalid backup filename.', 'purescan' ) ] );
        }
    
        $relative = str_replace( '**', '/', $m[1] );
        $target   = ABSPATH . $relative;
    
        // Read and restore content
        $content = file_get_contents( $upload_tmp );
    
        if ( $content === false || file_put_contents( $target, $content ) === false ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Restore failed – permission or disk error.', 'purescan' ) ] );
        }
    
        wp_send_json_success( [
            /* translators: %s: relative path to the restored file */
            'message' => sprintf( esc_html__( 'File successfully restored: %s', 'purescan' ), esc_html( $relative ) ),
        ] );
    }

    /**
     * AJAX handler: Quarantine/neutralize a suspicious file.
     *
     * Creates a mandatory backup first, then applies safe neutralization
     * based on file type. Aborts if backup fails or file is critical.
     */
    public function ajax_quarantine_file(): void {
        check_ajax_referer( PURESCAN_NONCE, 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Permission denied', 'purescan' ) ] );
        }
        $path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
        if ( ! $path || strpos( $path, '..' ) !== false || strpos( $path, "\0" ) !== false ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Invalid path', 'purescan' ) ] );
        }
        $relative = ltrim( $path, '/' );
        $full = ABSPATH . $relative;
        if ( ! is_file( $full ) || ! is_readable( $full ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'File not accessible or not readable', 'purescan' ) ] );
        }
        $ext = strtolower( pathinfo( $full, PATHINFO_EXTENSION ) );
        $profile = $this->ultra_profile_file( $full, $relative, $ext );
        if ( $profile['risk_score'] >= self::RISK_THRESHOLD_CRITICAL ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Critical core file – automatic neutralization blocked for safety.', 'purescan' ) ] );
        }
        if ( $profile['already_neutralized'] ) {
            wp_send_json_error( [ 'message' => esc_html__( 'File is already safely neutralized', 'purescan' ) ] );
        }
        // Mandatory backup – abort if it fails
        try {
            $backup_path = $this->create_quarantine_backup( $full, $relative );
            $backup_relative = ltrim( str_replace( WP_CONTENT_DIR, 'wp-content', $backup_path ), '/' );
            $backup_relative = str_replace( '\\', '/', $backup_relative );
            $backup_time = gmdate( 'Y-m-d H:i:s', filemtime( $backup_path ) );
        } catch ( \RuntimeException $e ) {
            wp_send_json_error( [
                'message' => esc_html__( 'Quarantine aborted: ', 'purescan' ) . $e->getMessage(),
            ] );
        }
        // Apply neutralization
        $original = file_get_contents( $full );
        $hash = hash( 'sha512', $original );
        $neutralized = $this->apply_ultra_neutralization( $original, $profile, $ext );
        if ( $neutralized === false ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Unsupported file type for neutralization', 'purescan' ) ] );
        }
        // Atomic write to prevent corruption
        $tmp = $full . '.purescan_tmp';
        if ( file_put_contents( $tmp, $neutralized ) === false || ! copy( $tmp, $full ) ) {
            wp_delete_file( $tmp );
            wp_send_json_error( [ 'message' => esc_html__( 'Failed to write neutralized file – permission or disk error', 'purescan' ) ] );
        }
        wp_delete_file( $tmp );
        // Log quarantine entry
        $log = get_option( 'purescan_bne_quarantined', [] );
        $log[] = [
            'original_path' => '/' . $relative,
            'hash' => $hash,
            'risk_score' => $profile['risk_score'],
            'neutralization_mode' => $profile['neutralization_mode'],
            'neutralized_at' => current_time( 'mysql' ),
            'extension' => strtoupper( $ext ),
            'file_size' => filesize( $full ) ?: 0,
        ];
        update_option( 'purescan_bne_quarantined', $log );
        // Clean up findings and counters
        $this->remove_from_findings( $relative );
        $counters = $this->get_counters();
        // Limit backups to latest 3
        $this->limit_backups_to_three( $relative );
        wp_send_json_success( [
            'message' => esc_html__( 'File successfully neutralized – malicious behavior blocked in frontend', 'purescan' ),
            'backup_info' => 'Automatic backup created successfully:' . "\n" .
                             esc_html( $backup_relative ) . "\n" .
                             'Dated: ' . esc_html( $backup_time ),
            'risk' => $profile['risk_score'],
            'type' => strtoupper( $ext ),
            'counters' => $counters,
        ] );
    }

    /**
     * Profile a file to determine neutralization strategy and risk.
     *
     * Analyzes file content and type to decide the safest neutralization method.
     *
     * @param string $full_path     Full server path to the file.
     * @param string $relative_path Relative path from ABSPATH.
     * @param string $ext           File extension (lowercase).
     *
     * @return array Profile data including risk score and neutralization mode.
     */
    private function ultra_profile_file( string $full_path, string $relative_path, string $ext ): array {
        $content = file_get_contents( $full_path );

        $profile = [
            'risk_score'          => 60,
            'already_neutralized' => false,
            'neutralization_mode' => self::NEUTRALIZATION_PROCEDURAL,
            'details'             => [],
        ];

        // Detect if already neutralized
        if ( strpos( $content, 'Safely neutralized by PureScan' ) !== false ) {
            $profile['already_neutralized'] = true;
            return $profile;
        }

        // PHP-specific profiling
        if ( $ext === 'php' ) {
            if ( preg_match_all( '/\b(class|interface|trait)\s+([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)/', $content, $m ) ) {
                $classes = array_unique( $m[2] );
                if ( ! empty( $classes ) ) {
                    $profile['neutralization_mode'] = preg_match( '/namespace\s+([^;]+);/', $content )
                        ? self::NEUTRALIZATION_FULL_STUB
                        : self::NEUTRALIZATION_CLASS_STUB;

                    $profile['details']['php']['classes'] = $classes;
                }
            }

            // Critical core files get maximum risk
            if ( in_array( basename( $relative_path ), $this->critical_paths, true ) ) {
                $profile['risk_score'] = self::RISK_THRESHOLD_CRITICAL + 10;
            }
        } elseif ( in_array( $ext, [ 'js' ], true ) ) {
            $profile['neutralization_mode'] = self::NEUTRALIZATION_JS_WRAPPER;
        } elseif ( in_array( $ext, [ 'html', 'htm' ], true ) ) {
            $profile['neutralization_mode'] = self::NEUTRALIZATION_HTML_SANITIZE;
        } elseif ( $ext === 'css' ) {
            $profile['neutralization_mode'] = self::NEUTRALIZATION_CSS_CLEAN;
        }

        return $profile;
    }

    /**
     * Apply ultra-safe neutralization to malicious files.
     *
     * Replaces dangerous code with safe stubs while preserving functionality.
     * Different strategies per file type (PHP, JS, HTML, CSS).
     *
     * @param string $content Original file content.
     * @param array  $profile Profiling data from ultra_profile_file().
     * @param string $ext     File extension.
     *
     * @return string|false Neutralized content or false if unsupported.
     */
    private function apply_ultra_neutralization( string $content, array $profile, string $ext ) {
        $time = current_time( 'mysql' );

        // PHP neutralization – preserves strict types and namespace
        if ( $ext === 'php' ) {
            $has_strict_types = (bool) preg_match( '/^<\?php\s*declare\s*\(\s*strict_types\s*=\s*1\s*\)\s*;?\R?/i', $content );
            $has_namespace    = (bool) preg_match( '/^\s*namespace\s+([^;\{]+);/m', $content, $ns_match );
            $original_namespace = $has_namespace ? trim( $ns_match[1] ) : null;

            // Strip PHP tags, declare, and namespace for clean rebuild
            $clean_content = preg_replace( '/^<\?php\s*/i', '', $content );
            $clean_content = preg_replace( '/^\s*declare\s*\(\s*strict_types\s*=\s*1\s*\)\s*;?\R?/i', '', $clean_content );
            $clean_content = preg_replace( '/^\s*namespace\s+[^;\{]+;\R?/m', '', $clean_content );
            $clean_content = ltrim( $clean_content );

            $result = "<?php\n";

            if ( $has_strict_types ) {
                $result .= "declare(strict_types=1);\n\n";
            }

            if ( $original_namespace ) {
                $result .= "namespace {$original_namespace};\n\n";
            }

            $result .= "/** Safely neutralized by PureScan on: {$time} */\n";
            $result .= "// Malicious behavior blocked – site remains fully functional\n\n";
            $result .= "if (\\PureScan\\Runtime_Guard::should_block()) {\n";
            $result .= "    // All potentially malicious behavior blocked in frontend\n";
            $result .= "    exit;\n";
            $result .= "}\n\n";
            $result .= $clean_content;

            return $result;
        }

        // JavaScript – hard execution block
        if ( $ext === 'js' ) {
            return "/* Safely neutralized by PureScan on: {$time} */\n" .
                   "throw new Error('[PureScan] Execution blocked for security');\n";
        }

        // HTML – full access blocked page
        if ( in_array( $ext, [ 'html', 'htm' ], true ) ) {
            return "<!-- Safely neutralized by PureScan on: {$time} -->\n" .
                   "<!DOCTYPE html>\n<html lang=\"en\"><head>\n" .
                   " <meta charset=\"utf-8\">\n <title>Access Blocked</title>\n" .
                   " <style>body{font-family:system-ui,sans-serif;text-align:center;padding:60px;background:#f8f9fa;color:#343a40;}" .
                   " .c{max-width:600px;margin:0 auto;background:white;padding:40px;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,0.1);}" .
                   " h1{color:#dc3545;font-size:32px;} p{font-size:18px;}</style>\n</head>\n<body>\n" .
                   " <div class=\"c\">\n <h1>Access Blocked</h1>\n" .
                   " <p>This file has been <strong>safely neutralized</strong> by PureScan.</p>\n" .
                   " <p>All malicious behavior is blocked while your site remains fully functional.</p>\n" .
                   " </div>\n</body></html>";
        }

        // CSS – remove dangerous constructs
        if ( $ext === 'css' ) {
            $clean = $content;

            // Block expression() (legacy IE danger)
            $clean = preg_replace( '/expression\s*\([^)]*\)/i', '/* PureScan: expression blocked */', $clean );

            // Block javascript: URLs
            $clean = preg_replace( '/url\s*\(\s*["\']?\s*javascript\s*:/i', 'url(/* PureScan: javascript: blocked */', $clean );

            return "/* Safely neutralized by PureScan on: {$time} */\n" .
                   "/* Potentially dangerous constructs removed */\n\n" .
                   $clean;
        }

        return false;
    }
    
    /**
     * AJAX handler: Restore a file from the latest quarantine backup (if file exists),
     * or simply remove the quarantine entry if the file has been deleted (no backup required).
     */
    public function ajax_restore_file(): void {
        check_ajax_referer( PURESCAN_NONCE, 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Permission denied', 'purescan' ) ] );
        }
    
        $path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
        if ( ! $path || strpos( $path, '..' ) !== false || strpos( $path, "\0" ) !== false ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Invalid path', 'purescan' ) ] );
        }
    
        $relative = ltrim( $path, '/' );
        $full     = ABSPATH . $relative;
    
        $file_exists = is_file( $full );
    
        if ( $file_exists ) {
            // File exists → require backup and restore
            $backup = $this->get_latest_quarantine_backup( $relative );
            if ( ! $backup || ! is_file( $backup ) || ! is_readable( $backup ) ) {
                wp_send_json_error( [ 'message' => esc_html__( 'No quarantine backup found. Cannot safely restore the file.', 'purescan' ) ] );
            }
    
            if ( ! copy( $backup, $full ) ) {
                wp_send_json_error( [ 'message' => esc_html__( 'Restore failed – permission or disk error', 'purescan' ) ] );
            }
            
            // translators: %s: relative path of the restored file
            $message = sprintf( esc_html__( 'File successfully restored from quarantine backup: %s', 'purescan' ), esc_html( $relative ) );
    
            // Limit backups only on actual restore
            $this->limit_backups_to_three( $relative );
        } else {
            // File deleted → simply remove from quarantine list (no backup needed)
            $message = esc_html__( 'Quarantine entry successfully removed (the original file no longer exists on the server).', 'purescan' );
        }
    
        // Always remove the entry from quarantine log
        $quarantined = get_option( 'purescan_bne_quarantined', [] );
        $quarantined = array_filter( $quarantined, function ( $item ) use ( $relative ) {
            return ( $item['original_path'] ?? '' ) !== '/' . $relative;
        } );
        update_option( 'purescan_bne_quarantined', array_values( $quarantined ) );
    
        // Clean up AI results
        $quarantine_ai_results = get_option( 'purescan_quarantine_ai_results', [] );
        if ( isset( $quarantine_ai_results[ '/' . $relative ] ) ) {
            unset( $quarantine_ai_results[ '/' . $relative ] );
            update_option( 'purescan_quarantine_ai_results', $quarantine_ai_results );
        }
    
        $counters = $this->get_counters();
    
        wp_send_json_success( [
            'message'  => $message,
            'counters' => $counters,
        ] );
    }

    /**
     * Remove a file from the current scan findings.
     *
     * Used when a file is quarantined or ignored to clean up the results.
     *
     * @param string $relative Relative path (without leading slash).
     */
    private function remove_from_findings( string $relative ): void {
        $state = get_option( PURESCAN_STATE, [] );

        if ( ! empty( $state['findings'] ) && is_array( $state['findings'] ) ) {
            $state['findings'] = array_filter( $state['findings'], function ( $f ) use ( $relative ) {
                return ltrim( $f['path'] ?? '', '/' ) !== $relative;
            } );

            $state['suspicious'] = count( $state['findings'] );
            update_option( PURESCAN_STATE, $state );
        }
    }

    /**
     * Create a dated backup of the original file before quarantine.
     *
     * Stores backups in wp-content/purescan-backups with a safe filename
     * that includes the original path and timestamp.
     *
     * @param string $full     Full server path to the file.
     * @param string $relative Relative path from ABSPATH.
     *
     * @return string Path to the created backup file.
     *
     * @throws \RuntimeException If backup creation fails.
     */
    private function create_quarantine_backup( string $full, string $relative ): string {
        $backup_dir = WP_CONTENT_DIR . '/purescan-backups';

        if ( ! is_dir( $backup_dir ) ) {
            wp_mkdir_p( $backup_dir );
            @file_put_contents( $backup_dir . '/index.php', "<?php // Silence" );
            @file_put_contents( $backup_dir . '/.htaccess', "Deny from all" );
        }

        $timestamp      = gmdate( 'Ymd-His' );
        $sanitized_path = str_replace( '/', '**', $relative );
        $sanitized_path = trim( $sanitized_path, '**' );

        $backup_file = $backup_dir . '/' . $sanitized_path . '.' . $timestamp . '.quarantined.bak.purescan';

        if ( ! copy( $full, $backup_file ) ) {
            throw new \RuntimeException( esc_html__( 'Failed to create mandatory backup before quarantine', 'purescan' ) );
        }

        return $backup_file;
    }

    /**
     * Get the path to the latest quarantine backup for a file.
     *
     * @param string $relative Relative path from ABSPATH.
     *
     * @return string|null Path to the latest backup or null if none exists.
     */
    public function get_latest_quarantine_backup( string $relative ): ?string {
        $backup_dir     = WP_CONTENT_DIR . '/purescan-backups';
        $sanitized_path = str_replace( '/', '**', $relative );
        $sanitized_path = trim( $sanitized_path, '**' );

        $pattern = $backup_dir . '/' . $sanitized_path . '.*.quarantined.bak.purescan';
        $files   = glob( $pattern );

        if ( empty( $files ) ) {
            return null;
        }

        // Sort by modification time (newest first)
        usort( $files, function ( $a, $b ) {
            return filemtime( $b ) - filemtime( $a );
        } );

        return $files[0];
    }

    /**
     * Limit quarantine backups to the 3 most recent per file.
     *
     * Implements FIFO deletion of older backups.
     *
     * @param string $relative Relative path from ABSPATH.
     */
    private function limit_backups_to_three( string $relative ): void {
        $base    = basename( $relative );
        $dir     = WP_CONTENT_DIR . '/purescan-backups';
        $pattern = $dir . '/' . $base . '.*.quarantined.bak.purescan';

        require_once ABSPATH . 'wp-admin/includes/file.php';

        $files = glob( $pattern );

        if ( empty( $files ) || count( $files ) <= 3 ) {
            return;
        }

        usort( $files, function ( $a, $b ) {
            return filemtime( $b ) - filemtime( $a );
        } );

        for ( $i = 3; $i < count( $files ); $i++ ) {
            wp_delete_file( $files[ $i ] );
        }
    }

    /**
     * AJAX handler: Add a file to the ignored list.
     *
     * Removes it from current findings and stores details for later reference.
     */
    public function ajax_ignore_file(): void {
        check_ajax_referer( PURESCAN_NONCE, 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Permission denied', 'purescan' ) ] );
        }

        $path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
        if ( ! $path || strpos( $path, '..' ) !== false || strpos( $path, "\0" ) !== false ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Invalid path', 'purescan' ) ] );
        }

        $relative  = ltrim( $path, '/' );
        $full_path = ABSPATH . $relative;

        // Check if already ignored
        $ignored = get_option( 'purescan_ignored_files', [] );
        foreach ( $ignored as $item ) {
            if ( ltrim( $item['original_path'] ?? '', '/' ) === $relative ) {
                wp_send_json_success( [
                    'message'  => esc_html__( 'File is already ignored.', 'purescan' ),
                    'counters' => $this->get_counters(),
                ] );
            }
        }

        // Add to ignored list
        $ignored[] = [
            'original_path' => $path,
            'date'          => current_time( 'mysql' ),
            'size'          => is_file( $full_path ) ? filesize( $full_path ) : 0,
        ];
        update_option( 'purescan_ignored_files', $ignored );

        // Remove from current scan findings and store details
        $state = get_option( PURESCAN_STATE, [] );
        if ( ! empty( $state['findings'] ) && is_array( $state['findings'] ) ) {
            $new_findings    = [];
            $ignored_finding = null;

            foreach ( $state['findings'] as $finding ) {
                if ( isset( $finding['path'] ) && ltrim( $finding['path'], '/' ) === $relative ) {
                    $ignored_finding = $finding;
                    continue;
                }
                $new_findings[] = $finding;
            }

            if ( $ignored_finding ) {
                $state['findings']   = $new_findings;
                $state['suspicious'] = count( $new_findings );
                update_option( PURESCAN_STATE, $state );

                $ignored_details                 = get_option( 'purescan_ignored_details', [] );
                $ignored_details[ $path ]        = $ignored_finding;
                update_option( 'purescan_ignored_details', $ignored_details );
            }
        }

        wp_send_json_success( [
            'message'  => esc_html__( 'File ignored successfully.', 'purescan' ),
            'counters' => $this->get_counters(),
        ] );
    }

    /**
     * AJAX handler: Remove a file from the ignored list.
     *
     * Simply deletes the entry – does not re-add to findings.
     */
    public function ajax_unignore_file(): void {
        check_ajax_referer( PURESCAN_NONCE, 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Unauthorized', 'purescan' ) ] );
        }

        $path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
        if ( ! $path ) {
            wp_send_json_error( [ 'message' => esc_html__( 'Invalid path', 'purescan' ) ] );
        }

        $ignored = get_option( 'purescan_ignored_files', [] );
        $ignored = array_filter( $ignored, function ( $i ) use ( $path ) {
            return ltrim( $i['original_path'] ?? '', '/' ) !== ltrim( $path, '/' );
        } );

        update_option( 'purescan_ignored_files', array_values( $ignored ) );

        $counters = $this->get_counters();

        wp_send_json_success( [
            'message'  => esc_html__( 'File removed from ignored list', 'purescan' ),
            'counters' => $counters,
        ] );
    }
    
    /**
     * Check if Pro is fully active: Pro addon installed + valid license.
     *
     * @return bool
     */
    public function is_pro(): bool {
        if ( get_option( 'purescan_plugin_files_modified', false ) ) {
            return false;
        }
    
        if ( function_exists( 'purescan_pro_is_license_valid' ) && purescan_pro_is_license_valid() ) {
            return true;
        }
    
        return false;
    }
}
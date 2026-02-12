<?php
/**
 * PureScan Settings UI
 *
 * Renders the Settings tab with form-based configuration,
 * live previews, validation, and reset functionality.
 *
 * @package PureScan\Settings
 */
namespace PureScan\Settings;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Settings_UI {

    /**
     * Get a human-readable timezone string for display.
     *
     * Falls back to UTC offset format if no timezone string is set.
     *
     * @return string Formatted timezone (e.g., "America/New_York" or "UTC+02:00").
     */
    private static function get_timezone_display(): string {
        $tz = get_option( 'timezone_string' );
        if ( $tz ) {
            return $tz;
        }
        $offset  = get_option( 'gmt_offset' );
        $hours   = (int) $offset;
        $minutes = absint( ( $offset - $hours ) * 60 );
        $sign    = $offset >= 0 ? '+' : '';
        return sprintf( 'UTC%s%02d:%02d', $sign, abs( $hours ), $minutes );
    }

    /**
     * Render the Settings tab content.
     */
    public static function render(): void {
        $settings = Settings_Handler::get();

        // Pro is active only if the PureScan Pro addon is installed and active
        $is_pro = defined( 'PURESCAN_PRO_ACTIVE' ) && PURESCAN_PRO_ACTIVE;

        // Restore manual API key from DB if connected but hidden (security measure)
        if (
            ! empty( $settings['openrouter_connected'] ) &&
            empty( $settings['openrouter_api_key'] ) &&
            $settings['api_source'] === 'manual'
        ) {
            $saved                       = get_option( Settings_Handler::OPTION_NAME, [] );
            $settings['openrouter_api_key'] = $saved['openrouter_api_key'] ?? '';
        }
        ?>
        <div class="purescan-card">
            <h2 class="purescan-section-title"><?php esc_html_e( 'Settings', 'purescan' ); ?></h2>
            <p class="purescan-description">
                <?php esc_html_e( 'Configure scan behavior, performance, and appearance.', 'purescan' ); ?>
            </p>

            <form id="purescan-settings-form">

                <!-- Scan Configuration Section -->
                <div class="purescan-settings-section">
                    <h3><?php esc_html_e( 'Scan Configuration', 'purescan' ); ?></h3>

                    <!-- Limit Maximum Files to Scan -->
                    <div class="purescan-field">
                        <div class="wpr-Content-tips" style="display:block;">
                            <div class="wpr-radio wpr-radio--reverse wpr-radio--tips">
                                <input
                                    type="checkbox"
                                    class="wpr-js-tips"
                                    id="limit_files_enabled"
                                    <?php checked( $settings['max_files'] > 0 ); ?>
                                >
                                <label for="limit_files_enabled">
                                    <span data-l10n-active="On" data-l10n-inactive="Off" class="wpr-radio-ui"></span>
                                    <?php esc_html_e( 'Limit Maximum Files to Scan', 'purescan' ); ?>
                                </label>
                            </div>
                        </div>
                        <div id="max-files-wrapper" style="margin-top:12px; <?php echo ( $settings['max_files'] > 0 ) ? '' : 'opacity:0.5; pointer-events:none;'; ?>">
                            <label for="max_files"><?php esc_html_e( 'Maximum Files', 'purescan' ); ?></label>
                            <input
                                type="number"
                                id="max_files"
                                name="settings[max_files]"
                                value="<?php echo $settings['max_files'] > 0 ? esc_attr( $settings['max_files'] ) : '500000'; ?>"
                                min="100"
                                step="100"
                                placeholder="500000"
                                <?php echo ( $settings['max_files'] <= 0 ) ? 'disabled' : ''; ?>
                            >
                            <p class="purescan-help">
                                <?php
                                echo wp_kses(
                                    __( 'Default: 500,000. Higher values = more thorough but slower.<br>When the switch is <strong>Off</strong> → <strong>No limit</strong> (scan all files).', 'purescan' ),
                                    [ 'br' => [], 'strong' => [] ]
                                );
                                ?>
                            </p>
                        </div>
                    </div>

                    <!-- Max File Size to Read -->
                    <div class="purescan-field">
                        <label for="max_read_mb"><?php esc_html_e( 'Max File Size to Read (MB)', 'purescan' ); ?></label>
                        <input
                            type="number"
                            id="max_read_mb"
                            name="settings[max_read_mb]"
                            value="<?php echo esc_attr( $settings['max_read_mb'] ); ?>"
                            min="1"
                            max="50"
                            step="1"
                        >
                        <p class="purescan-help">
                            <?php esc_html_e( 'Files larger than this will be partially scanned.', 'purescan' ); ?>
                        </p>
                    </div>

                    <!-- Include Paths -->
                    <div class="purescan-field">
                        <label for="include_paths">
                            <?php esc_html_e( 'Include Paths – Only Scan These Folders (one per line)', 'purescan' ); ?>
                        </label>
                        <textarea
                            id="include_paths"
                            name="settings[include_paths]"
                            rows="6"
                            placeholder="<?php esc_attr_e( 'Leave empty to scan the entire site', 'purescan' ); ?>"
                        ><?php echo esc_textarea( $settings['include_paths'] ); ?></textarea>
                        <p class="purescan-help">
                            <?php
                            echo wp_kses(
                                __( 'Use this when you want to scan <strong>only specific parts</strong> of the site – much faster and more targeted.<br><strong>Most common use cases:</strong>', 'purescan' ),
                                [ 'br' => [], 'strong' => [] ]
                            );
                            ?>
                        </p>
                        <div class="purescan-examples">
                            <code>wp-content/themes</code> → <?php esc_html_e( 'All themes (great after a theme update)', 'purescan' ); ?><br>
                            <code>wp-content/themes/twentytwentyfive</code> → <?php esc_html_e( 'Only your active theme', 'purescan' ); ?><br>
                            <code>wp-content/themes/your-theme-name</code> → <?php esc_html_e( 'Specific theme folder', 'purescan' ); ?><br>
                            <code>wp-content/plugins</code> → <?php esc_html_e( 'All plugins (recommended after installing/updating plugins)', 'purescan' ); ?><br>
                            <code>wp-content/plugins/woocommerce</code> → <?php esc_html_e( 'Only WooCommerce plugin', 'purescan' ); ?><br>
                            <code>wp-content/plugins/contact-form-7</code> → <?php esc_html_e( 'Only Contact Form 7', 'purescan' ); ?><br>
                            <code>wp-content/mu-plugins</code> → <?php esc_html_e( 'Must-use plugins (hackers love hiding here)', 'purescan' ); ?><br>
                            <code>wp-content/uploads</code> → <?php esc_html_e( 'Only media uploads – ideal for finding uploaded webshells', 'purescan' ); ?><br>
                            <code>wp-includes</code> → <?php esc_html_e( 'WordPress core files only', 'purescan' ); ?><br>
                            <code>wp-admin</code> → <?php esc_html_e( 'Admin area files only', 'purescan' ); ?>
                        </div>
                        <small style="color:#6366f1; font-weight:600;">
                            <?php esc_html_e( 'Paths are relative to your WordPress root (where wp-config.php is located).', 'purescan' ); ?>
                        </small>
                    </div>

                    <!-- Exclude Paths -->
                    <div class="purescan-field">
                        <label for="exclude_paths">
                            <?php esc_html_e( 'Exclude Paths – Skip These Folders Completely (one per line)', 'purescan' ); ?>
                        </label>
                        <textarea
                            id="exclude_paths"
                            name="settings[exclude_paths]"
                            rows="9"
                        ><?php echo esc_textarea( $settings['exclude_paths'] ); ?></textarea>
                        <p class="purescan-help">
                            <?php
                            echo wp_kses(
                                __( 'Skip large or irrelevant folders to make scans <strong>up to 10× faster</strong>, especially on shared hosting.<br><strong>Recommended excludes for shared hosting & large sites:</strong>', 'purescan' ),
                                [ 'br' => [], 'strong' => [] ]
                            );
                            ?>
                        </p>
                        <div class="purescan-examples">
                            <code>wp-content/uploads</code> → <?php esc_html_e( 'Media library – often millions of images (skipped by 99% of users)', 'purescan' ); ?><br>
                            <code>wp-content/cache</code> → <?php esc_html_e( 'All cache folders (WP Rocket, LiteSpeed Cache, W3 Total Cache, etc.)', 'purescan' ); ?><br>
                            <code>wp-content/backups</code> → <?php esc_html_e( 'Backup folders (UpdraftPlus, Duplicator, BackupBuddy)', 'purescan' ); ?><br>
                            <code>wp-content/upgrade</code> → <?php esc_html_e( 'Temporary WordPress update folder', 'purescan' ); ?><br>
                            <code>wp-content/wc-logs</code> → <?php esc_html_e( 'WooCommerce log files', 'purescan' ); ?><br>
                            <code>wp-content/et-cache</code> → <?php esc_html_e( 'Divi / Extra theme cache', 'purescan' ); ?><br>
                            <code>wp-content/litespeed</code> → <?php esc_html_e( 'LiteSpeed Cache specific folder', 'purescan' ); ?><br>
                            <code>wp-content/ai1wm-backups</code> → <?php esc_html_e( 'All-in-One WP Migration backups', 'purescan' ); ?><br>
                            <code>public_html/wp-content/uploads</code> → <?php esc_html_e( 'When WordPress is installed in a subfolder', 'purescan' ); ?>
                        </div>
                        <small style="color:#dc2626; font-weight:600;">
                            <?php
                            echo wp_kses(
                                __( 'Default excludes already include: wp-content/uploads • wp-content/cache • wp-content/backup<br>You can remove any of these lines if you want those folders to be scanned.', 'purescan' ),
                                [ 'br' => [] ]
                            );
                            ?>
                        </small>
                    </div>

                    <!-- Database Deep Scan (Pro only – hidden in free version) -->
                    <?php if ( $is_pro ) : ?>
                    <div class="purescan-field" style="margin-top: 32px;">
                        <div class="wpr-Content-tips" style="display:block;">
                            <div class="wpr-radio wpr-radio--reverse wpr-radio--tips">
                                <input
                                    type="checkbox"
                                    class="wpr-js-tips"
                                    id="database_deep_scan_enabled"
                                    name="settings[database_deep_scan_enabled]"
                                    value="1"
                                    <?php checked( ! empty( $settings['database_deep_scan_enabled'] ) ); ?>
                                >
                                <label for="database_deep_scan_enabled">
                                    <span data-l10n-active="On" data-l10n-inactive="Off" class="wpr-radio-ui"></span>
                                    <?php esc_html_e( 'Enable Database Deep Scan', 'purescan' ); ?>
                                </label>
                            </div>
                        </div>
                        <p class="purescan-help">
                            <?php
                            echo wp_kses(
                                __( 'When enabled, PureScan will perform a thorough scan of database tables (postmeta, usermeta, termmeta, commentmeta, etc.) for hidden malicious code and payloads.<br><br><strong>Note:</strong> This feature can be resource-intensive on sites with very large databases.', 'purescan' ),
                                [ 'br' => [], 'strong' => [] ]
                            );
                            ?>
                        </p>
                        <?php if ( ! empty( $settings['database_deep_scan_enabled'] ) ) : ?>
                            <div class="notice notice-warning" style="margin-top: 16px;">
                                <p>
                                    <strong><?php esc_html_e( 'Performance Warning:', 'purescan' ); ?></strong>
                                    <?php esc_html_e( 'Database Deep Scan may increase scan time significantly on large sites.', 'purescan' ); ?>
                                </p>
                            </div>
                        <?php endif; ?>
                    </div>
                    <?php endif; ?>
                </div>

                <!-- OpenRouter AI Integration Section -->
                <div class="purescan-settings-section">
                    <!-- Master AI Features Toggle -->
                    <div class="purescan-field" style="margin-bottom: 32px;">
                        <div class="wpr-Content-tips" style="display:block;">
                            <div class="wpr-radio wpr-radio--reverse wpr-radio--tips">
                                <input
                                    type="checkbox"
                                    class="wpr-js-tips"
                                    id="ai_features_enabled"
                                    name="settings[ai_features_enabled]"
                                    value="1"
                                    <?php checked( ! empty( $settings['ai_features_enabled'] ) ); ?>
                                >
                                <label for="ai_features_enabled">
                                    <span data-l10n-active="On" data-l10n-inactive="Off" class="wpr-radio-ui"></span>
                                    <?php esc_html_e( 'Enable AI Features', 'purescan' ); ?>
                                </label>
                            </div>
                        </div>
                        <p class="purescan-help">
                            <?php esc_html_e( 'Turn off to completely disable all AI-powered features (Layer 2 deep analysis in scan results and AI code analysis in the AI tab).', 'purescan' ); ?>
                        </p>
                    </div>

                    <!-- AI Integration Content -->
                    <div id="ai-integration-content" style="<?php echo empty( $settings['ai_features_enabled'] ) ? 'opacity:0.5; pointer-events:none;' : ''; ?>">
                        <h3><?php esc_html_e( 'OpenRouter AI Integration', 'purescan' ); ?></h3>

                        <!-- API Source Selection -->
                        <div class="purescan-field">
                            <label><?php esc_html_e( 'API Key Source', 'purescan' ); ?></label>
                            <div class="purescan-radio-group-modern">
                                <div class="wpr-Content-tips">
                                    <div class="wpr-radio wpr-radio--tips">
                                        <input
                                            type="radio"
                                            name="api_source_radio"
                                            value="external"
                                            id="api_source_external"
                                            <?php checked( $settings['api_source'] !== 'manual' ); ?>
                                        >
                                        <label for="api_source_external">
                                            <span class="wpr-radio-circle"></span>
                                            <?php esc_html_e( 'External API (Default Server)', 'purescan' ); ?>
                                        </label>
                                    </div>
                                </div>
                                <div class="wpr-Content-tips">
                                    <div class="wpr-radio wpr-radio--tips">
                                        <input
                                            type="radio"
                                            name="api_source_radio"
                                            value="manual"
                                            id="api_source_manual"
                                            <?php checked( $settings['api_source'] === 'manual' ); ?>
                                        >
                                        <label for="api_source_manual">
                                            <span class="wpr-radio-circle"></span>
                                            <?php esc_html_e( 'Manual API (Your own key)', 'purescan' ); ?>
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Manual API Fields -->
                        <div id="manual-api-wrapper" style="display: <?php echo ( $settings['api_source'] === 'manual' ) ? 'block' : 'none'; ?>;">
                            <div class="purescan-field">
                                <label for="openrouter_api_key"><?php esc_html_e( 'Manual API Key', 'purescan' ); ?></label>
                                <input
                                    type="text"
                                    id="openrouter_api_key"
                                    value="<?php echo esc_attr( $settings['openrouter_api_key'] ); ?>"
                                    placeholder="<?php esc_attr_e( 'sk-or-...', 'purescan' ); ?>"
                                    autocomplete="off"
                                >
                                <p class="purescan-help">
                                    <?php echo esc_html__( 'Get your key from', 'purescan' ) . ' <a href="https://openrouter.ai/keys" target="_blank" rel="noopener">' . esc_html__( 'openrouter.ai/keys', 'purescan' ) . '</a>'; ?>
                                </p>
                            </div>
                            <div class="purescan-field">
                                <label for="openrouter_model"><?php esc_html_e( 'AI Model', 'purescan' ); ?></label>
                                <select id="openrouter_model" style="width:100%;">
                                    <option value=""><?php esc_html_e( 'Enter your API key first to load models...', 'purescan' ); ?></option>
                                </select>
                                <p class="purescan-help">
                                    <?php esc_html_e( 'Choose a model from OpenRouter. Free models have no cost.', 'purescan' ); ?>
                                    <span id="model-price-info" style="display:block; margin-top:4px; font-weight:500;"></span>
                                </p>
                            </div>
                        </div>

                        <!-- Test Connection Button -->
                        <div class="purescan-field">
                            <button type="button" id="purescan-test-openrouter" class="ps-btn ps-btn-test-connection">
                                <?php esc_html_e( 'Test Connection', 'purescan' ); ?>
                            </button>
                            <span id="purescan-openrouter-status"></span>
                        </div>

                        <!-- Active External Key Info -->
                        <?php
                        $active_key = get_option( 'purescan_active_external_key' );
                        $clean_model = $active_key['model'] ?? '';
                        $clean_model = str_replace( ':free', '', $clean_model );
                        ?>
                        <?php if ( ! empty( $active_key['key'] ) && ! empty( $active_key['model'] ) ) : ?>
                            <div class="purescan-field" id="external-key-info" style="margin-top: 18px; padding: 18px; background: #ecfdf5; border: 1px solid #6ee7b7; border-radius: 12px; display: <?php echo ( $settings['api_source'] !== 'manual' ) ? 'block' : 'none'; ?>;">
                                <p style="margin:0; font-size:15px; line-height:1.8; color:#065f46;">
                                    <strong style="color:#059669; font-size:16px;">
                                        <?php esc_html_e( 'Active External API Key', 'purescan' ); ?>
                                    </strong>
                                    <br><strong><?php esc_html_e( 'Model:', 'purescan' ); ?></strong> <code><?php echo esc_html( $clean_model ); ?></code>
                                    <br><strong><?php esc_html_e( 'Key Preview:', 'purescan' ); ?></strong> <code><?php echo esc_html( substr( $active_key['key'], 0, 34 ) ); ?>...</code>
                                    <br><br>
                                    <small style="color:#059669; opacity:0.95; font-weight:500;">
                                        <?php esc_html_e( 'PureScan automatically selects the best working key. This is the currently active one.', 'purescan' ); ?>
                                    </small>
                                </p>
                            </div>
                        <?php endif; ?>

                        <!-- Active Manual Key Info -->
                        <?php if ( $settings['api_source'] === 'manual' && ! empty( $settings['openrouter_connected'] ) && ! empty( $settings['openrouter_model'] ) ) : ?>
                            <div class="purescan-field" id="manual-key-info" style="margin-top: 18px; padding: 18px; background: #f0f9ff; border: 1px solid #3b82f6; border-radius: 12px;">
                                <p style="margin:0; font-size:15px; line-height:1.8; color:#1e40af;">
                                    <strong style="color:#2563eb; font-size:16px;">
                                        <?php esc_html_e( 'Active Manual API Key', 'purescan' ); ?>
                                    </strong>
                                    <br><strong><?php esc_html_e( 'Model:', 'purescan' ); ?></strong> <code><?php echo esc_html( $settings['openrouter_model'] ); ?></code>
                                    <br><strong><?php esc_html_e( 'Key Preview:', 'purescan' ); ?></strong> <code><?php echo esc_html( substr( $settings['openrouter_api_key'], 0, 34 ) ); ?>...</code>
                                    <br><br>
                                    <small style="color:#2563eb; opacity:0.95; font-weight:500;">
                                        <?php esc_html_e( 'Your own OpenRouter key is active and working perfectly.', 'purescan' ); ?>
                                    </small>
                                    <br><br>
                                    <button type="button" class="ps-btn ps-btn-danger purescan-remove-manual-key-btn">
                                        <?php esc_html_e( 'Remove Manual API Key', 'purescan' ); ?>
                                    </button>
                                </p>
                            </div>
                        <?php endif; ?>

                        <!-- AI Deep Scan in Deep Scan (Layer 2) – Pro only -->
                        <?php if ( $is_pro ) : ?>
                        <div class="purescan-field" id="ai-deep-scan-toggle" style="margin-top: 32px;">
                            <div class="wpr-Content-tips" style="display:block;">
                                <div class="wpr-radio wpr-radio--reverse wpr-radio--tips">
                                    <input
                                        type="checkbox"
                                        class="wpr-js-tips"
                                        id="ai_deep_scan_enabled"
                                        name="settings[ai_deep_scan_enabled]"
                                        value="1"
                                        <?php checked( ! empty( $settings['ai_deep_scan_enabled'] ) ); ?>
                                    >
                                    <label for="ai_deep_scan_enabled">
                                        <span data-l10n-active="On" data-l10n-inactive="Off" class="wpr-radio-ui"></span>
                                        <?php esc_html_e( 'Enable AI in Deep Scan (Layer 2)', 'purescan' ); ?>
                                    </label>
                                </div>
                            </div>
                            <p class="purescan-help">
                                <?php esc_html_e( 'When enabled, suspicious files found in the regular scan will be sent to AI for deeper analysis (Layer 2).', 'purescan' ); ?>
                            </p>
                        </div>
                        <?php endif; ?>

                        <!-- Warning if AI Deep Scan enabled but no connection -->
                        <?php if ( ! empty( $settings['ai_deep_scan_enabled'] ) && empty( $settings['openrouter_connected'] ) ) : ?>
                            <div class="purescan-notice purescan-notice-warning" style="margin-top: 20px; padding: 16px; background: #fffbeb; border-radius: 12px; box-shadow: 0 2px 8px rgba(245, 158, 11, 0.15);">
                                <div style="display: flex; align-items: flex-start; gap: 12px;">
                                    <span class="dashicons dashicons-warning" style="color: #f59e0b; font-size: 20px; margin-top: 2px;"></span>
                                    <div>
                                        <strong style="color: #92400e;">
                                            <?php esc_html_e( 'AI Deep Scan is enabled but API not connected', 'purescan' ); ?>
                                        </strong>
                                        <p style="margin: 8px 0 0 0; color: #92400e; line-height: 1.5; font-size: 14px;">
                                            <?php esc_html_e( 'Please test your API connection using the button above before saving.', 'purescan' ); ?><br>
                                            <em style="color: #92400e; opacity: 0.9;">
                                                <?php esc_html_e( 'Regular scan will still work without AI.', 'purescan' ); ?>
                                            </em>
                                        </p>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Hidden Fields for AI Integration -->
                <input type="hidden" name="settings[api_source]" value="<?php echo esc_attr( $settings['api_source'] ?? 'external' ); ?>">
                <input type="hidden" name="settings[openrouter_model]" value="<?php echo esc_attr( $settings['openrouter_model'] ?? '' ); ?>">
                <input type="hidden" name="settings[openrouter_connected]" value="<?php echo ! empty( $settings['openrouter_connected'] ) ? '1' : '0'; ?>">

                <!-- Scheduled Automatic Scan Section (Pro only – completely hidden in free version) -->
                <?php if ( $is_pro ) : ?>
                <div class="purescan-settings-section">
                    <h3><?php esc_html_e( 'Scheduled Automatic Scan', 'purescan' ); ?></h3>

                    <div class="purescan-field">
                        <div class="wpr-Content-tips" style="display:block;">
                            <div class="wpr-radio wpr-radio--reverse wpr-radio--tips">
                                <input
                                    type="checkbox"
                                    class="wpr-js-tips"
                                    id="scheduled_scan_enabled"
                                    name="settings[scheduled_scan_enabled]"
                                    value="1"
                                    <?php checked( $settings['scheduled_scan_enabled'] ); ?>
                                >
                                <label for="scheduled_scan_enabled">
                                    <span data-l10n-active="On" data-l10n-inactive="Off" class="wpr-radio-ui"></span>
                                    <?php esc_html_e( 'Enable Automatic Scheduled Scans', 'purescan' ); ?>
                                </label>
                            </div>
                        </div>
                        <p class="purescan-help">
                            <?php esc_html_e( 'PureScan will automatically run a full Deep Scan in the background according to the schedule below.', 'purescan' ); ?>
                        </p>
                        <p class="description">
                            <?php esc_html_e( 'The scheduled scan runs intelligently in the background during normal site activity (admin logins, admin page loads, heartbeat requests, etc.). It does not rely on a real cron job and is fully stable on shared hosting environments.', 'purescan' ); ?>
                        </p>
                    </div>

                    <!-- Schedule Options -->
                    <div id="scheduled-scan-options" style="<?php echo $settings['scheduled_scan_enabled'] ? '' : 'opacity:0.5; pointer-events:none;'; ?>">
                        <!-- Frequency Selection -->
                        <div class="purescan-field" style="margin-top:16px;">
                            <label><?php esc_html_e( 'Frequency', 'purescan' ); ?></label>
                            <div class="purescan-radio-group-modern" style="margin-top:10px;">
                                <div class="wpr-Content-tips">
                                    <input type="radio" name="settings[scheduled_scan_frequency]" value="daily" id="freq_daily" <?php checked( $settings['scheduled_scan_frequency'], 'daily' ); ?>>
                                    <label for="freq_daily"><span class="wpr-radio-circle"></span> <?php esc_html_e( 'Daily', 'purescan' ); ?></label>
                                </div>
                                <div class="wpr-Content-tips">
                                    <input type="radio" name="settings[scheduled_scan_frequency]" value="weekly" id="freq_weekly" <?php checked( $settings['scheduled_scan_frequency'], 'weekly' ); ?>>
                                    <label for="freq_weekly"><span class="wpr-radio-circle"></span> <?php esc_html_e( 'Weekly', 'purescan' ); ?></label>
                                </div>
                                <div class="wpr-Content-tips">
                                    <input type="radio" name="settings[scheduled_scan_frequency]" value="monthly" id="freq_monthly" <?php checked( $settings['scheduled_scan_frequency'], 'monthly' ); ?>>
                                    <label for="freq_monthly"><span class="wpr-radio-circle"></span> <?php esc_html_e( 'Monthly', 'purescan' ); ?></label>
                                </div>
                            </div>
                        </div>

                        <!-- Day of Week (for Weekly) -->
                        <div class="purescan-field" id="weekly-day-wrapper" style="display:<?php echo $settings['scheduled_scan_frequency'] === 'weekly' ? 'block' : 'none'; ?>; margin-top:12px;">
                            <label for="scheduled_scan_day"><?php esc_html_e( 'Day of Week', 'purescan' ); ?></label>
                            <select id="scheduled_scan_day" name="settings[scheduled_scan_day]" style="width:100%; max-width:300px;">
                                <?php
                                $days = [
                                    'monday'    => __( 'Monday', 'purescan' ),
                                    'tuesday'   => __( 'Tuesday', 'purescan' ),
                                    'wednesday' => __( 'Wednesday', 'purescan' ),
                                    'thursday'  => __( 'Thursday', 'purescan' ),
                                    'friday'    => __( 'Friday', 'purescan' ),
                                    'saturday'  => __( 'Saturday', 'purescan' ),
                                    'sunday'    => __( 'Sunday', 'purescan' ),
                                ];
                                foreach ( $days as $value => $label ) {
                                    echo '<option value="' . esc_attr( $value ) . '" ' . selected( $settings['scheduled_scan_day'], $value, false ) . '>' . esc_html( $label ) . '</option>';
                                }
                                ?>
                            </select>
                        </div>

                        <!-- Day of Month (for Monthly) -->
                        <div class="purescan-field" id="monthly-date-wrapper" style="display:<?php echo $settings['scheduled_scan_frequency'] === 'monthly' ? 'block' : 'none'; ?>; margin-top:12px;">
                            <label for="scheduled_scan_date"><?php esc_html_e( 'Day of Month', 'purescan' ); ?></label>
                            <select id="scheduled_scan_date" name="settings[scheduled_scan_date]" style="width:100%; max-width:300px;">
                                <?php
                                for ( $d = 1; $d <= 31; $d++ ) {
                                    $ends    = [ 'th', 'st', 'nd', 'rd', 'th', 'th', 'th', 'th', 'th', 'th' ];
                                    $suffix  = ( $d % 100 >= 11 && $d % 100 <= 13 ) ? 'th' : $ends[ $d % 10 ];
                                    $ordinal = $d . $suffix;
                                    ?>
                                    <option value="<?php echo esc_attr( $d ); ?>" <?php selected( $settings['scheduled_scan_date'], $d ); ?>>
                                        <?php echo esc_html( $ordinal ); ?>
                                    </option>
                                <?php } ?>
                            </select>
                        </div>

                        <!-- Start Time -->
                        <div class="purescan-field" style="margin-top:18px;">
                            <label><?php esc_html_e( 'Start Time', 'purescan' ); ?></label>
                            <div style="display: flex; align-items: center; gap: 12px; max-width: 300px; flex-wrap: wrap;">
                                <select name="settings[scheduled_scan_hour]" id="scheduled_scan_hour" style="width: 120px; padding:0.625rem 0.75rem; border:1px solid #d1d5db; border-radius:8px; font-size:0.9375rem;">
                                    <?php
                                    $saved_hour = '02';
                                    if ( ! empty( $settings['scheduled_scan_time'] ) ) {
                                        $parts      = explode( ':', $settings['scheduled_scan_time'] );
                                        $saved_hour = $parts[0] ?? '02';
                                    }
                                    for ( $h = 0; $h < 24; $h++ ) {
                                        $hour_str = str_pad( $h, 2, '0', STR_PAD_LEFT );
                                        echo '<option value="' . esc_attr( $hour_str ) . '"' . selected( $saved_hour, $hour_str, false ) . '>' . esc_html( $hour_str ) . '</option>';
                                    }
                                    ?>
                                </select>
                                <span style="font-size:1.125rem; color:#4b5563; font-weight:600;">:</span>
                                <select name="settings[scheduled_scan_minute]" id="scheduled_scan_minute" style="width: 120px; padding:0.625rem 0.75rem; border:1px solid #d1d5db; border-radius:8px; font-size:0.9375rem;">
                                    <?php
                                    $saved_minute = '00';
                                    if ( ! empty( $settings['scheduled_scan_time'] ) ) {
                                        $parts        = explode( ':', $settings['scheduled_scan_time'] );
                                        $saved_minute = $parts[1] ?? '00';
                                    }
                                    for ( $m = 0; $m < 60; $m += 5 ) {
                                        $minute_str = str_pad( $m, 2, '0', STR_PAD_LEFT );
                                        echo '<option value="' . esc_attr( $minute_str ) . '"' . selected( $saved_minute, $minute_str, false ) . '>' . esc_html( $minute_str ) . '</option>';
                                    }
                                    ?>
                                </select>
                            </div>
                            <p class="purescan-help" style="margin-top:8px;">
                                <?php esc_html_e( 'Scan will start at the selected time (server time). Current server time:', 'purescan' ); ?>
                                <strong><?php echo esc_html( date_i18n( 'H:i' ) . ' (' . self::get_timezone_display() . ')' ); ?></strong>
                            </p>
                        </div>
                    </div>

                    <!-- Next Scheduled Scan Info -->
                    <?php if ( $settings['scheduled_scan_enabled'] ) : ?>
                        <?php
                        $next_timestamp = \PureScan\Settings\Settings_Handler::calculate_next_scheduled_time( $settings );
                        $diff           = $next_timestamp - current_time( 'timestamp' );

                        if ( $diff <= 0 ) {
                            $remaining_text = esc_html__( 'Scan is starting now...', 'purescan' );
                        } else {
                            $days_remaining = floor( $diff / 86400 );
                            $hours          = floor( ( $diff % 86400 ) / 3600 );
                            $minutes        = floor( ( $diff % 3600 ) / 60 );
                            $parts          = [];

                            if ( $days_remaining > 0 ) {
                                // translators: %d is the number of remaining days
                                $parts[] = sprintf( _n( '%d day', '%d days', $days_remaining, 'purescan' ), $days_remaining );
                            }
                            if ( $hours > 0 ) {
                                // translators: %d is the number of remaining hours
                                $parts[] = sprintf( _n( '%d hour', '%d hours', $hours, 'purescan' ), $hours );
                            }
                            if ( $minutes > 0 || ( $days_remaining == 0 && $hours == 0 ) ) {
                                // translators: %d is the number of remaining minutes
                                $parts[] = sprintf( _n( '%d minute', '%d minutes', $minutes, 'purescan' ), $minutes );
                            }

                            $remaining_text = empty( $parts )
                                ? esc_html__( 'Less than a minute', 'purescan' )
                                : implode( ', ', $parts ) . ' ' . esc_html__( 'remaining', 'purescan' );
                        }

                        $frequency = $settings['scheduled_scan_frequency'];
                        $days_map  = [
                            'monday'    => __( 'Monday', 'purescan' ),
                            'tuesday'   => __( 'Tuesday', 'purescan' ),
                            'wednesday' => __( 'Wednesday', 'purescan' ),
                            'thursday'  => __( 'Thursday', 'purescan' ),
                            'friday'    => __( 'Friday', 'purescan' ),
                            'saturday'  => __( 'Saturday', 'purescan' ),
                            'sunday'    => __( 'Sunday', 'purescan' ),
                        ];

                        if ( $frequency === 'daily' ) {
                            $freq_text = esc_html__( 'Daily', 'purescan' );
                        } elseif ( $frequency === 'weekly' ) {
                            $day_name  = $days_map[ $settings['scheduled_scan_day'] ] ?? ucfirst( $settings['scheduled_scan_day'] );
                            // translators: %s is the name of the weekday (e.g. Monday, Tuesday, etc.)
                            $freq_text = sprintf( esc_html__( 'Every %s', 'purescan' ), esc_html( $day_name ) );
                        } elseif ( $frequency === 'monthly' ) {
                            $day_num   = (int) $settings['scheduled_scan_date'];
                            $ends      = [ 'th', 'st', 'nd', 'rd', 'th', 'th', 'th', 'th', 'th', 'th' ];
                            $suffix    = ( $day_num % 100 >= 11 && $day_num % 100 <= 13 ) ? 'th' : $ends[ $day_num % 10 ];
                            // translators: %s is the ordinal day of the month (e.g. 1st, 2nd, 3rd, etc.)
                            $freq_text = sprintf( esc_html__( 'Day %s of every month', 'purescan' ), $day_num . $suffix );
                        } else {
                            $freq_text = esc_html__( 'Daily', 'purescan' );
                        }
                        ?>
                        <div class="purescan-field" id="next-scheduled-info-wrapper" style="margin-top: 20px; padding: 18px; background: #f0fdf4; border: 1px solid #86efac; border-radius: 12px;">
                            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                                <span class="dashicons dashicons-clock" style="color: #16a34a; font-size: 22px;"></span>
                                <div>
                                    <strong style="color: #16a34a; font-size: 16px;"><?php esc_html_e( 'Next Automatic Scan', 'purescan' ); ?></strong>
                                    <div style="margin-top: 8px; font-size: 15.5px; color: #166534; font-weight: 600;">
                                        <?php echo esc_html( $remaining_text ); ?>
                                    </div>
                                    <small style="color: #22c55e; font-weight: 500;">
                                        <span id="next-scan-frequency"><?php echo esc_html( $freq_text ); ?></span> • <?php esc_html_e( 'Server time', 'purescan' ); ?>
                                    </small>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <!-- Email Notification Toggle -->
                    <div class="purescan-field" style="margin-top: 20px;" id="email-notifications">
                        <div class="wpr-Content-tips" style="display:block;">
                            <div class="wpr-radio wpr-radio--reverse wpr-radio--tips" id="email-toggle-wrapper">
                                <input
                                    type="checkbox"
                                    class="wpr-js-tips"
                                    id="scheduled_scan_send_email"
                                    name="settings[scheduled_scan_send_email]"
                                    value="1"
                                    <?php checked( $settings['scheduled_scan_send_email'] ); ?>
                                >
                                <label for="scheduled_scan_send_email">
                                    <span data-l10n-active="On" data-l10n-inactive="Off" class="wpr-radio-ui"></span>
                                    <?php esc_html_e( 'Send Email Report When Threats Found', 'purescan' ); ?>
                                </label>
                            </div>
                        </div>
                        <p class="purescan-help">
                            <?php esc_html_e( 'If enabled, you will receive a beautiful HTML email summary when the scheduled scan finds suspicious files.', 'purescan' ); ?>
                        </p>
                    </div>

                    <!-- Email Recipient Information -->
                    <div class="purescan-field" id="email-recipient-info" style="margin-top: 18px; padding: 16px; background: #f0fdf4; border: 1px solid #86efac; border-radius: 12px; <?php echo ( ! $settings['scheduled_scan_send_email'] ) ? 'display:none;' : ''; ?>">
                        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                            <span class="dashicons dashicons-email-alt" style="color: #16a34a; font-size: 20px;"></span>
                            <div>
                                <strong style="color: #16a34a; font-size: 15px;">
                                    <?php esc_html_e( 'Email Report Recipient', 'purescan' ); ?>
                                </strong>
                                <div style="margin-top: 6px; font-size: 14.5px; color: #166534;">
                                    <strong style="color: #15803d;">
                                        <?php echo esc_html( get_option( 'admin_email' ) ); ?>
                                    </strong>
                                    <br>
                                    <small style="color: #22c55e; font-weight: 500;">
                                        <?php esc_html_e( 'This is your WordPress admin email (Settings → General)', 'purescan' ); ?>
                                        <a href="<?php echo esc_url( admin_url( 'options-general.php' ) ); ?>" style="color: #16a34a; text-decoration: underline;">
                                            <?php esc_html_e( 'Change it here', 'purescan' ); ?>
                                        </a>
                                    </small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <!-- External Host Configuration Scan (Pro only – completely hidden in free version) -->
                <?php if ( $is_pro ) : ?>
                <div class="purescan-settings-section">
                    <h3><?php esc_html_e( 'External Host Configuration Scan', 'purescan' ); ?></h3>
                    <div class="purescan-field">
                        <div class="wpr-Content-tips" style="display:block;">
                            <div class="wpr-radio wpr-radio--reverse wpr-radio--tips">
                                <input
                                    type="checkbox"
                                    class="wpr-js-tips"
                                    id="external_scan_enabled"
                                    name="settings[external_scan_enabled]"
                                    value="1"
                                    <?php checked( ! empty( $settings['external_scan_enabled'] ) ); ?>
                                >
                                <label for="external_scan_enabled">
                                    <span data-l10n-active="On" data-l10n-inactive="Off" class="wpr-radio-ui"></span>
                                    <?php esc_html_e( 'Enable scanning of host configuration files outside WordPress root', 'purescan' ); ?>
                                </label>
                            </div>
                        </div>
                        <p class="purescan-help">
                            <?php esc_html_e( 'When enabled, PureScan will scan configuration files located outside the WordPress installation directory (e.g., parent .htaccess, php.ini, .user.ini).', 'purescan' ); ?>
                        </p>
                        <?php if ( ! empty( $settings['external_scan_enabled'] ) ) : ?>
                            <div class="notice notice-warning">
                                <p>
                                    <strong><?php esc_html_e( 'Warning:', 'purescan' ); ?></strong>
                                    <?php esc_html_e( 'This feature is disabled by default for safety on shared hosting. Only enable if you understand the risks (potential timeout or high resource usage).', 'purescan' ); ?>
                                </p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endif; ?>

                <!-- Form Actions -->
                <div class="purescan-settings-actions">
                    <button type="submit" id="purescan-save-settings" class="ps-btn ps-btn-save">
                        <?php esc_html_e( 'Save Settings', 'purescan' ); ?>
                    </button>
                    <button type="button" id="purescan-reset-settings" class="ps-btn ps-btn-reset">
                        <?php esc_html_e( 'Reset to Defaults', 'purescan' ); ?>
                    </button>
                    <span id="purescan-settings-status"></span>
                </div>

                <!-- AI Toggle Confirmation Modal -->
                <div id="ai-toggle-confirmation-modal" class="purescan-modal-overlay" style="display:none;">
                    <div class="purescan-modal-content">
                        <div class="purescan-modal-header">
                            <h3><?php esc_html_e( 'Confirm AI Features Change', 'purescan' ); ?></h3>
                        </div>
                        <div class="purescan-modal-body">
                            <p id="ai-modal-message"></p>
                        </div>
                        <div class="purescan-modal-footer">
                            <button type="button" id="ai-modal-confirm" class="ps-btn ps-btn-save"><?php esc_html_e( 'Confirm', 'purescan' ); ?></button>
                            <button type="button" id="ai-modal-cancel" class="ps-btn ps-btn-reset"><?php esc_html_e( 'Cancel', 'purescan' ); ?></button>
                        </div>
                    </div>
                </div>
            </form>
        </div>
        <?php
    }
}
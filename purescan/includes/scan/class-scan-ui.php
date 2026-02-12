<?php
/**
 * PureScan Deep Scan UI — Final Unified & Professional Version
 * Only ONE box for all states | All messages inside the same progress box
 * Core checks, current folder, final messages, cancel/complete — all unified
 */
namespace PureScan\Scan;
if (!defined('ABSPATH')) {
    exit;
}
class Scan_UI {
 
    public static function render() {
        $state = get_option(PURESCAN_STATE, ['status' => 'idle']);
        $settings = \PureScan\Settings\Settings_Handler::get();
        $external_enabled = !empty($settings['external_scan_enabled']);
        $database_enabled = !empty($settings['database_deep_scan_enabled']);
        $is_running = $state['status'] === 'running';
        $is_done = in_array($state['status'], ['completed', 'cancelled', 'single'], true);
        $findings = $is_done && !empty($state['findings']) ? $state['findings'] : [];
        $frozen = !empty($state['progress_frozen']);
    
        // Always show the progress box if scan is running or finished
        $show_box = $is_running || $frozen;
    
        // Determine what to show in the status box
        $scanned_count = $state['scanned'] ?? 0;
        $total_files = $state['total_files_for_display'] ?? 0;
        if ($total_files > 0) {
            $scanned_display = number_format($scanned_count) . ' / ' . number_format($total_files);
        } else {
            $scanned_display = number_format($scanned_count);
        }
    
        // Actual number of remaining suspicious files
        $actual_suspicious_count = count($findings);
    
        // Base box configuration
        $box = [
            'title' => $is_running ? 'Scanning in progress...' : ($state['status'] === 'completed' ? 'Scan Completed' : 'Scan Cancelled'),
            'percent' => $frozen ? '100%' : '0%',
            'width' => $frozen ? '100%' : '0%',
            'bar_bg' => $frozen ? '#94a3b8' : '',
            'stats' => 'Scanned: ' . $scanned_display . ' | Suspicious: ' . number_format($actual_suspicious_count),
            'folder' => null
        ];
    
        $patterns_source = get_option('purescan_patterns_source', '');
        if ($patterns_source) {
            $box['stats'] .= ' | Using ' . esc_html($patterns_source);
        }
    
        // When scan is finished – use final_message if available
        if ($frozen) {
            if (!empty($state['final_message'])) {
                $fm = $state['final_message'];
                $box['folder'] = [
                    'icon' => $fm['icon'] ?? 'yes-alt',
                    'color' => $fm['color'] ?? '#10b981',
                    'short' => $fm['text'] ?? 'Scan Completed',
                    'label' => $fm['detail'] ?? 'Scan completed successfully',
                ];
            } else {
                // Fallback
                $final_text = $state['status'] === 'cancelled' ? 'Scan was cancelled' : 'Scan completed successfully';
                $final_detail = sprintf(
                    '%s files scanned, %s suspicious file(s) found%s.',
                    number_format($scanned_count),
                    number_format($actual_suspicious_count),
                    $state['status'] === 'cancelled' ? ' before cancellation' : ''
                );
                $final_icon = $state['status'] === 'cancelled' ? 'warning' : 'yes-alt';
                $final_color = $state['status'] === 'cancelled' ? '#f59e0b' : '#10b981';
                $box['folder'] = [
                    'icon' => $final_icon,
                    'color' => $final_color,
                    'short' => $final_text,
                    'label' => $final_detail
                ];
            }
        }
        // During active scan – use current_folder if available
        elseif ($is_running && !empty($state['current_folder'])) {
            $box['folder'] = [
                'icon' => $state['current_folder']['icon'] ?? 'admin-generic',
                'color' => $state['current_folder']['color'] ?? '#6366f1',
                'short' => $state['current_folder']['short'] ?? 'Initializing...',
                'label' => $state['current_folder']['label'] ?? 'WordPress Root Directory'
            ];
        }
        // Initializing state during active scan
        elseif ($is_running) {
            $box['folder'] = [
                'icon' => 'admin-home',
                'color' => '#6366f1',
                'short' => 'Initializing...',
                'label' => 'Preparing scan – collecting files and checking core integrity',
            ];
        }
        ?>
        <div class="purescan-card">
            <h2 class="purescan-section-title">Deep Scan</h2>
            <p class="purescan-description">
                Scan all files for malware, backdoors, and suspicious code. Only infected files are shown.
            </p>
    
            <!-- Controls -->
            <div class="purescan-controls">
                <?php if (!$is_running): ?>
                    <button type="button" id="purescan-start-scan" class="ps-btn ps-btn-start">
                        Start Deep Scan
                    </button>
                <?php else: ?>
                    <button type="button" id="purescan-cancel-scan" class="ps-btn ps-btn-cancel">
                        Cancel Scan
                    </button>
                <?php endif; ?>
                <?php if ($is_done && !empty($findings)): ?>
                    <button type="button" id="purescan-clear-results" class="ps-btn ps-btn-clear">
                        Clear Results
                    </button>
                <?php endif; ?>
            </div>
    
            <?php if ($show_box): ?>
                <!-- Step-based Progress Bar (Dynamic) -->
                <div class="purescan-step-progress-container">
                    <ul class="purescan-scanner-progress">
                        <?php
                        if ($external_enabled) {
                            $steps = [
                                'plugin' => ['title' => 'Plugin Integrity Check', 'id' => 'ps-step-plugin'],
                                'core' => ['title' => 'WordPress Core Check', 'id' => 'ps-step-core'],
                                'spamvertising' => ['title' => 'Spamvertising Checks', 'id' => 'ps-step-spamvertising'],
                                'password' => ['title' => 'Password Strength Check', 'id' => 'ps-step-password'],
                                'audit' => ['title' => 'User & Option Audit', 'id' => 'ps-step-audit'],
                            ];
                    
                            if ($database_enabled) {
                                $steps['database'] = ['title' => 'Database Deep Scan', 'id' => 'ps-step-database'];
                            }
                    
                            $steps['server'] = ['title' => 'Server Files Discovery', 'id' => 'ps-step-server-discovery'];
                            $steps['root'] = ['title' => 'Root Files Discovery', 'id' => 'ps-step-root-discovery'];
                            $steps['malware'] = ['title' => 'Malware Analysis', 'id' => 'ps-step-malware'];
                        } else {
                            $steps = [
                                'plugin' => ['title' => 'Plugin Integrity Check', 'id' => 'ps-step-plugin'],
                                'core' => ['title' => 'WordPress Core Check', 'id' => 'ps-step-core'],
                                'spamvertising' => ['title' => 'Spamvertising Checks', 'id' => 'ps-step-spamvertising'],
                                'password' => ['title' => 'Password Strength Check', 'id' => 'ps-step-password'],
                                'audit' => ['title' => 'User & Option Audit', 'id' => 'ps-step-audit'],
                            ];
                    
                            if ($database_enabled) {
                                $steps['database'] = ['title' => 'Database Deep Scan', 'id' => 'ps-step-database'];
                            }
                    
                            $steps['root'] = ['title' => 'Root Files Discovery', 'id' => 'ps-step-root-discovery'];
                            $steps['malware'] = ['title' => 'Malware Analysis', 'id' => 'ps-step-malware'];
                        }
                        $current_step = $state['current_step'] ?? '';
                        $ordered_keys = array_keys($steps);
                        $current_index = array_search($current_step, $ordered_keys) ?: -1;

                        foreach ($steps as $key => $info):
                            $index = array_search($key, $ordered_keys);
                        
                            $step_key = str_replace('ps-step-', '', $info['id']);
                            $step_key = str_replace('-discovery', '', $step_key);
                        
                            $step_error = $state['step_error'][$step_key] ?? null;
                            $counts     = $state['step_counts'][$step_key] ?? null;
                        
                            $has_warning = !empty($step_error) || (!empty($counts) && ($counts['found'] ?? 0) > 0);
                        
                            if ($frozen) {
                                if ($state['status'] !== 'cancelled') {
                                    $class = $has_warning ? 'complete-warning' : 'complete-success';
                                } else {
                                    if ($index < $current_index) {
                                        $class = $has_warning ? 'complete-warning' : 'complete-success';
                                    } elseif ($index === $current_index) {
                                        $class = $has_warning ? 'complete-warning' : 'complete-success cancelled-current';
                                    } else {
                                        $class = 'pending';
                                    }
                                }
                            } else {
                                if ($index < $current_index) {
                                    $class = $has_warning ? 'complete-warning' : 'complete-success';
                                } elseif ($index === $current_index) {
                                    $class = 'active pending';
                                } else {
                                    $class = 'pending';
                                }
                            }
                            ?>
                            <li id="<?php echo esc_attr($info['id']); ?>" class="purescan-scan-step <?php echo esc_attr($class); ?>">
                                <div class="purescan-scan-step-icon">
                                    <div class="purescan-scan-step-pending"></div>
                                    <div class="purescan-scan-step-complete-success"></div>
                                    <div class="purescan-scan-step-complete-warning"></div>
                                </div>
                                <div class="purescan-scan-step-title"><?php echo esc_html($info['title']); ?></div>
                                <?php
                                $is_non_file_step = in_array($step_key, ['spamvertising', 'password', 'audit', 'database']);
                        
                                if ($step_error) {
                                    ?>
                                    <div class="purescan-step-subtext warning">
                                        <?php echo esc_html($step_error); ?>
                                    </div>
                                    <?php
                                }
                        
                                elseif ($counts && ($counts['checked'] ?? 0) > 0) {
                                    $checked_num = $counts['checked'] ?? 0;
                                    $found_num   = $counts['found'] ?? 0;
                        
                                    $unit = 'files';
                                    if (in_array($step_key, ['spamvertising', 'password', 'audit'])) {
                                        $unit = 'entries';
                                    } elseif ($step_key === 'database') {
                                        $unit = 'rows';
                                    }
                        
                                    if ($found_num > 0) {
                                        $text          = number_format($found_num) . ' / ' . number_format($checked_num) . ' ' . $unit;
                                        $subtext_class = 'warning';
                                    } else {
                                        $text          = number_format($checked_num) . ' ' . $unit;
                                        $subtext_class = 'success';
                                    }
                                    ?>
                                    <div class="purescan-step-subtext <?php echo esc_attr($subtext_class); ?>">
                                        <?php echo esc_html($text); ?>
                                    </div>
                                    <?php
                                }
                        
                                elseif ($is_non_file_step && in_array($class, ['active pending', 'complete-success', 'complete-warning'])) {
                                    if (strpos($class, 'active') !== false) {
                                        $scanning_unit = $step_key === 'database' ? 'rows' : 'entries';
                                        $text          = 'Scanning ' . $scanning_unit . '...';
                                    } else {
                                        $text = '0 ' . ($step_key === 'database' ? 'rows' : 'entries');
                                    }
                                    $subtext_class = 'success';
                                    ?>
                                    <div class="purescan-step-subtext <?php echo esc_attr($subtext_class); ?>">
                                        <?php echo esc_html($text); ?>
                                    </div>
                                    <?php
                                }
                                ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
    
            <?php if ($is_running): ?>
                <div id="purescan-progress-container" class="purescan-progress-box">
                    <div class="purescan-progress-header">
                        <span><?php echo esc_html($box['title']); ?></span>
                        <span id="purescan-progress-percent"><?php echo esc_html($box['percent']); ?></span>
                    </div>
                    <div class="purescan-progress-bar-container">
                        <div id="purescan-progress-bar" class="purescan-progress-bar"
                             style="width:<?php echo esc_attr($box['width']); ?>;
                                    <?php echo $box['bar_bg'] ? 'background:' . esc_attr($box['bar_bg']) . ';' : ''; ?>">
                        </div>
                    </div>
                    <div class="purescan-progress-stats" id="purescan-progress-stats">
                        <?php echo esc_html($box['stats']); ?>
                    </div>
                </div>
            <?php endif; ?>
    
            <?php if ($is_running || ($frozen && !empty($box['folder']))): ?>
                <div class="purescan-current-folder-pro <?php echo !empty($state['final_message']['box_class']) ? 'final-' . esc_attr($state['final_message']['box_class']) : ''; ?>"
                     id="purescan-current-folder"
                     data-status="<?php echo esc_attr($is_running ? 'running' : ($state['status'] ?? 'idle')); ?>">
                    <div class="purescan-current-folder-icon">
                        <span class="dashicons dashicons-<?php echo esc_attr($box['folder']['icon'] ?? 'admin-generic'); ?>"
                              style="color:<?php echo esc_attr($box['folder']['color'] ?? '#6366f1'); ?>;"></span>
                    </div>
                    <div class="purescan-current-folder-text">
                        <div class="purescan-current-folder-short" style="color:<?php echo esc_attr($box['folder']['color'] ?? '#6366f1'); ?>;">
                            <?php echo esc_html($box['folder']['short'] ?? 'Initializing...'); ?>
                        </div>
                        <div class="purescan-current-folder-label">
                            <?php echo esc_html($box['folder']['label'] ?? 'Preparing scan...'); ?>
                        </div>
                    </div>
                    <?php if ($is_running): ?>
                        <div class="purescan-current-folder-pulse"></div>
                    <?php else: ?>
                        <div class="purescan-current-folder-pulse" style="background:transparent !important;"></div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
    
            <!-- Results Section -->
            <div id="purescan-results-container" style="<?php echo $is_done ? '' : 'display:none;'; ?>">
                <?php if ($is_done): ?>
                    <?php self::render_results($findings, $state); ?>
                <?php else: ?>
                    <div class="purescan-results-header">
                        <h3>Results Found <span class="purescan-count-badge">(0)</span></h3>
                    </div>
                    <div class="purescan-tree-container" id="purescan-tree-container"></div>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    /**
     * Render final results with category filter buttons (search box removed)
     */
    private static function render_results($findings, $state) {
        $total = count($findings);
        // Calculate counts per category
        $category_counts = [
            'plugin' => 0,
            'core' => 0,
            'spamvertising' => 0,
            'password' => 0,
            'audit' => 0,
            'database' => 0,
            'malware' => 0,
        ];
       
        $categories = [
            'all' => 'All',
            'plugin' => 'Plugin Integrity',
            'core' => 'WordPress Core',
            'spamvertising' => 'Spamvertising',
            'password' => 'Password Strength',
            'audit' => 'User & Option Audit',
            'database' => 'Database Deep Scan',
            'malware' => 'Malware Analysis',
        ];
        // First pass: count items in each category
        foreach ($findings as $f) {
            $cat = 'malware'; // default fallback
            if (!empty($f['is_plugin_modified'])) {
                $cat = 'plugin';
            } elseif (!empty($f['is_core_modified'])) {
                $cat = 'core';
            } elseif (!empty($f['is_database'])) {
                $db_type = $f['db_type'] ?? '';
                if ($db_type === 'post' || $db_type === 'comment') {
                    $cat = 'spamvertising';
                } elseif ($db_type === 'option') {
                    $cat = 'audit';
                } elseif ($db_type === 'user') {
                    $matched_text = $f['snippets'][0]['matched_text'] ?? '';
                    if (stripos($matched_text, 'WEAK PASSWORD') !== false || stripos($matched_text, 'CRITICAL WEAK PASSWORD') !== false) {
                        $cat = 'password';
                    } else {
                        $cat = 'audit';
                    }
                } elseif ($db_type === 'deep') {
                    $cat = 'database';
                }
            }
            $category_counts[$cat]++;
        }
        ?>
        <div class="purescan-results-header">
            <h3>
                <?php if ($total === 0): ?>
                    No Results Found
                <?php else: ?>
                    Results Found <span class="purescan-count-badge" id="purescan-results-count">(<?php echo esc_html( $total ); ?>)</span>
                <?php endif; ?>
            </h3>
            <?php if ($total > 0): ?>
            <div class="purescan-filter-buttons">
                <?php foreach ($categories as $key => $label): ?>
                    <?php $count = ($key === 'all') ? $total : ($category_counts[$key] ?? 0); ?>
                    <button type="button"
                            class="ps-btn ps-btn-filter <?php echo $key === 'all' ? 'active' : ''; ?>"
                            data-filter="<?php echo esc_attr($key); ?>">
                        <?php echo esc_html($label); ?>
                        <?php if ($key !== 'all'): ?>
                            <span class="purescan-filter-count">(<?php echo esc_html( $count ); ?>)</span>
                        <?php endif; ?>
                    </button>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
        </div>
        <?php if ($total === 0): ?>
            <div class="purescan-no-threat">
                <?php echo $state['status'] === 'single' ? 'File is clean. No threats found.' : 'No suspicious files found. Your site appears clean!'; ?>
            </div>
            <?php return; ?>
        <?php endif; ?>
        <div class="purescan-tree-container" id="purescan-tree-container">
            <?php foreach ($findings as $f): ?>
                <?php
                // Determine category for this finding
                $cat = 'malware';
                if (!empty($f['is_plugin_modified'])) {
                    $cat = 'plugin';
                } elseif (!empty($f['is_core_modified'])) {
                    $cat = 'core';
                } elseif (!empty($f['is_database'])) {
                    $db_type = $f['db_type'] ?? '';
                    if ($db_type === 'post' || $db_type === 'comment') {
                        $cat = 'spamvertising';
                    } elseif ($db_type === 'option') {
                        $cat = 'audit';
                    } elseif ($db_type === 'user') {
                        $matched_text = $f['snippets'][0]['matched_text'] ?? '';
                        if (stripos($matched_text, 'WEAK PASSWORD') !== false || stripos($matched_text, 'CRITICAL WEAK PASSWORD') !== false) {
                            $cat = 'password';
                        } else {
                            $cat = 'audit';
                        }
                    } elseif ($db_type === 'deep') { // New: Database Deep Scan findings
                        $cat = 'database';
                    }
                }
                ?>
                <div class="purescan-finding-item" data-category="<?php echo esc_attr($cat); ?>">
                    <?php \PureScan\Scan\Scan_Result::render_finding($f); ?>
                </div>
            <?php endforeach; ?>
        </div>
        <?php if ($total > 0): ?>
        <script>
            jQuery(function($) {
                $('.ps-btn-filter').on('click', function() {
                    var filter = $(this).data('filter');
                    $('.ps-btn-filter').removeClass('active');
                    $(this).addClass('active');
                    if (filter === 'all') {
                        $('.purescan-finding-item').show();
                    } else {
                        $('.purescan-finding-item').hide();
                        $('.purescan-finding-item[data-category="' + filter + '"]').show();
                    }
                    var visible = $('.purescan-finding-item:visible').length;
                    $('#purescan-results-count').text('(' + visible + ')');
                });
            });
        </script>
        <?php endif; ?>
        <?php
    }
    private static function render_tree($findings) {
        foreach ($findings as $f) {
            \PureScan\Scan\Scan_Result::render_finding($f);
        }
    }
    private static function build_tree($findings) {
        $tree = [];
        foreach ($findings as $f) {
            if (!is_array($f) || empty($f['path'])) continue;
            $dir = dirname($f['path']);
            $key = $dir === '.' ? 'root_files' : $dir;
            $tree[$key][] = $f;
        }
        $order = [
            'wp-admin' => 1,
            'wp-includes' => 2,
            'wp-content/plugins' => 3,
            'wp-content/themes' => 4,
            'wp-content/uploads' => 5,
            'wp-config.php' => 6,
            '.htaccess' => 7,
            'root_files' => 99
        ];
        uksort($tree, function($a, $b) use ($order) {
            return ($order[$a] ?? 99) <=> ($order[$b] ?? 99);
        });
        return $tree;
    }
    private static function get_folder_label($path) {
        $map = [
            'wp-admin' => 'WordPress Admin',
            'wp-includes' => 'WordPress Core',
            'wp-content/plugins' => 'Plugins',
            'wp-content/themes' => 'Themes',
            'wp-content/uploads' => 'Uploads',
            'wp-config.php' => 'Configuration',
            '.htaccess' => 'Server Config',
            'root_files' => 'Root Files'
        ];
        return $map[$path] ?? ucfirst(str_replace(['wp-content/', '/'], ['', ' → '], $path));
    }
}
<?php
/**
 * PureScan Quarantine UI
 * Renders neutralized files using the exact same structure and logic as Scan_Result::render_finding
 * for complete visual and functional consistency.
 *
 * @package PureScan\Scan
 */
namespace PureScan\Scan;
if (!defined('ABSPATH')) {
    exit;
}
class Quarantine_UI {
    public static function render() {
        // Load neutralized files from BNE registry
        $neutralized_files = get_option('purescan_bne_quarantined', []);
        $count = count($neutralized_files);
        // Instance of Core to access backup method
        $core = new \PureScan\Core();
        ?>
        <!-- Main Neutralized Files Card -->
        <div class="purescan-card">
            <h2 class="purescan-section-title">
                Quarantine Files
                <?php if ($count > 0): ?>
                    <span
                        class="awaiting-mod purescan-quarantine-badge count-<?php echo esc_attr($count); ?>"
                        style="background: #d63638;">
                        <span class="purescan-threat-count"><?php echo esc_html($count); ?></span>
                    </span>
                <?php endif; ?>
            </h2>
            <p class="purescan-description">
                These files have been <strong>safely neutralized</strong> by injecting a secure guard header. An automatic dated backup of the original file was created before neutralization. The original files remain in their locations, but any malicious code is prevented from executing.
            </p>
            <?php if ($count > 0): ?>
                <div class="notice notice-success inline" style="margin: 0 0 20px 0; background: #ecfdf5; border: 1px solid #6ee7b7; border-radius: 12px; box-shadow: 0 4px 12px rgba(16, 180, 96, 0.12);">
                    <p>
                        <strong>Neutralization Active</strong> —
                        These files have been <strong>safely neutralized</strong> by injecting a secure guard header. Malicious behavior is completely blocked while preserving full site functionality and avoiding any downtime.
                    </p>
                </div>
            <?php endif; ?>
            <?php if (empty($neutralized_files)): ?>
                <div class="purescan-no-threat">
                    No files are currently neutralized. Your site has no active threats in quarantine — excellent!
                </div>
            <?php else: ?>
                <div id="purescan-results-container" style="display:block;">
                    <h3 style="margin-top:20px; margin-bottom:16px;">
                        Neutralized Files
                        <span class="purescan-count-badge">(<?php echo esc_html($count); ?>)</span>
                    </h3>
                    <div class="purescan-files-list">
                        <?php foreach ($neutralized_files as $item):
                            // Build a pseudo-finding array compatible with Scan_Result::render_finding
                            $pseudo_finding = [
                                'path' => $item['original_path'] ?? '',
                                'size' => $item['file_size'] ?? 0,
                                'mtime' => $item['neutralized_at'] ?? '—',
                                // These flags are false for neutralized files (they are not core/plugin integrity violations)
                                'is_core_modified' => false,
                                'is_plugin_modified' => false,
                                // No snippets available in quarantine log → pure checksum violation logic will be skipped
                                'snippets' => [],
                            ];
                            // Additional quarantine-specific data attached for use in details section
                            $pseudo_finding['quarantine_data'] = $item;
                            // Render using the exact same method as regular scan results
                            \PureScan\Scan\Scan_Result::render_quarantine_finding($pseudo_finding, $core);
                        endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        <style>
        .purescan-quarantine-info {
            background: #e3f2ff;
            padding: 16px;
            border-radius: 8px;
            margin: 16px 0;
            border: 1px solid #bbd8ff;
        }
        .quarantine-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }
        .quarantine-info-item {
            display: flex;
            flex-direction: column;
            font-size: 14px;
        }
        .quarantine-info-item strong {
            color: #1b57ad;
            margin-bottom: 4px;
            font-weight: 600;
        }
        .quarantine-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            color: #004883 !important;
            background: #cde8ff !important;
        }
        </style>
        <script>
        jQuery(document).ready(function($) {
            $(document).on('click', '.ps-btn-restore', function() {
                if ( ! confirm( '<?php echo esc_js( __( 'Are you sure you want to remove this file from quarantine?', 'purescan' ) ); ?>' ) ) {
                    return;
                }
        
                const btn  = $(this);
                const path = btn.data('path');
        
                btn.prop('disabled', true).text('<?php echo esc_js( __( 'Processing...', 'purescan' ) ); ?>');
        
                $.post(ajaxurl, {
                    action: 'purescan_restore_file',
                    path: path,
                    nonce: '<?php echo esc_js( wp_create_nonce( PURESCAN_NONCE ) ); ?>'
                }, function(res) {
                    if (res.success) {
                        alert( res.data.message || '<?php echo esc_js( __( 'Operation completed successfully!', 'purescan' ) ); ?>' );
                        location.reload();
                    } else {
                        alert('<?php echo esc_js( __( 'Operation failed:', 'purescan' ) ); ?> ' + (res.data?.message || '<?php echo esc_js( __( 'Unknown error', 'purescan' ) ); ?>'));
                        btn.prop('disabled', false).text('<?php echo esc_js( __( 'Remove from Quarantine', 'purescan' ) ); ?>');
                    }
                }).fail(function() {
                    alert('<?php echo esc_js( __( 'Connection error. Please try again.', 'purescan' ) ); ?>');
                    btn.prop('disabled', false).text('<?php echo esc_js( __( 'Remove from Quarantine', 'purescan' ) ); ?>');
                });
            });
        });
        </script>
        <?php
    }
}
/**
 * Extension to Scan_Result class to render quarantine entries using the exact same UI.
 * Keeps all original logic from render_finding() but adds quarantine-specific details.
 */
namespace PureScan\Scan;
class Scan_Result {
    // Existing render_finding() method remains unchanged (as provided)
    /**
     * Render a neutralized (quarantined) file using the exact same structure as regular findings.
     */
    public static function render_quarantine_finding($finding, $core) {
        $path = ltrim($finding['path'], '/');
        $file_id = 'quarantine-' . md5($finding['path']);
        // Neutralized files are never core/plugin checksum violations
        $is_core_modified_file = false;
        $is_plugin_modified_file = false;
        $is_modified_file = false;
        $is_pure_checksum_violation = false;
        // Default badge – neutralized files are considered "Infected" originally but now safe
        $badge_class = 'purescan-infected';
        $badge_text = 'Neutralized';
        // AI state
        $quarantine_ai_results = get_option('purescan_quarantine_ai_results', []);
        $ai_data = $quarantine_ai_results[$finding['path']] ?? null;
        if ($ai_data && !empty($ai_data['parsed_status']) && in_array($ai_data['parsed_status'], ['clean', 'suspicious', 'malicious'])) {
            $has_ai = true;
            $ai_status = strtoupper($ai_data['parsed_status']);
            $raw_explanation = $ai_data['raw_response'] ?? '';
            if (class_exists('\PureScan\Scan\Scan_Engine')) {
                $parsed_analysis = \PureScan\Scan\Scan_Engine::parse_structured_ai_response($raw_explanation);
                $ai_explanation = $parsed_analysis['analysis'] ?? $raw_explanation;
            } else {
                $ai_explanation = $raw_explanation;
            }
            $ai_explanation = preg_replace('/^(Details|Explanation|Analysis|Reasoning|Summary)\s*[:：]\s*/i', '', $ai_explanation);
            $ai_explanation = trim($ai_explanation);
            $ai_notice = 'AI analysis completed.';
        } else {
            $has_ai = false;
            $ai_status = null;
            $ai_explanation = '';
            $ai_notice = 'AI analysis was skipped or incomplete for this file.';
        }
        $quarantine_data = $finding['quarantine_data'] ?? [];
        $mode = ucwords(str_replace(['-', '_'], ' ', $quarantine_data['neutralization_mode'] ?? 'unknown'));
        $risk = $quarantine_data['risk_score'] ?? 0;
        $risk_level = $risk >= 90 ? 'critical' : ($risk >= 70 ? 'high' : 'medium');
        $extension = strtoupper($quarantine_data['extension'] ?? 'UNKNOWN');
        // Backup info
        $backup_path = $core->get_latest_quarantine_backup( $path );
        if ( $backup_path && is_file( $backup_path ) ) {
            $filename            = basename( $backup_path );
            $backup_display      = esc_html( 'wp-content/purescan-backups/' . $filename );
            $backup_time_display = gmdate( 'Y-m-d H:i:s', filemtime( $backup_path ) );
        } else {
            $backup_display      = esc_html__( 'No backup found', 'purescan' );
            $backup_time_display = '—';
        }
        ?>
        <div class="purescan-finding purescan-finding-collapsible <?php echo esc_attr($badge_class . '-border'); ?> neutralized-file"
             id="<?php echo esc_attr($file_id); ?>"
             data-path="<?php echo esc_attr($finding['path']); ?>">
            <!-- Header -->
            <div class="purescan-finding-summary" role="button" tabindex="0">
                <div class="purescan-finding-header">
                    <code class="purescan-file-name-full"><?php echo esc_html($path); ?></code>
                    <span class="purescan-finding-meta">
                        <?php echo esc_html(size_format($finding['size'])); ?> • Neutralized: <?php echo esc_html($finding['mtime']); ?>
                    </span>
                </div>
                <div class="purescan-finding-status">
                    <span class="purescan-status-badge <?php echo esc_attr($badge_class); ?>">
                        <?php echo esc_html($badge_text); ?>
                    </span>
                    <button type="button" class="ps-btn ps-btn-toggle">
                        <span class="text">Details</span>
                        <span class="dashicons dashicons-arrow-down-alt2"></span>
                    </button>
                </div>
            </div>
            <!-- Collapsible Details -->
            <div class="purescan-finding-content">
                <!-- AI Notice -->
                <?php if (!$has_ai): ?>
                <div class="purescan-ai-notice purescan-ai-notice-warning">
                    <strong>Warning: AI Analysis Unavailable</strong><br>
                    <?php echo esc_html($ai_notice); ?>
                </div>
                <?php endif; ?>
                <?php if ($has_ai && trim($ai_explanation) !== ''): ?>
                <div class="purescan-ai-details <?php echo $ai_status === 'MALICIOUS' ? 'purescan-ai-malicious' : ($ai_status === 'CLEAN' ? 'purescan-ai-clean' : 'purescan-ai-suspicious'); ?>"
                     style="border-left-color: <?php echo $ai_status === 'MALICIOUS' ? '#ef4444' : ($ai_status === 'CLEAN' ? '#10b981' : '#f59e0b'); ?>;">
                    <?php echo wp_kses_post(nl2br(esc_html($ai_explanation))); ?>
                </div>
                <?php endif; ?>
                <!-- Quarantine-specific information (replaces checksum message) -->
                <div class="purescan-quarantine-info">
                    <div class="quarantine-info-grid">
                        <div class="quarantine-info-item">
                            <strong>Neutralization Mode:</strong>
                            <span class="quarantine-badge mode-<?php echo esc_attr(strtolower($quarantine_data['neutralization_mode'] ?? '')); ?>">
                                <?php echo esc_html($mode); ?>
                            </span>
                        </div>
                        <div class="quarantine-info-item">
                            <strong>Risk Score:</strong>
                            <span class="quarantine-badge risk-<?php echo esc_attr($risk_level); ?>">
                                <?php echo esc_html($risk); ?> (<?php echo esc_html(ucfirst($risk_level)); ?>)
                            </span>
                        </div>
                        <div class="quarantine-info-item">
                            <strong>File Type:</strong>
                            <span class="quarantine-badge"><?php echo esc_html($extension); ?></span>
                        </div>
                    </div>
                    <div class="quarantine-info-url" style="margin-top: 15px; color: #475569; font-weight: 600;">
                        <strong>Latest Backup:</strong>
                        <code style="font-size:12px;word-break:break-all;display:block;margin-top:4px;color: #004883;background: #cde8ff;padding:4px 8px;border-radius:6px;">
                            <?php echo esc_html( $backup_display ); ?>
                        </code>
                    </div>
                </div>
                <!-- Action Buttons -->
                <div class="purescan-code-actions">
                    <button type="button"
                            class="ps-btn ps-btn-view-current"
                            onclick="window.open('<?php echo esc_url(admin_url('admin.php?page=purescan&action=view_full&file=' . urlencode($finding['path']))); ?>', '_blank')">
                        View Current File
                    </button>
                    <!-- AI Analyze button – identical to regular findings -->
                    <button type="button"
                            class="ps-btn ps-btn-analyze"
                            data-path="<?php echo esc_attr($finding['path']); ?>"
                            data-force="1">
                        Analyze with AI
                    </button>
                    <!-- Restore button -->
                    <button type="button"
                            class="ps-btn ps-btn-restore"
                            data-path="<?php echo esc_attr($finding['path']); ?>">
                        Remove from Quarantine
                    </button>
                </div>
            </div>
        </div>
        <?php
    }
    // Existing get_overall_ai_status() method remains unchanged
    private static function get_overall_ai_status($snippets) {
        $has_ai = false;
        $status = 'clean';
        foreach ($snippets as $snippet) {
            if (!is_array($snippet) || empty($snippet['ai_status']) || $snippet['ai_status'] === 'skipped') {
                continue;
            }
            $has_ai = true;
            $current = strtolower($snippet['ai_status']);
            if ($current === 'malicious') {
                return 'malicious';
            }
            if ($current === 'suspicious' && $status !== 'malicious') {
                $status = 'suspicious';
            }
        }
        return $has_ai ? $status : null;
    }
}
<?php
/**
 * PureScan Ignored Files UI
 *
 * Displays a list of files that have been manually ignored.
 * Files in this list will not appear in future scan results.
 *
 * @package PureScan\Scan
 */

namespace PureScan\Scan;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Ignored_UI {
    public static function render(): void {
        $ignored         = get_option( 'purescan_ignored_files', [] );
        $count           = count( $ignored );
        $ignored_details = get_option( 'purescan_ignored_details', [] );
        $real_abspath    = realpath( ABSPATH ) ?: ABSPATH;
        ?>
        <div class="purescan-card">
            <h2 class="purescan-section-title">
                <?php esc_html_e( 'Ignored Files', 'purescan' ); ?>
                <?php if ( $count > 0 ) : ?>
                    <span
                        class="awaiting-mod purescan-ignored-badge count-<?php echo esc_attr( $count ); ?>"
                        style="background: #fcb214;">
                        <span class="purescan-threat-count"><?php echo esc_html( $count ); ?></span>
                    </span>
                <?php endif; ?>
            </h2>
            <p class="purescan-description">
                <?php esc_html_e( 'These files have been manually ignored and will not appear in future scan results.', 'purescan' ); ?>
            </p>

            <?php if ( empty( $ignored ) ) : ?>
                <div class="purescan-no-threat">
                    <?php esc_html_e( 'No ignored files — excellent! All suspicious files are being monitored.', 'purescan' ); ?>
                </div>
            <?php else : ?>
                <div id="purescan-results-container" style="display:block;">
                    <h3 style="margin-top:10px;">
                        <?php esc_html_e( 'Ignored Files', 'purescan' ); ?>
                        <span class="purescan-count-badge">(<?php echo esc_html( $count ); ?>)</span>
                    </h3>
                    <div id="purescan-tree-container">
                        <?php foreach ( $ignored as $item ) :
                            $stored_path   = $item['original_path'] ?? '';
                            $original_path = ltrim( $stored_path, '/' );

                            $actual_full_path = false;
                            $is_external      = false;
                            $file_size        = $item['size'] ?? 0;
                            $file_mtime       = '';

                            $internal_candidate = ABSPATH . $original_path;
                            $real_internal      = realpath( $internal_candidate );
                            if ( $real_internal && is_file( $real_internal ) && is_readable( $real_internal ) ) {
                                $actual_full_path = $real_internal;
                                $is_external      = false;
                                $file_size        = filesize( $actual_full_path );
                                $file_mtime = date_i18n( 'Y-m-d H:i', filemtime( $actual_full_path ) );
                            } else {
                                $external_candidate = '/' . $original_path;
                                $real_external      = realpath( $external_candidate );
                                if ( $real_external && is_file( $real_external ) && is_readable( $real_external ) ) {
                                    $actual_full_path = $real_external;
                                    $is_external      = true;
                                    $file_size        = filesize( $actual_full_path );
                                    $file_mtime = date_i18n( 'Y-m-d H:i', filemtime( $actual_full_path ) );
                                }
                            }

                            // External badge (translated & escaped)
                            $external_badge_text = $is_external ? esc_html__( 'External Config', 'purescan' ) : '';
                            $external_badge      = $external_badge_text ? '<span class="purescan-external-badge">' . esc_html( $external_badge_text ) . '</span>' : '';

                            $finding = $ignored_details[ $stored_path ] ?? null;

                            $is_content_finding = ! empty( $finding['is_database'] );

                            if ( ! $finding ) {
                                $finding = [
                                    'path'               => $stored_path,
                                    'size'               => $file_size,
                                    'mtime'              => $file_mtime,
                                    'snippets'           => [],
                                    'is_core_modified'   => false,
                                    'is_plugin_modified' => false,
                                    'is_external'        => $is_external,
                                    'is_database'        => false,
                                    'db_type'            => '',
                                    'db_id'              => 0,
                                ];
                            } else {
                                $finding['size']        = $file_size;
                                $finding['mtime']       = $file_mtime;
                                $finding['is_external'] = $is_external;
                            }

                            $path                   = $original_path;
                            $file_id                = 'finding-' . md5( $finding['path'] );
                            $is_core_modified_file  = ! empty( $finding['is_core_modified'] );
                            $is_plugin_modified_file = ! empty( $finding['is_plugin_modified'] );
                            $is_modified_file       = $is_core_modified_file || $is_plugin_modified_file;

                            $is_pure_checksum_violation = false;
                            if ( $is_modified_file && ! empty( $finding['snippets'] ) ) {
                                $is_pure_checksum_violation = true;
                                foreach ( $finding['snippets'] as $snippet ) {
                                    if ( empty( $snippet['without_ai'] ) || $snippet['without_ai'] !== true ) {
                                        $is_pure_checksum_violation = false;
                                        break;
                                    }
                                }
                            }

                            // AI status
                            $has_ai                   = false;
                            $ai_status                = null;
                            $ai_explanation           = '';
                            $ai_successfully_analyzed = false;

                            if ( ! $is_pure_checksum_violation && ! empty( $finding['snippets'] ) ) {
                                foreach ( $finding['snippets'] as $snippet ) {
                                    if ( ! empty( $snippet['ai_status'] ) && $snippet['ai_status'] !== 'skipped' ) {
                                        $has_ai   = true;
                                        $current  = strtolower( $snippet['ai_status'] );
                                        if ( $current === 'malicious' ) {
                                            $ai_status = 'malicious';
                                        } elseif ( $current === 'suspicious' && $ai_status !== 'malicious' ) {
                                            $ai_status = 'suspicious';
                                        } elseif ( $current === 'clean' && ! $ai_status ) {
                                            $ai_status = 'clean';
                                        }

                                        if ( ! empty( $snippet['ai_debug']['explanation'] ) ) {
                                            $ai_explanation = $snippet['ai_debug']['explanation'];
                                        } elseif ( ! empty( $snippet['ai_analysis'] ) ) {
                                            $ai_explanation = $snippet['ai_analysis'];
                                        }

                                        $debug = $snippet['ai_debug'] ?? [];
                                        if (
                                            ! empty( $debug['raw_response'] ) &&
                                            empty( $debug['error'] ) &&
                                            ! empty( $debug['parsed_status'] ) &&
                                            in_array( $debug['parsed_status'], [ 'clean', 'suspicious', 'malicious' ], true )
                                        ) {
                                            $ai_successfully_analyzed = true;
                                        }
                                    }
                                }
                            }

                            // Badge logic
                            if ( $is_pure_checksum_violation || $is_modified_file ) {
                                $badge_class = 'purescan-infected';
                                $badge_text  = 'Modified';
                            } elseif ( $has_ai && $ai_status && trim( $ai_explanation ) !== '' ) {
                                $badge_class = $ai_status === 'clean' ? 'purescan-clean' :
                                    ( $ai_status === 'suspicious' ? 'purescan-suspicious' : 'purescan-infected' );
                                $badge_text  = ucfirst( $ai_status );
                            } else {
                                $badge_class = 'purescan-infected';
                                $badge_text  = 'Infected';
                            }
                            ?>
                            <div class="purescan-finding purescan-finding-collapsible <?php echo esc_attr( $badge_class . '-border' ); ?>"
                                 id="<?php echo esc_attr( $file_id ); ?>"
                                 data-path="<?php echo esc_attr( $finding['path'] ); ?>">
                                <!-- Header -->
                                <div class="purescan-finding-summary" role="button" tabindex="0">
                                    <div class="purescan-finding-header">
                                        <code class="purescan-file-name-full">
                                            <?php echo esc_html( $path ); ?>
                                            <?php 
                                            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $external_badge is hardcoded HTML with escaped translated text (trusted source).
                                            echo $external_badge; 
                                            ?>
                                        </code>
                                        <span class="purescan-finding-meta">
                                            <?php echo esc_html( size_format( $finding['size'] ) ); ?> • <?php echo esc_html( $finding['mtime'] ); ?>
                                        </span>
                                    </div>
                                    <div class="purescan-finding-status">
                                        <span class="purescan-status-badge <?php echo esc_attr( $badge_class ); ?>">
                                            <?php echo esc_html( $badge_text ); ?>
                                        </span>
                                        <button type="button" class="ps-btn ps-btn-toggle">
                                            <span class="text">Details</span>
                                            <span class="dashicons dashicons-arrow-down-alt2"></span>
                                        </button>
                                    </div>
                                </div>

                                <!-- Collapsible Details -->
                                <div class="purescan-finding-content">
                                    <?php
                                    // AI Notice
                                    if ( ! $is_pure_checksum_violation && ( ! $has_ai || empty( trim( $ai_explanation ) ) ) ) {
                                        echo '<div class="purescan-ai-notice purescan-ai-notice-warning">
                                                <strong>' . esc_html__( 'Warning: AI Analysis Unavailable', 'purescan' ) . '</strong><br>
                                                ' . esc_html__( 'AI analysis was skipped, incomplete, or failed for this file.', 'purescan' ) . '
                                              </div>';
                                    }

                                    // External file warning
                                    if ( $is_external ) {
                                        echo '<div class="purescan-checksum-details">
                                                ' . esc_html__( 'This file is located outside your WordPress installation directory. Quarantine is disabled for safety reasons. Manual review recommended.', 'purescan' ) . '
                                              </div>';
                                    }

                                    // Checksum message
                                    if ( $is_modified_file ) {
                                        echo '<div class="purescan-checksum-details">';
                                        if ( $is_core_modified_file ) {
                                            echo esc_html__( 'This WordPress core file has been modified. Automatic quarantine is disabled to prevent site issues. Please reinstall WordPress or the original file manually.', 'purescan' );
                                        } elseif ( $is_plugin_modified_file ) {
                                            echo esc_html__( 'This PureScan plugin file has been modified. Automatic quarantine is disabled for safety. Please reinstall the plugin from a trusted source.', 'purescan' );
                                        }
                                        echo '</div>';
                                    }

                                    // AI Explanation
                                    if ( ! $is_pure_checksum_violation && $has_ai && trim( $ai_explanation ) !== '' ) {
                                        $ai_color = $ai_status === 'malicious' ? '#ef4444' : ( $ai_status === 'clean' ? '#10b981' : '#f59e0b' );
                                        $ai_class = $ai_status === 'malicious' ? 'purescan-ai-malicious' :
                                            ( $ai_status === 'clean' ? 'purescan-ai-clean' : '' );
                                        echo '<div class="purescan-ai-details ' . esc_attr( $ai_class ) . '" style="border-left-color:' . esc_attr( $ai_color ) . '">';
                                        echo wp_kses_post( nl2br( esc_html( $ai_explanation ) ) );
                                        echo '</div>';
                                    }
                                    ?>

                                    <!-- Database warning -->
                                    <?php if ( ! empty( $finding['is_database'] ) && in_array( $finding['db_type'] ?? '', [ 'option', 'deep' ], true ) ) : ?>
                                        <div class="purescan-checksum-details" style="margin: 15px 0 0; background:#fefce8; padding:12px; border:1px solid #f59e0b; border-radius:8px; font-size:14px;">
                                            <?php if ( ( $finding['db_type'] ?? '' ) === 'deep' ) : ?>
                                                <?php esc_html_e( 'This database entry contains a suspicious payload (detected in deep table scan).', 'purescan' ); ?><br>
                                            <?php else : ?>
                                                <?php esc_html_e( 'This database option contains suspicious content.', 'purescan' ); ?><br>
                                            <?php endif; ?>
                                            <?php esc_html_e( 'No direct edit link exists — manual review or deletion via phpMyAdmin (or a database plugin) is strongly recommended.', 'purescan' ); ?>
                                        </div>
                                    <?php endif; ?>

                                    <!-- Action Buttons -->
                                    <div class="purescan-code-actions">
                                        <?php if ( ! empty( $finding['is_database'] ) ) : ?>
                                            <?php
                                            $edit_url = null;
                                            $view_url = null;
                                            $db_type  = $finding['db_type'] ?? '';

                                            switch ( $db_type ) {
                                                case 'post':
                                                    if ( ! empty( $finding['db_id'] ) ) {
                                                        $edit_url = admin_url( 'post.php?post=' . (int) $finding['db_id'] . '&action=edit' );
                                                        $view_url = admin_url( 'admin.php?page=purescan&action=view_content&db_type=post&db_id=' . (int) $finding['db_id'] );
                                                    }
                                                    break;
                                                case 'comment':
                                                    if ( ! empty( $finding['db_id'] ) ) {
                                                        $edit_url = admin_url( 'comment.php?action=editcomment&c=' . (int) $finding['db_id'] );
                                                        $view_url = admin_url( 'admin.php?page=purescan&action=view_content&db_type=comment&db_id=' . (int) $finding['db_id'] );
                                                    }
                                                    break;
                                                case 'user':
                                                    if ( ! empty( $finding['db_id'] ) ) {
                                                        $edit_url = admin_url( 'user-edit.php?user_id=' . (int) $finding['db_id'] );
                                                    }
                                                    break;
                                            }
                                            ?>

                                            <?php if ( $edit_url ) : ?>
                                                <button type="button"
                                                        class="ps-btn ps-btn-edit"
                                                        onclick="window.open('<?php echo esc_url( $edit_url ); ?>', '_blank')">
                                                    <?php esc_html_e( 'Edit in Admin', 'purescan' ); ?>
                                                </button>
                                            <?php endif; ?>

                                            <?php if ( $view_url ) : ?>
                                                <button type="button"
                                                        class="ps-btn ps-btn-view-content"
                                                        onclick="window.open('<?php echo esc_url( $view_url ); ?>', '_blank')">
                                                    <?php esc_html_e( 'View Full Content', 'purescan' ); ?>
                                                </button>
                                            <?php endif; ?>

                                            <button type="button"
                                                    class="ps-btn ps-btn-unignore"
                                                    data-path="<?php echo esc_attr( $stored_path ); ?>">
                                                <?php esc_html_e( 'Remove from Ignored', 'purescan' ); ?>
                                            </button>
                                        <?php else : ?>
                                            <button type="button"
                                                    class="ps-btn ps-btn-unignore"
                                                    data-path="<?php echo esc_attr( $stored_path ); ?>">
                                                <?php esc_html_e( 'Remove from Ignored', 'purescan' ); ?>
                                            </button>

                                            <button type="button"
                                                    class="ps-btn ps-btn-view-full"
                                                    onclick="window.open('<?php echo esc_url( admin_url( 'admin.php?page=purescan&action=view_full&file=' . urlencode( $stored_path ) ) ); ?>', '_blank')">
                                                <?php esc_html_e( 'View Full File', 'purescan' ); ?>
                                                <?php if ( $finding['size'] > 1048576 ) : ?>
                                                    (<?php echo esc_html( size_format( $finding['size'] ) ); ?>)
                                                <?php endif; ?>
                                            </button>

                                            <?php if ( $is_modified_file ) : ?>
                                                <button type="button"
                                                        class="ps-btn ps-btn-view-diff"
                                                        onclick="window.open('<?php echo esc_url( admin_url( 'admin.php?page=purescan&action=view_diff&file=' . urlencode( $stored_path ) ) ); ?>', '_blank')">
                                                    <?php esc_html_e( 'View Differences', 'purescan' ); ?>
                                                </button>
                                            <?php endif; ?>

                                            <?php if ( ! $is_modified_file && ! $ai_successfully_analyzed ) : ?>
                                                <button type="button"
                                                        class="ps-btn ps-btn-analyze"
                                                        data-path="<?php echo esc_attr( $finding['path'] ); ?>"
                                                        data-force="1">
                                                    <?php esc_html_e( 'Analyze with AI', 'purescan' ); ?>
                                                </button>
                                            <?php endif; ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <script>
        jQuery(document).ready(function($) {
            $(document).on('click', '.ps-btn-unignore', function(e) {
                e.preventDefault();
                const btn     = $(this);
                const path    = btn.data('path');
                const finding = btn.closest('.purescan-finding');

                if (!confirm('<?php echo esc_js( __( 'Remove this file from the ignored list?\n\nIt will appear again in future scan results.', 'purescan' ) ); ?>')) {
                    return;
                }

                btn.prop('disabled', true).text('<?php echo esc_js( __( 'Processing...', 'purescan' ) ); ?>');

                $.post(ajaxurl, {
                    action: 'purescan_unignore_file',
                    nonce : '<?php echo esc_js( wp_create_nonce( PURESCAN_NONCE ) ); ?>',
                    path  : path
                }, function(res) {
                    if (res.success) {
                        if (finding.length) {
                            finding.css({
                                transition: 'opacity 0.6s ease, transform 0.6s ease',
                                opacity   : 0,
                                transform : 'translateY(-20px)'
                            });
                            setTimeout(() => {
                                finding.remove();
                                setTimeout(() => location.reload(), 800);
                            }, 600);
                        } else {
                            location.reload();
                        }
                    } else {
                        alert('<?php echo esc_js( __( 'Error:', 'purescan' ) ); ?> ' + (res.data?.message || '<?php echo esc_js( __( 'Unknown error occurred.', 'purescan' ) ); ?>'));
                        btn.prop('disabled', false).text('<?php echo esc_js( __( 'Remove from Ignored', 'purescan' ) ); ?>');
                    }
                }).fail(function() {
                    alert('<?php echo esc_js( __( 'Connection error. Please try again.', 'purescan' ) ); ?>');
                    btn.prop('disabled', false).text('<?php echo esc_js( __( 'Remove from Ignored', 'purescan' ) ); ?>');
                });
            });
        });
        </script>
        <?php
    }
}
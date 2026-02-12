<?php
/**
 * PureScan Scan Result Renderer
 * Renders individual scan findings with unified Details block and clean actions.
 *
 * @package PureScan\Scan
 */

namespace PureScan\Scan;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Scan_Result {
    public static function render_finding( array $finding ): void {
        $path = ltrim( $finding['path'], '/' );
        $file_id = 'finding-' . md5( $finding['path'] );

        // Detect core file modified by checksum
        $is_core_modified_file = ! empty( $finding['is_core_modified'] );
        if ( ! $is_core_modified_file && ! empty( $finding['snippets'] ) ) {
            foreach ( $finding['snippets'] as $snippet ) {
                if (
                    ! empty( $snippet['without_ai'] ) &&
                    $snippet['without_ai'] === true &&
                    in_array( $snippet['ai_status'], [ 'malicious', 'suspicious' ], true ) &&
                    (
                        stripos( $snippet['matched_text'] ?? '', 'CORE FILE MODIFIED' ) !== false ||
                        stripos( $snippet['original_code'] ?? '', 'WordPress core file' ) !== false ||
                        stripos( $snippet['context_code'] ?? '', 'Core Integrity Violation' ) !== false
                    )
                ) {
                    $is_core_modified_file = true;
                    break;
                }
            }
        }

        // Detect plugin modified by checksum
        $is_plugin_modified_file = ! empty( $finding['is_plugin_modified'] );

        // Detect if this is an external file (outside WordPress root)
        $is_external = ! empty( $finding['is_external'] );

        // External badge (translated & escaped)
        $external_badge_text = $is_external ? esc_html__( 'External Config', 'purescan' ) : '';
        $external_badge      = $external_badge_text ? '<span class="purescan-external-badge">' . esc_html( $external_badge_text ) . '</span>' : '';

        // Combined modified detection
        $is_modified_file = $is_core_modified_file || $is_plugin_modified_file;

        // Default values
        $has_ai          = false;
        $ai_status       = null;
        $ai_explanation  = '';
        $badge_class     = 'purescan-infected';
        $badge_text      = 'Infected';

        // Check if this finding is ONLY a checksum violation (no real malicious snippets)
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

        // If it's a pure checksum violation → completely ignore AI
        if ( ! $is_pure_checksum_violation ) {
            $ai_status = self::get_overall_ai_status( $finding['snippets'] ?? [] );
            $has_ai    = $ai_status && $ai_status !== 'skipped';

            if ( $has_ai && ! empty( $finding['snippets'] ) ) {
                foreach ( $finding['snippets'] as $snippet ) {
                    if ( ! empty( $snippet['ai_debug']['explanation'] ) ) {
                        $ai_explanation = $snippet['ai_debug']['explanation'];
                        break;
                    }
                    if ( ! empty( $snippet['ai_analysis'] ) ) {
                        $ai_explanation = $snippet['ai_analysis'];
                        break;
                    }
                }
            }

            // Badge according to AI result
            if ( $has_ai && $ai_status !== null && trim( $ai_explanation ) !== '' ) {
                $badge_class = $ai_status === 'clean' ? 'purescan-clean' :
                    ( $ai_status === 'suspicious' ? 'purescan-suspicious' : 'purescan-infected' );
                $badge_text  = ucfirst( $ai_status );
            } else {
                if ( $is_pure_checksum_violation || $is_modified_file ) {
                    $badge_class = 'purescan-infected';
                    $badge_text  = 'Modified';
                }
            }
        }

        // Plugin settings
        $settings               = \PureScan\Settings\Settings_Handler::get();
        $ai_enabled_in_settings = ! empty( $settings['ai_deep_scan_enabled'] );
        $is_content_finding     = ! empty( $finding['is_database'] );
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
                        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $external_badge is trusted hardcoded HTML with escaped translated text.
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
                        <span class="text"><?php esc_html_e( 'Details', 'purescan' ); ?></span>
                        <span class="dashicons dashicons-arrow-down-alt2"></span>
                    </button>
                </div>
            </div>

            <!-- Collapsible Details -->
            <div class="purescan-finding-content">
                <?php if ( ! $is_pure_checksum_violation && ! $is_content_finding ) : ?>
                    <?php
                    $show_ai_notice     = false;
                    $ai_notice_type     = 'warning';
                    $ai_notice_title    = '';
                    $ai_notice_message  = '';

                    if ( ! $ai_enabled_in_settings ) {
                        $show_ai_notice     = true;
                        $ai_notice_type     = 'info';
                        $ai_notice_title    = esc_html__( 'Warning: AI Analysis Unavailable', 'purescan' );
                        $ai_notice_message  = esc_html__( 'AI Deep Scan is currently disabled in PureScan settings.', 'purescan' );
                    } elseif ( ! $has_ai || empty( trim( $ai_explanation ) ) ) {
                        $show_ai_notice     = true;
                        $ai_notice_type     = 'warning';
                        $ai_notice_title    = esc_html__( 'Warning: AI Analysis Unavailable', 'purescan' );

                        $error_message = esc_html__( 'AI analysis did not complete.', 'purescan' );
                        $error_found   = false;

                        foreach ( ( $finding['snippets'] ?? [] ) as $snippet ) {
                            $debug = $snippet['ai_debug'] ?? [];
                            if ( ! empty( $debug['error'] ) ) {
                                $error_found   = true;
                                $error_message = esc_html( $debug['error'] );
                                break;
                            }
                            if ( empty( $debug['raw_response'] ) && ! empty( $debug['retry_possible'] ) ) {
                                $error_found   = true;
                                $error_message = esc_html__( 'AI request timed out or the model did not respond.', 'purescan' );
                                break;
                            }
                            if ( ! empty( $debug['raw_response'] ) && stripos( $debug['raw_response'], 'error' ) !== false ) {
                                $error_found   = true;
                                $error_message = esc_html__( 'AI returned an error: ', 'purescan' ) . esc_html( substr( $debug['raw_response'], 0, 200 ) );
                                break;
                            }
                        }

                        $ai_notice_message = $error_found
                            ? esc_html__( 'AI Analysis Failed: ', 'purescan' ) . $error_message
                            : esc_html__( 'AI analysis was skipped or incomplete for this file.', 'purescan' );
                    }

                    if ( $show_ai_notice ) :
                        ?>
                        <div class="purescan-ai-notice purescan-ai-notice-<?php echo esc_attr( $ai_notice_type ); ?>">
                            <strong><?php echo esc_html( $ai_notice_title ); ?></strong><br>
                            <?php echo esc_html( $ai_notice_message ); ?>
                            <?php if ( ! $ai_enabled_in_settings ) : ?>
                                <br>
                                <?php
                                printf(
                                    /* translators: %s: link to settings */
                                    esc_html__( 'You can enable AI Deep Scan in %s.', 'purescan' ),
                                    '<a href="' . esc_url( admin_url( 'admin.php?page=purescan&tab=settings#ai-deep-scan-toggle' ) ) . '">' .
                                    esc_html__( 'PureScan → Settings', 'purescan' ) . '</a>'
                                );
                                ?>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- External file warning -->
                <?php if ( $is_external ) : ?>
                    <div class="purescan-checksum-details">
                        <?php esc_html_e( 'This file is located outside your WordPress installation directory. Quarantine is disabled for safety reasons. Manual review recommended.', 'purescan' ); ?>
                    </div>
                <?php endif; ?>

                <!-- Core or Plugin file modified message -->
                <?php if ( $is_modified_file ) : ?>
                    <div class="purescan-checksum-details">
                        <?php
                        if ( $is_core_modified_file ) {
                            esc_html_e( 'This WordPress core file has been modified. Automatic quarantine is disabled to prevent site issues. Please reinstall WordPress or the original file manually.', 'purescan' );
                        } elseif ( $is_plugin_modified_file ) {
                            esc_html_e( 'This PureScan plugin file has been modified. Automatic quarantine is disabled for safety. Please reinstall the plugin from a trusted source.', 'purescan' );
                        }
                        ?>
                    </div>
                <?php endif; ?>

                <!-- AI Explanation – only for non-checksum files -->
                <?php if ( ! $is_pure_checksum_violation && $has_ai && trim( $ai_explanation ) !== '' ) : ?>
                    <div class="purescan-ai-details <?php echo $ai_status === 'malicious' ? 'purescan-ai-malicious' : ( $ai_status === 'clean' ? 'purescan-ai-clean' : '' ); ?>"
                         style="border-left-color: <?php echo $ai_status === 'malicious' ? '#ef4444' : ( $ai_status === 'clean' ? '#10b981' : '#f59e0b' ); ?>">
                        <?php echo wp_kses_post( nl2br( esc_html( $ai_explanation ) ) ); ?>
                    </div>
                <?php endif; ?>

                <!-- Unified warning for option and deep database findings -->
                <?php if ( ! empty( $finding['is_database'] ) && in_array( $finding['db_type'] ?? '', [ 'option', 'deep' ], true ) ) : ?>
                    <div class="purescan-checksum-details" style="margin: 15px 0 0; background:#fefce8; padding:16px; border:1px solid #f59e0b; border-radius:8px; font-size:14px; line-height:1.6;">
                        <strong>This database entry has been identified as containing malicious or highly suspicious code.</strong><br><br>
                        <?php if ( ( $finding['db_type'] ?? '' ) === 'deep' ) : ?>
                            Entry details:<br>
                            • Table: <code><?php echo esc_html( $finding['db_table'] ?? 'unknown' ); ?></code><br>
                            • Row ID (primary key): <code><?php echo esc_html( $finding['db_row_id'] ?? 'unknown' ); ?></code><br>
                            • Column: <code><?php echo esc_html( $finding['db_column'] ?? 'unknown' ); ?></code><br><br>

                            <strong>How to find and review it in phpMyAdmin:</strong><br>
                            1. Open phpMyAdmin and select your WordPress database.<br>
                            2. Click on the table <code><?php echo esc_html( $finding['db_table'] ?? 'unknown' ); ?></code>.<br>
                            3. Click the <strong>"Search"</strong> tab at the top.<br>
                            4. In the search form:<br>
                               &nbsp;&nbsp;• Find the field for the primary key column (usually "ID" or "meta_id").<br>
                               &nbsp;&nbsp;• Select "<strong>the exact phrase as whole field</strong>" from the dropdown.<br>
                               &nbsp;&nbsp;• Enter exactly: <code><?php echo esc_html( $finding['db_row_id'] ?? 'unknown' ); ?></code><br>
                            5. Click <strong>"Go"</strong>.<br>
                            6. Check the value in column <code><?php echo esc_html( $finding['db_column'] ?? 'unknown' ); ?></code> and delete the row if it looks malicious.
                        <?php else : ?>
                            Option name: <code><?php echo esc_html( $finding['option_name'] ?? 'unknown' ); ?></code><br><br>

                            <strong>How to find and review it in phpMyAdmin:</strong><br>
                            1. Open phpMyAdmin and select your WordPress database.<br>
                            2. Click on the table <code>wp_options</code> (your prefix may be different, e.g., wp123_options).<br>
                            3. Click the <strong>"Search"</strong> tab at the top.<br>
                            4. In the search form:<br>
                               &nbsp;&nbsp;• Find the field for <code>option_name</code>.<br>
                               &nbsp;&nbsp;• Select "<strong>the exact phrase as whole field</strong>" from the dropdown.<br>
                               &nbsp;&nbsp;• Enter exactly: <code><?php echo esc_html( $finding['option_name'] ?? 'unknown' ); ?></code><br>
                            5. Click <strong>"Go"</strong>.<br>
                            6. Check the <code>option_value</code> column and delete the entire row if it looks malicious.
                        <?php endif; ?>
                        <br><br>
                        There is no direct edit link in the WordPress admin dashboard, so you must use phpMyAdmin (or a similar database tool) to review or delete it.
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
                                class="ps-btn ps-btn-ignore"
                                data-path="<?php echo esc_attr( $finding['path'] ); ?>">
                            <?php esc_html_e( 'Ignore Entry', 'purescan' ); ?>
                        </button>
                    <?php else : ?>
                        <!-- Regular file findings -->
                        <button type="button"
                                class="ps-btn ps-btn-view-full"
                                onclick="window.open('<?php echo esc_url( admin_url( 'admin.php?page=purescan&action=view_full&file=' . urlencode( $finding['path'] ) ) ); ?>', '_blank')">
                            <?php esc_html_e( 'View Full File', 'purescan' ); ?>
                            <?php if ( $finding['size'] > 1048576 ) : ?>
                                (<?php echo esc_html( size_format( $finding['size'] ) ); ?>)
                            <?php endif; ?>
                        </button>

                        <?php if ( $is_modified_file ) : ?>
                            <button type="button"
                                    class="ps-btn ps-btn-view-diff"
                                    onclick="window.open('<?php echo esc_url( admin_url( 'admin.php?page=purescan&action=view_diff&file=' . urlencode( $finding['path'] ) ) ); ?>', '_blank')">
                                <?php esc_html_e( 'View Differences', 'purescan' ); ?>
                            </button>
                        <?php endif; ?>

                        <?php if ( empty( $finding['is_plugin_modified'] ) ) : ?>
                            <button type="button"
                                    class="ps-btn ps-btn-ignore"
                                    data-path="<?php echo esc_attr( $finding['path'] ); ?>">
                                <?php esc_html_e( 'Ignore File', 'purescan' ); ?>
                            </button>
                        <?php endif; ?>

                        <?php if ( ! $is_modified_file && ! $is_external ) : ?>
                            <button type="button"
                                    class="ps-btn ps-btn-quarantine"
                                    data-path="<?php echo esc_attr( $finding['path'] ); ?>">
                                <?php esc_html_e( 'Disable File (Safe Quarantine)', 'purescan' ); ?>
                            </button>
                        <?php endif; ?>

                        <?php
                        $ai_successfully_analyzed = false;
                        if ( ! empty( $finding['snippets'] ) ) {
                            foreach ( $finding['snippets'] as $snippet ) {
                                $debug = $snippet['ai_debug'] ?? [];
                                if (
                                    ! empty( $debug['raw_response'] ) &&
                                    empty( $debug['error'] ) &&
                                    ! empty( $debug['parsed_status'] ) &&
                                    in_array( $debug['parsed_status'], [ 'clean', 'suspicious', 'malicious' ], true )
                                ) {
                                    $ai_successfully_analyzed = true;
                                    break;
                                }
                            }
                        }

                        if ( ! $ai_successfully_analyzed && ! $is_modified_file ) {
                            $button_text = $ai_enabled_in_settings ? esc_html__( 'Re-Analyze with AI', 'purescan' ) : esc_html__( 'Analyze with AI', 'purescan' );
                            ?>
                            <button type="button"
                                    class="ps-btn ps-btn-analyze"
                                    data-path="<?php echo esc_attr( $finding['path'] ); ?>"
                                    data-force="1">
                                <?php echo esc_html( $button_text ); ?>
                            </button>
                        <?php } ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php
    }

    private static function get_overall_ai_status( array $snippets ): ?string {
        $has_ai = false;
        $status = 'clean';

        foreach ( $snippets as $snippet ) {
            if ( ! is_array( $snippet ) || empty( $snippet['ai_status'] ) || $snippet['ai_status'] === 'skipped' ) {
                continue;
            }

            $has_ai  = true;
            $current = strtolower( $snippet['ai_status'] );

            if ( $current === 'malicious' ) {
                return 'malicious';
            }

            if ( $current === 'suspicious' && $status !== 'malicious' ) {
                $status = 'suspicious';
            }
        }

        return $has_ai ? $status : null;
    }
}
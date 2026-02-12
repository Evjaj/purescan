<?php
/**
 * PureScan File Viewer — Full File View
 * Professional, GitHub-inspired viewer with syntax highlighting.
 * Supports neutralized files with clear protection notice.
 * Fully compatible with external files (outside WordPress root).
 *
 * @package PureScan
 */
if (!defined('ABSPATH')) {
    exit;
}

function purescan_render_file_viewer($file_path, $current_content) {
    // Handle internal PureScan plugin paths
    if (strpos($file_path, 'PureScan/') === 0) {
        $file_path = 'wp-content/plugins/purescan/' . str_replace('PureScan/', '', $file_path);
    }

    // Resolve the real path for metadata (supports both internal and external files)
    $internal_candidate = ABSPATH . ltrim($file_path, '/');
    $real_path = realpath($internal_candidate);

    // If not found as internal, treat as external path from server root
    if (!$real_path || !is_file($real_path)) {
        $external_candidate = '/' . ltrim($file_path, '/');
        $real_path = realpath($external_candidate);
    }

    // Fallback values for display (in case real_path resolution fails – very rare)
    $filename = basename($file_path);
    $display_filename = $filename;
    $filesize = ($real_path && is_file($real_path)) ? size_format(filesize($real_path)) : 'Unknown';
    $modified = ($real_path && is_file($real_path)) ? date_i18n('M j, Y @ H:i', filemtime($real_path)) : 'Unknown';

    // Detect if the file is external (outside WordPress root)
    $is_external = $real_path && strpos($real_path, realpath(ABSPATH)) !== 0;

    $lines = explode("\n", $current_content);

    // Detect if this file is neutralized by PureScan
    $is_quarantined = (
        strpos($current_content, 'Safely neutralized by PureScan') !== false ||
        strpos($current_content, '\\PureScan\\Runtime_Guard::should_block()') !== false ||
        strpos($current_content, 'if (\\PureScan\\Runtime_Guard::should_block())') !== false
    );

    // Detect dangerous lines AND AI context lines (only if AI was used)
    $dangerous_lines = [];
    $ai_context_lines = [];
    $use_ai_highlight = false;

    $state = get_option(PURESCAN_STATE, []);
    
    if (
        !empty($state['live_search_path']) &&
        $state['live_search_path'] === $file_path &&
        isset($state['live_search_finding'])
    ) {
        $live_finding = $state['live_search_finding'];
        if ($live_finding) {
            $state['findings'] = [$live_finding];
        }
        unset($state['live_search_finding'], $state['live_search_path']);
        update_option(PURESCAN_STATE, $state, false);
    }

    foreach (($state['findings'] ?? []) as $f) {
        if (isset($f['path']) && $f['path'] === $file_path && !empty($f['snippets'])) {
            foreach ($f['snippets'] as $snippet) {
                if (isset($snippet['without_ai']) && !$snippet['without_ai']) {
                    $use_ai_highlight = true;
                }
                foreach (($snippet['snippet_lines'] ?? []) as $l) {
                    $ln = $l['line'];
                    if (!empty($l['dangerous'])) {
                        $dangerous_lines[$ln] = true;
                    }
                    if ($use_ai_highlight) {
                        $ai_context_lines[$ln] = true;
                    }
                }
            }
            break;
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title><?php echo esc_html($display_filename); ?> - <?php esc_html_e('File Viewer', 'purescan'); ?> - PureScan</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {margin:0;font-family:system-ui,-apple-system,sans-serif;background:#fafafa;color:#24292e;line-height:1.6;}
            .container {max-width:1800px;margin:20px auto;background:#fff;border:1px solid #d0d7de;border-radius:12px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.08);}
            .header {padding:30px 40px;background:#f6f8fa;border-bottom:1px solid #d0d7de;}
            .title {font-size:28px;font-weight:600;margin:0;display:flex;align-items:center;gap:12px;}
            .title svg {width:38px;height:38px;}
            .info {margin-top:12px;font-size:15px;color:#555;}
            .external-notice {
                margin-top:20px;
                padding:16px 20px;
                background:#fffbeb;
                border:1px solid #fbbf24;
                border-radius:8px;
                font-size:15px;
                color:#92400e;
            }
            .external-notice strong {color:#f59e0b;}
            .quarantine-notice {
                margin-top:20px;
                padding:16px 20px;
                background:#f0fdf4;
                border:1px solid #10b981;
                border-radius:8px;
                font-size:15px;
                color:#065f46;
            }
            .quarantine-notice strong {color:#047857;}
            table.viewer {width:100%;border-collapse:collapse;table-layout:fixed;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14.2px;}
            col.line-num {width:70px;}
            col.code {width:calc(100% - 70px);}
            td.line-num {background:#f6f8fa;color:#656d76;text-align:right;padding:6px 16px 6px 0 !important;font-size:13px;user-select:none;border-right:1px solid #e1e4e8;font-family:ui-monospace,monospace;}
            td.code {padding:6px 20px !important;word-break:break-all;font-family:ui-monospace,SFMono-Regular,"Fira Code",Menlo,monospace;font-size:14px;line-height:1.5;}
            tr.danger {background:#ffebe9 !important;}
            tr.danger td.line-num {background:#ffebe9 !important;color:#cf222e;font-weight:600;border-left:4px solid #cf222e;}
            tr.danger td.code {background:#ffebe9 !important;}
            tr:hover td.code {background:rgba(175,184,193,0.08);}
            tr.ai-context {background:#fefce8 !important;}
            tr.ai-context td.line-num {
                background:#fefce8 !important;
                color:#92400e;
                border-left:4px solid #fbbf24;
                font-weight:600;
            }
            tr.ai-context td.code {background:#fefce8 !important;}
            tr.ai-context:hover td.code {background:#fde68a !important;}
            @media (max-width:720px) {
                table.viewer {table-layout:fixed;}
                col.line-num {width:55px;}
                col.code {width:calc(100% - 55px);}
                td.line-num {width:55px !important;min-width:55px !important;max-width:55px !important;padding:6px 10px 6px 0 !important;font-size:13px;}
                td.code {padding:6px 12px !important;word-break:break-all;font-size:13.5px;}
                .header {padding:20px;}
                .title {font-size:24px;}
                .info {font-size:14px;}
            }
            .footer {
                text-align:center;
                padding:30px;
                color:#fff !important;
                font-size:14px;
                background:#10b981 !important;
                border-top:1px solid #eaecef;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="title">
                    <span class="purescan-logo-svg" style="display:inline-block;width:40px;height:40px;flex-shrink:0;margin-right:12px;">
                        <svg width="36" height="40" viewBox="0 0 33 36" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path fill-rule="evenodd" clip-rule="evenodd" d="M16.5 0C17.1481 0 17.7936 0.196512 18.4117 0.427599C19.0489 0.66583 19.8436 1.01621 20.8214 1.44642C22.228 2.06531 23.986 2.74204 25.9758 3.30267C27.4628 3.72162 28.6843 4.06407 29.6104 4.42003C30.5263 4.77206 31.411 5.2274 32.0147 6.01954C32.5966 6.78324 32.8109 7.6648 32.9076 8.56946C33.0021 9.45453 33 10.5632 33 11.8785V16.6559C33 21.7851 30.6622 25.8444 27.8586 28.8547C25.2403 31.6661 22.1573 33.6305 19.9832 34.8061L19.5609 35.0306C18.5987 35.5339 17.765 36 16.5 36C15.235 36 14.4013 35.5339 13.4391 35.0306C11.2558 33.8885 7.93423 31.8534 5.14136 28.8547C2.38158 25.8914 0.0732929 21.9116 0.00183327 16.8954L9.12162e-06 16.6559V11.4075C-4.84578e-06 10.1081 -0.00267048 9.09713 0.0957767 8.31122C0.206005 7.43137 0.453228 6.7182 0.985655 6.01954C1.58934 5.22744 2.47399 4.77205 3.38988 4.42003C4.31602 4.06409 5.53733 3.72159 7.02418 3.30267C9.014 2.74203 10.772 2.06532 12.1786 1.44642L12.8782 1.13936C13.544 0.848206 14.1104 0.606265 14.5883 0.427599C15.2064 0.196513 15.8519 2.24081e-06 16.5 0ZM16.5 17.9998H3.1804C3.53413 21.5171 5.25027 24.4224 7.42884 26.7616C9.88968 29.4038 12.8726 31.2453 14.892 32.3017C15.814 32.784 16.0627 32.8911 16.365 32.9104L16.5 32.9143V17.9998H29.8196C29.8637 17.5614 29.8868 17.1134 29.8868 16.6559V11.8785C29.8868 10.4949 29.8848 9.5791 29.8117 8.89461C29.7495 8.31282 29.6489 8.06109 29.5651 7.92912L29.5305 7.8794C29.4632 7.79112 29.2535 7.59242 28.4846 7.29691C27.726 7.00534 26.6717 6.70675 25.1246 6.27085C22.9684 5.66337 21.0715 4.93253 19.5582 4.26665C18.5455 3.82109 17.847 3.5144 17.313 3.31472C16.829 3.13379 16.6123 3.09399 16.5283 3.08691L16.5 3.08571V17.9998ZM5.9151 7.81702C4.71154 7.81703 3.73586 8.78409 3.73586 9.97701C3.73586 11.1699 4.71154 12.137 5.9151 12.137C7.11866 12.137 8.09435 11.1699 8.09435 9.97701C8.09435 8.78408 7.11866 7.81702 5.9151 7.81702Z" fill="#10B981"/>
                        </svg>
                    </span>
                    <div style="display:flex;flex-direction:column;justify-content:center;">
                        <span style="font-size:28px;line-height:1.2;">PureScan</span>
                        <span style="font-size:15px;color:#6b7280;font-weight:500;margin-top:2px;">
                            <?php esc_html_e('File Viewer', 'purescan'); ?> • v<?php echo esc_html(PURESCAN_VERSION); ?>
                        </span>
                    </div>
                </h1>
                <div class="info">
                    <strong><?php esc_html_e('File:', 'purescan'); ?></strong> <?php echo esc_html($file_path); ?><br>
                    <strong><?php esc_html_e('Size:', 'purescan'); ?></strong> <?php echo esc_html($filesize); ?> •
                    <strong><?php esc_html_e('Last Modified:', 'purescan'); ?></strong> <?php echo esc_html($modified); ?>
                </div>
                <?php if ($is_external): ?>
                    <div class="external-notice">
                        <strong><?php esc_html_e('Warning: External File', 'purescan'); ?></strong><br><br>
                        <?php esc_html_e('This file is located outside your WordPress installation directory.', 'purescan'); ?><br>
                        <?php esc_html_e('File size and modification date may be approximate or unavailable on some hosting environments.', 'purescan'); ?><br>
                        <?php esc_html_e('Manual review is strongly recommended.', 'purescan'); ?>
                    </div>
                <?php endif; ?>
                <?php if ($is_quarantined): ?>
                    <div class="quarantine-notice">
                        <strong><?php esc_html_e('Neutralization Active — File Safely Protected', 'purescan'); ?></strong><br><br>
                        
                        <?php esc_html_e('This file has been ', 'purescan'); ?>
                        <strong><?php esc_html_e('safely neutralized', 'purescan'); ?></strong>
                        <?php esc_html_e(' by PureScan.', 'purescan'); ?><br>
                        
                        <?php esc_html_e('A secure guard has been injected at the top, completely blocking any malicious behavior in the frontend.', 'purescan'); ?><br><br>
                        
                        <?php esc_html_e('Your site remains fully functional with ', 'purescan'); ?>
                        <strong><?php esc_html_e('zero downtime', 'purescan'); ?></strong>
                        <?php esc_html_e('.', 'purescan'); ?><br>
                        
                        <?php esc_html_e('An automatic dated backup of the original file is safely stored and can be restored instantly from the Quarantine tab.', 'purescan'); ?>
                    </div>
                <?php endif; ?>
            </div>
            <table class="viewer">
                <colgroup>
                    <col class="line-num">
                    <col class="code">
                </colgroup>
                <tbody>
                <?php foreach ($lines as $i => $line):
                    $line_num = $i + 1;
                    $is_danger = isset($dangerous_lines[$line_num]);
                    $is_ai_context = isset($ai_context_lines[$line_num]);
                
                    $row_class = $is_danger ? 'danger' : ($is_ai_context ? 'ai-context' : '');
                
                    $code = htmlspecialchars(rtrim($line), ENT_QUOTES, 'UTF-8');
                    if ($code === '') {
                        $code = '&nbsp;';
                    }
                ?>
                    <tr class="<?php echo esc_attr($row_class); ?>">
                        <td class="line-num"><?php echo esc_html($line_num); ?></td>
                        <td class="code">
                            <code>
                                <?php
                                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Content is already safely escaped with htmlspecialchars() above.
                                echo $code;
                                ?>
                            </code>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <div class="footer">
                <span style="display:inline-block;width:20px;height:20px;vertical-align:-4px;margin-right:8px;">
                    <svg width="18" height="20" viewBox="0 0 18 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path fill-rule="evenodd" clip-rule="evenodd" d="M9 0C9.35351 0 9.70561 0.109174 10.0427 0.237555C10.3903 0.369906 10.8238 0.564559 11.3571 0.803569C12.1243 1.14739 13.0833 1.52336 14.1686 1.83482C14.9797 2.06756 15.646 2.25781 16.1511 2.45557C16.6507 2.65114 17.1333 2.90411 17.4625 3.34419C17.78 3.76847 17.8969 4.25822 17.9496 4.76081C18.0012 5.25252 18 5.86845 18 6.59914V9.25327C18 12.1028 16.7248 14.358 15.1956 16.0304C13.7674 17.5923 12.0858 18.6836 10.8999 19.3367L10.6696 19.4614C10.1448 19.7411 9.68999 20 9 20C8.31001 20 7.85524 19.7411 7.33041 19.4614C6.13953 18.8269 4.32776 17.6963 2.80438 16.0304C1.29904 14.3841 0.0399779 12.1731 0.000999963 9.38636L4.97543e-06 9.25327V6.33748C-2.64315e-06 5.61561 -0.00145663 5.05396 0.0522418 4.61734C0.112366 4.12854 0.247215 3.73233 0.53763 3.34419C0.866911 2.90413 1.34945 2.65114 1.84902 2.45557C2.35419 2.25783 3.02036 2.06755 3.83137 1.83482C4.91673 1.52335 5.87563 1.1474 6.64288 0.803569L7.02445 0.632978C7.38762 0.471226 7.6966 0.336814 7.95725 0.237555C8.29439 0.109174 8.6465 1.24489e-06 9 0ZM9 9.99992H1.73477C1.92771 11.954 2.86378 13.568 4.05209 14.8675C5.39437 16.3355 7.0214 17.3585 8.12292 17.9454C8.62584 18.2133 8.76146 18.2728 8.92637 18.2835L9 18.2857V9.99992H16.2652C16.2893 9.75633 16.3019 9.50747 16.3019 9.25327V6.59914C16.3019 5.83052 16.3008 5.32172 16.2609 4.94145C16.227 4.61824 16.1721 4.47838 16.1264 4.40507L16.1075 4.37744C16.0708 4.3284 15.9565 4.21801 15.5371 4.05384C15.1233 3.89186 14.5482 3.72597 13.7043 3.48381C12.5282 3.14632 11.4936 2.74029 10.6681 2.37036C10.1157 2.12283 9.73474 1.95244 9.44343 1.84151C9.17946 1.74099 9.06125 1.71888 9.01542 1.71495L9 1.71428V9.99992ZM3.22642 4.34279C2.56993 4.34279 2.03774 4.88005 2.03774 5.54279C2.03774 6.20552 2.56993 6.74278 3.22642 6.74278C3.88291 6.74278 4.4151 6.20553 4.4151 5.54279C4.4151 4.88005 3.88291 4.34279 3.22642 4.34279Z" fill="white"/>
                    </svg>
                </span>
                <?php esc_html_e('PureScan File Viewer • Highlighted lines indicate potential threats • Version', 'purescan'); ?> <?php echo esc_html(PURESCAN_VERSION); ?>
            </div>
        </div>
    </body>
    </html>
    <?php
}
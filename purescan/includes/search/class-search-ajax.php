<?php
/**
 * PureScan Live Search AJAX Handler
 * Handles real-time search and file scan from results.
 * Supports external files when External Scan is enabled.
 *
 * @package PureScan\Search
 */
namespace PureScan\Search;
if (!defined('ABSPATH')) {
    exit;
}
class Search_Ajax {
    /**
     * Perform live search via AJAX.
     */
    public static function live_search() {
        check_ajax_referer(PURESCAN_NONCE, 'nonce');
        if (!current_user_can('manage_options')) {
            wp_die();
        }
        $query = sanitize_text_field( wp_unslash( $_POST['query'] ?? '' ) );

        if (strlen($query) < Search_Engine::MIN_QUERY_LENGTH) {
            wp_send_json_success(['results' => [], 'truncated' => false]);
        }
        $results = Search_Engine::live_search($query);
        $truncated = count($results) >= Search_Engine::MAX_RESULTS;
        wp_send_json_success([
            'results' => $results,
            'truncated' => $truncated
        ]);
    }
    /**
     * Scan a file selected from Live Search results.
     */
    public static function scan_file_from_search() {
        check_ajax_referer(PURESCAN_NONCE, 'nonce');
        if (!current_user_can('manage_options')) {
            wp_die();
        }
        $path = sanitize_text_field( wp_unslash( $_POST['path'] ?? '' ) );
        if (!$path || strpos($path, '..') !== false) {
            wp_send_json_error('Invalid path');
        }
        $config = \PureScan\Settings\Settings_Handler::get();
        $external_enabled = !empty($config['external_scan_enabled']);
        // Determine full path and display path
        if ($external_enabled && $path[0] === '/') {
            // External absolute path
            $full_path = realpath($path);
            if (!$full_path || !is_file($full_path) || !is_readable($full_path)) {
                wp_send_json_error('External file not found or not readable');
            }
            // Security: ensure truly outside WordPress root
            $wp_root = realpath(ABSPATH);
            if ($wp_root && strpos($full_path, $wp_root) === 0) {
                wp_send_json_error('External path resolved to internal directory');
            }
            $display_path = $path; // Original path for display and AI
        } else {
            // Internal relative path
            $full_path = ABSPATH . ltrim($path, '/');
            $real_full = realpath($full_path);
            if (!$real_full || !is_file($real_full) || !is_readable($real_full)) {
                wp_send_json_error('File not found or not readable');
            }
            // Security: file must be inside WordPress root
            if (strpos($real_full, realpath(ABSPATH)) !== 0) {
                wp_send_json_error('Invalid internal path');
            }
            $display_path = ltrim(str_replace(ABSPATH, '', $real_full), '/');
            $full_path = $real_full;
        }
    
        $snippets = \PureScan\Scan\Scan_Engine::scan_single_file_standalone($full_path, $config);
    
        $patterns_source = get_option('purescan_patterns_source', 'Local Patterns');
    
        $ai_enabled = !empty($config['ai_deep_scan_enabled']);
        $has_suspicious = !empty($snippets);
        $has_ai_analyzed = false;
        if ($ai_enabled && $has_suspicious && class_exists('\PureScan\AI_Client')) {
            $client = new \PureScan\AI_Client();
            if ($client->is_connected()) {
                $content = file_get_contents($full_path);
                if ($content !== false && strlen($content) < 8 * 1024 * 1024) {
                    try {
                        $prompt = \PureScan\Scan\Scan_Engine::build_ai_context_from_snippets($content, $snippets);
                        // Use display_path for AI context (absolute for external, relative for internal)
                        $response = $client->analyze_code($prompt, $display_path);
                        if (!is_wp_error($response) && is_string($response) && trim($response) !== '') {
                            $parsed = \PureScan\Scan\Scan_Engine::parse_structured_ai_response($response);
                            $status = strtolower($parsed['status'] ?? 'malicious');
                            $status = in_array($status, ['clean', 'suspicious']) ? $status : 'malicious';
                            foreach ($snippets as &$snippet_group) {
                                foreach ($snippet_group as &$snippet) {
                                    $snippet['ai_status'] = $status;
                                    $snippet['ai_analysis'] = $parsed['analysis'] ?? $response;
                                    $snippet['without_ai'] = false;
                                    $snippet['ai_debug'] = [
                                        'model' => $client->get_current_model(),
                                        'timestamp' => current_time('mysql'),
                                        'raw_response' => $response,
                                    ];
                                }
                            }
                            unset($snippet);
                            $has_ai_analyzed = true;
                        }
                    } catch (\Throwable $e) {
                        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Logging AI analysis failure for troubleshooting in production.
                        error_log('PureScan Live Search AI auto-analysis failed: ' . $e->getMessage());
                    }
                }
            }
        }
        $finding = !empty($snippets) ? [
            'path' => $display_path,
            'size' => filesize($full_path),
            'mtime' => date_i18n('Y-m-d H:i', filemtime($full_path)),
            'snippets' => $snippets,
            'ai_enabled_in_settings' => $ai_enabled,
            'ai_analyzed' => $has_ai_analyzed
        ] : null;
    
        $state = get_option(PURESCAN_STATE, []);
        $state['live_search_finding'] = $finding;
        $state['live_search_path'] = $display_path;
        update_option(PURESCAN_STATE, $state, false);
    
        wp_send_json_success([
            'clean' => empty($snippets),
            'snippets' => $snippets,
            'path' => $display_path,
            'findings' => $finding ? [$finding] : [],
            'patterns_source' => $patterns_source,
        ]);
    }
}
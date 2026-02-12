<?php
/**
 * PureScan Scan AJAX Handler
 * Manages scan lifecycle: start, cancel, progress, single file, snippets.
 *
 * @package PureScan\Scan
 */
namespace PureScan\Scan;

if (!defined('ABSPATH')) {
    exit;
}

class Scan_Ajax {
    /**
     * Start a new deep scan (manual).
     * Now fully compatible with the new opportunistic background architecture.
     */
    public static function start_scan() {
        check_ajax_referer(PURESCAN_NONCE, 'nonce');
        if (!current_user_can('manage_options')) {
            wp_die();
        }
        
        $host = wp_parse_url( home_url(), PHP_URL_HOST );
        if ($host) {
            $key = 'purescan_pro_status_' . md5($host);
            delete_transient($key);
        }
        
        \PureScan\Settings\Settings_Handler::get();
    
        $state = get_option(PURESCAN_STATE, []);
        if (($state['status'] ?? '') === 'running') {
            wp_send_json_error([
                'message' => __('Scan is already running.', 'purescan')
            ]);
        }
        
        $state = get_option(PURESCAN_STATE, []);
        unset($state['live_search_finding'], $state['live_search_path']);
        update_option(PURESCAN_STATE, $state, false);
    
        delete_transient('purescan_file_list_temp');
        delete_transient('purescan_engine_lock');
        delete_transient('purescan_bg_lock');
        delete_transient('purescan_local_hashes_cache');
        delete_option('purescan_background_flag');
        delete_transient('purescan_remote_patterns_cache');
        delete_transient('purescan_patterns_remote_failed');
        delete_option('purescan_patterns_source');
        delete_transient('purescan_local_patterns_cache');
    
        delete_option(PURESCAN_STATE);
    
        update_option(PURESCAN_STATE, [
            'status' => 'running',
            'started' => current_time('mysql'),
            'scan_start_time' => microtime(true),
            'progress' => 0,
            'scanned' => 0,
            'suspicious' => 0,
            'findings' => [],
            'is_scheduled_scan' => false,
            'is_manual_scan' => true,
            'initialized' => true,
            'chunk_start' => 0,
            'file_list' => [],
            'total_files' => 0,
        ], false);
    
        update_option('purescan_background_flag', time(), false);
    
        wp_send_json_success([
            'message' => __('Scan started cleanly from scratch. Running in background.', 'purescan'),
        ]);
    }

    /**
     * Cancel running scan — Ultra-robust industrial version
     * Force immediate and permanent stop with full cleanup
     * Preserves partial findings while preventing any resumption or restart
     */
    public static function cancel_scan() {
        check_ajax_referer(PURESCAN_NONCE, 'nonce');
        if (!current_user_can('manage_options')) {
            wp_die();
        }
    
        $state = get_option(PURESCAN_STATE, []);
    
        // If no active running scan, nothing to do
        if (empty($state['status']) || $state['status'] !== 'running') {
            wp_send_json_success([
                'message' => __('No active scan to cancel.', 'purescan')
            ]);
        }
    
        // Activate aggressive force-cancel flags to trigger repetitive enforcement
        set_transient('purescan_force_cancel', '1', 300); // 5 minutes persistence
        update_option('purescan_cancel_pending', true, false);
    
        // Force cancelled state
        $state['status'] = 'cancelled';
        $state['cancelled_at'] = current_time('mysql');
        $state['elapsed'] = round(
            microtime(true) - ($state['scan_start_time'] ?? microtime(true)),
            2
        );
        $state['progress_frozen'] = true;
    
        $suspicious_count = count($state['findings'] ?? []);
    
        // Build user-friendly detail message
        $scanned_display = number_format($state['scanned'] ?? 0);
        $detail = sprintf(
            '%s files scanned • %s suspicious issue(s) found before cancellation',
            $scanned_display,
            number_format($suspicious_count)
        );
    
        $state['final_message'] = [
            'text' => 'Scan was cancelled',
            'detail' => $detail,
            'icon' => 'warning',
            'color' => '#f59e0b',
            'box_class' => 'cancelled',
        ];
    
        $state['current_folder'] = [
            'short' => 'Scan Cancelled',
            'label' => $detail,
            'icon' => 'warning',
            'color' => '#f59e0b',
        ];
    
        // === ULTRA CLEANUP: Remove all temporary/resumable state keys ===
        // Partial results (findings, scanned, suspicious, step_counts, etc.) are preserved
        $temporary_keys = [
            'discovery_phase',
            'file_discovery_started',
            'external_industrial_phase',
            'external_file_list',
            'temp_server_files',
            'temp_server_count',
            'file_list',
            'total_files',
            'total_files_for_display',
            'chunk_start',
            'malware_scan_phase',
            'adaptive_chunk',
            'core_phase',
            'plugin_phase',
            'core_check_started',
            'plugin_check_started',
            'core_check_completed',
            'plugin_check_completed',
            'spamvertising_content_completed',
            'password_strength_completed',
            'user_option_audit_completed',
            'is_manual_scan',
            'is_scheduled_scan',
            'initialized',
            'scan_start_time',
        ];
    
        foreach ($temporary_keys as $key) {
            unset($state[$key]);
        }
    
        update_option(PURESCAN_STATE, $state, false);
    
        // Force clear cached option
        wp_cache_delete(PURESCAN_STATE, 'options');
    
        // === FINAL HARD CLEANUP: All locks, transients and background flag ===
        delete_transient('purescan_engine_lock');
        delete_transient('purescan_bg_lock');
        delete_transient('purescan_file_list_temp');
        delete_transient('purescan_local_hashes_cache');
        delete_option('purescan_background_flag');
        delete_transient('purescan_remote_patterns_cache');
        delete_transient('purescan_patterns_remote_failed');
        delete_option('purescan_patterns_source');
        delete_transient('purescan_local_patterns_cache');
    
        wp_send_json_success([
            'message' => __('Scan cancelled instantly and permanently.', 'purescan')
        ]);
    }

    /**
     * Get current scan progress and state.
     */
    public static function get_progress() {
        check_ajax_referer(PURESCAN_NONCE, 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.']);
        }
        $state = get_option(PURESCAN_STATE, []);
        $all_findings = array_merge($state['core_findings'] ?? [], $state['findings'] ?? []);
        if (!empty($all_findings)) {
            $ai_enabled = !empty(\PureScan\Settings\Settings_Handler::get()['ai_deep_scan_enabled']);
            foreach ($all_findings as &$finding) {
                $finding['ai_enabled_in_settings'] = $ai_enabled;
            }
            unset($finding);
        }
        $default_folder = [
            'short' => 'Preparing Scan',
            'label' => 'Collecting files and initializing scanner...',
            'icon' => 'admin-home',
            'color' => '#6366f1',
        ];
        $current_folder = $state['current_folder'] ?? $default_folder;
        if (is_array($current_folder)) {
            $current_folder = wp_parse_args($current_folder, $default_folder);
        } else {
            $current_folder = $default_folder;
        }
        // Base response with safe defaults
        $response = wp_parse_args($state, [
            'status' => 'idle',
            'scanned' => 0,
            'suspicious' => 0,
            'progress' => 0,
            'findings' => [],
            'elapsed' => 0,
            'started' => null,
            'completed' => null,
        ]);
        // Manual progress calculation (fallback for sites where 'progress' is not reliably saved)
        $scanned = $response['scanned'] ?? 0;
        $total_display = $response['total_files_for_display'] ?? 0;
        $total_fallback = $response['total_files'] ?? 0;
        $calculated_progress = 0;
        if ($total_display > 0) {
            $calculated_progress = min(100, round(($scanned / $total_display) * 100));
        } elseif ($total_fallback > 0) {
            $calculated_progress = min(100, round(($scanned / $total_fallback) * 100));
        }
        // Force 100% on completed, cancelled, or single file scans
        if (in_array($response['status'], ['completed', 'cancelled', 'single'], true)) {
            $calculated_progress = 100;
        }
        $response['progress'] = $calculated_progress;
        $response['findings'] = $all_findings;
        $response['current_folder'] = $current_folder;
        // === LIVE COUNTERS (exactly the same logic as Core::get_counters()) ===
        $threat_count = (int) ($state['suspicious'] ?? 0);
        $quarantined_files = get_option('purescan_bne_quarantined', []);
        $quarantine_count = is_array($quarantined_files) ? count($quarantined_files) : 0;
        $ignored_files = get_option('purescan_ignored_files', []);
        $ignored_count = is_array($ignored_files) ? count($ignored_files) : 0;
        $response['counters'] = [
            'threats' => $threat_count,
            'quarantine' => $quarantine_count,
            'ignored' => $ignored_count,
        ];
    
        // === Send patterns source for real-time badge update ===
        $response['patterns_source'] = get_option('purescan_patterns_source', '');
    
        wp_send_json_success($response);
    }

    /**
     * Scan a single file from path.
     */
    public static function scan_single_file() {
        check_ajax_referer(PURESCAN_NONCE, 'nonce');
        if (!current_user_can('manage_options')) {
            wp_die();
        }

        $path = sanitize_text_field( wp_unslash( $_POST['path'] ?? '' ) );
        if (!$path || strpos($path, '..') !== false || $path[0] === '/') {
            wp_send_json_error('Invalid path');
        }

        $full_path = ABSPATH . ltrim($path, '/');
        if (!file_exists($full_path) || !is_file($full_path)) {
            wp_send_json_error('File not found');
        }

        $config = \PureScan\Settings\Settings_Handler::get();
        $engine = new Scan_Engine($config);
        $snippets = $engine->scan_single_file($full_path);

        $finding = [
            'path'     => $path,
            'size'     => filesize($full_path),
            'mtime' => date_i18n( 'Y-m-d H:i', filemtime( $full_path ) ),
            'snippets' => $snippets
        ];

        $state = [
            'status'        => 'single',
            'single_clean'  => empty($snippets),
            'findings'      => [$finding],
            'scanned'       => 1,
            'suspicious'    => count($snippets),
            'progress'      => 100,
            'elapsed'       => 0
        ];

        update_option('purescan_single_scan_state', $state);
        wp_send_json_success($state);
    }

    public static function clear_results() {
        check_ajax_referer(PURESCAN_NONCE, 'nonce');
        if (!current_user_can('manage_options')) {
            wp_die();
        }
   
        $state = get_option(PURESCAN_STATE, []);
   
        if (!empty($state)) {
            unset(
                $state['status'],
                $state['started'],
                $state['completed'],
                $state['cancelled_at'],
                $state['elapsed'],
                $state['scanned'],
                $state['suspicious'],
                $state['progress'],
                $state['findings'],
                $state['core_findings'],
                $state['final_message'],
                $state['current_folder'],
                $state['progress_frozen'],
                $state['is_scheduled_scan'],
                $state['is_manual_scan'],
                $state['discovery_phase'],
                $state['file_discovery_started'],
                $state['external_industrial_phase'],
                $state['external_file_list'],
                $state['temp_server_files'],
                $state['temp_server_count'],
                $state['file_list'],
                $state['total_files'],
                $state['total_files_for_display'],
                $state['chunk_start'],
                $state['malware_scan_phase'],
                $state['adaptive_chunk'],
                $state['core_phase'],
                $state['plugin_phase'],
                $state['core_check_started'],
                $state['plugin_check_started'],
                $state['core_check_completed'],
                $state['plugin_check_completed'],
                $state['live_search_finding'],
                $state['live_search_path']
            );
   
            $state['status'] = 'idle';
            $state['progress'] = 0;
            $state['scanned'] = 0;
            $state['suspicious'] = 0;
            $state['findings'] = [];
   
            update_option(PURESCAN_STATE, $state, false);
        } else {
            update_option(PURESCAN_STATE, ['status' => 'idle'], false);
        }
   
        delete_option('purescan_ai_results');
        delete_transient('purescan_file_list_temp');
        delete_transient('purescan_engine_lock');
        delete_transient('purescan_bg_lock');
        delete_option('purescan_background_flag');
        delete_transient('purescan_local_hashes_cache');
        delete_transient('purescan_remote_patterns_cache');
        delete_transient('purescan_patterns_remote_failed');
        delete_option('purescan_patterns_source');
        delete_transient('purescan_local_patterns_cache');
   
        wp_send_json_success([
            'message' => __('All scan results and temporary data cleared successfully.', 'purescan')
        ]);
    }
}
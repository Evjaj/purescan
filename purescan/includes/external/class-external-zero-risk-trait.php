<?php
/**
 * PureScan Industrial External Engine Trait - Smart Targeted Forensic Mode
 *
 * High-performance, resumable, deep external filesystem scanner with smart targeting.
 *
 * Key Features:
 * - Fully resumable with directory stack and persistent state
 * - Prioritizes high-risk directories based on real-world malware reports (Sucuri, Wordfence 2024-2025)
 * - Collects all readable files (no strict extension filtering) to cover hidden payloads in txt/log/zip/cache
 * - Skips only critical performance/safety paths (e.g., massive session dir in CageFS)
 * - No depth/size/number limits beyond safety (resumable prevents timeout)
 * - Strict separation: NEVER includes any file physically inside WordPress root (public_html/ABSPATH)
 *
 * @package PureScan\External
 * @since 2.0 Industrial Edition
 */
namespace PureScan\External;
use PureScan\External\IndustrialPolicy;
if (!defined('ABSPATH')) {
    exit;
}
trait IndustrialEngineTrait
{
    /**
     * High-risk directories prioritized based on malware reports (Sucuri/Wordfence 2024-2025)
     * Common external hiding spots: tmp, cache, logs, CageFS, etc.
     */
    protected $priority_dirs = [
        'tmp/', 'var/tmp/', '/dev/shm/',
        'cache/', 'caches/', 'twig/', 'compiled/', 'compiles/', 'template_cache/', 'smarty_cache/', 'var/cache/',
        'logs/', 'access-logs/', 'mail/', 'error_logs/',
        '.cpanel/', '.trash/', '.softaculous/',
        '.cagefs/', // Full CageFS is high-risk for backdoors
    ];
    protected function execute_industrial_external_scan(array &$state, array &$findings): void
    {
        if (empty($state['external_industrial_phase'])) {
            $this->initialize_external_discovery($state);
            return;
        }
        if ($state['external_industrial_phase'] === 'discovery') {
            $this->continue_external_discovery($state);
            if ($state['external_industrial_phase'] === 'discovery') {
                return;
            }
        }
    }
    private function initialize_external_discovery(array &$state): void
    {
        $wp_root_real = realpath(ABSPATH) ?: ABSPATH;
        $home_dir = dirname(rtrim($wp_root_real, '/'));
        $home_dir_real = realpath($home_dir) ?: $home_dir;
        $wp_root_realpath = realpath($wp_root_real) ?: rtrim($wp_root_real, '/');

        // Start with home root, then prioritize high-risk dirs
        $stack = [$home_dir_real . '/'];
        foreach ($this->priority_dirs as $pri) {
            $full = $home_dir_real . '/' . ltrim($pri, '/');
            if (is_dir($full) && realpath($full) !== false) {
                array_unshift($stack, $full . '/'); // Process high-risk first
            }
        }
        $state['external_industrial_phase'] = 'discovery';
        $state['external_engine'] = [
            'home_dir_real' => $home_dir_real,
            'wp_root_realpath' => $wp_root_realpath,
            'directory_stack' => $stack,
            'files' => [],
            'seen_paths' => [],
            'skipped_count' => 0,
        ];

        update_option(PURESCAN_STATE, $state, false);
    }
    private function continue_external_discovery(array &$state): void
    {
        $engine = &$state['external_engine'];
        $policy = IndustrialPolicy::get_merged($this->config);
        $safe_time = ((int)ini_get('max_execution_time') ?: 30) - 8;
        $forbidden = $policy['external_forbidden_paths'] ?? [];
        $cagefs_allowed = array_merge($policy['cagefs_allowed_paths'] ?? [], ['.cagefs', '/.cagefs']);
        $start_time = microtime(true);
        $wp_root_realpath = $engine['wp_root_realpath'];
    
        while (!empty($engine['directory_stack'])) {
            // Time safety check
            if ((microtime(true) - $start_time) > $safe_time) {
                $this->update_discovery_ui($state);
                update_option(PURESCAN_STATE, $state, false);
                return;
            }
    
            // Fresh status check on every directory processed
            $current_state = get_option(PURESCAN_STATE, []);
            if (($current_state['status'] ?? '') !== 'running') {
                $this->update_discovery_ui($state);
                update_option(PURESCAN_STATE, $state, false);
                unset($state['external_engine']);
                return;
            }
    
            $dir = array_pop($engine['directory_stack']);
            $dir = rtrim($dir, '/');
            $real_dir = @realpath($dir) ?: $dir;
            $is_cagefs = stripos($real_dir, '/.cagefs') !== false;
    
            // Critical safety skip: massive PHP session directory in CageFS
            $basename = basename($dir);
            if ($is_cagefs && $basename === 'session') {
                $engine['skipped_count']++;
                continue;
            }
    
            $items = @scandir($dir);
            if ($items === false) {
                $engine['skipped_count']++;
                continue;
            }
    
            foreach (array_reverse($items) as $item) {
                if ($item === '.' || $item === '..') {
                    continue;
                }
    
                $full_path = $dir . DIRECTORY_SEPARATOR . $item;
                $real_path = @realpath($full_path) ?: $full_path;
    
                // Essential security checks
                if (strpos($real_path, $engine['home_dir_real'] . DIRECTORY_SEPARATOR) !== 0) {
                    $engine['skipped_count']++;
                    continue;
                }
    
                // Strict exclusion using realpath – prevents any overlap with internal scan
                if (strpos($real_path, $wp_root_realpath . DIRECTORY_SEPARATOR) === 0 || $real_path === $wp_root_realpath) {
                    continue;
                }
    
                if (@is_link($full_path) && @is_dir($full_path) && !$is_cagefs) {
                    $engine['skipped_count']++;
                    continue;
                }
    
                $skip = false;
                foreach ($forbidden as $danger) {
                    $danger_real = @realpath($danger) ?: $danger;
                    if (strpos($real_path . '/', $danger_real . '/') === 0) {
                        $skip = true;
                        break;
                    }
                }
                if ($skip) {
                    continue;
                }
    
                $new_is_cagefs = $is_cagefs || stripos($real_path, '/.cagefs') !== false;
                if ($new_is_cagefs) {
                    $allowed = false;
                    foreach ($cagefs_allowed as $allowed_sub) {
                        if (stripos($real_path, $allowed_sub) !== false) {
                            $allowed = true;
                            break;
                        }
                    }
                    if (!$allowed) {
                        $engine['skipped_count']++;
                        continue;
                    }
                }
    
                if (@is_dir($full_path)) {
                    $engine['directory_stack'][] = $full_path . '/';
                    continue;
                }
    
                if (!@is_file($full_path) || !@is_readable($full_path)) {
                    continue;
                }
    
                // Loose size limit for safety (skip extremely large files)
                $size = @filesize($full_path);
                if ($size === false || $size > 100 * 1048576) { // 100 MB
                    continue;
                }
                
                // Additional safety: Skip any external paths related to PureScan plugin
                // (own files, backups, quarantine copies, or files in trash/backups outside WordPress root)
                $lower_real_path = strtolower($real_path);
                if (
                    strpos($lower_real_path, '/purescan/') !== false ||
                    strpos($lower_real_path, '\\purescan\\') !== false ||
                    strpos($lower_real_path, '/purescan-backups/') !== false ||
                    strpos($lower_real_path, '\\purescan-backups\\') !== false
                ) {
                    $engine['skipped_count']++;
                    continue;
                }
    
                // Collect all readable files (covers payloads hidden in txt/log/zip/cache)
                $normalized = $real_path !== $full_path ? $real_path : $full_path;
                if (isset($engine['seen_paths'][$normalized])) {
                    continue;
                }
                $engine['seen_paths'][$normalized] = true;
                $engine['files'][] = $full_path;
            }
    
            // UI update every 20 files + extra status check for maximum responsiveness
            if (count($engine['files']) % 20 === 0) {
                // Extra fresh status check before UI update
                $current_state = get_option(PURESCAN_STATE, []);
                if (($current_state['status'] ?? '') !== 'running') {
                    $this->update_discovery_ui($state);
                    update_option(PURESCAN_STATE, $state, false);
                    unset($state['external_engine']);
                    return;
                }
    
                $this->update_discovery_ui($state);
                update_option(PURESCAN_STATE, $state, false);
            }
        }
    
        // Discovery completed
        $state['external_file_list'] = $engine['files'];
        $state['external_industrial_phase'] = 'complete';
        unset($state['external_engine']);
        update_option(PURESCAN_STATE, $state, false);
    }
    private function update_discovery_ui(array &$state): void
    {
        $engine = $state['external_engine'];
        $state['current_folder'] = [
            'short' => 'Server Files Discovered',
            'label' => number_format(count($engine['files'])) . ' server files discovered outside WordPress root',
            'icon' => 'search',
            'color' => '#7c3aed',
        ];
    }
}
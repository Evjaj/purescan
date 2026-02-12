<?php
/**
 * PureScan Live Search Engine
 * Real-time file search with path filtering and exclusion.
 * Supports external files when External Scan is enabled.
 *
 * @package PureScan\Search
 */

namespace PureScan\Search;

if (!defined('ABSPATH')) {
    exit;
}

class Search_Engine {

    /**
     * Maximum results to return.
     */
    const MAX_RESULTS = 50;

    /**
     * Minimum query length.
     */
    const MIN_QUERY_LENGTH = 2;

    /**
     * Perform live search.
     *
     * @param string $query Search term.
     * @return array Results array.
     */
    public static function live_search($query) {
        $query = trim($query);
        if (strlen($query) < self::MIN_QUERY_LENGTH) {
            return [];
        }

        $query = sanitize_text_field($query);
        $results = [];
        $seen_realpaths = []; // Prevent duplicates (including symlinks)
        $config = \PureScan\Settings\Settings_Handler::get();
        $external_enabled = !empty($config['external_scan_enabled']);
        $wp_root = realpath(ABSPATH);

        // ==================================================================
        // 1. Support for absolute external path (e.g., /.cagefs/tmp/.accepted)
        // ==================================================================
       if ($external_enabled && $query[0] === '/') {
            $candidate = realpath($query);
            if ($candidate && is_file($candidate) && is_readable($candidate)) {
                if (!$wp_root || strpos($candidate, $wp_root) !== 0) {
                    $lower_candidate = strtolower($candidate);
                    if (
                        strpos($lower_candidate, '/purescan/') !== false ||
                        strpos($lower_candidate, '\\purescan\\') !== false ||
                        strpos($lower_candidate, '/purescan-backups/') !== false ||
                        strpos($lower_candidate, '\\purescan-backups\\') !== false
                    ) {
                        return [];
                    }

                    if (!in_array($candidate, $seen_realpaths)) {
                        $seen_realpaths[] = $candidate;
                        $results[] = [
                            'path' => $query,
                            'size' => filesize($candidate),
                            'mtime' => date_i18n('Y-m-d H:i', filemtime($candidate))
                        ];
                    }
                }
            }
        }

        // ==================================================================
        // 2. Partial search in common external paths (e.g., typing ".accepted")
        // ==================================================================
        if ($external_enabled && $query[0] !== '/') {
            $external_base_paths = [
                '/.cagefs',
                '/tmp',
                '/var/tmp',
                // Add more base paths if needed
            ];

            $external_scanned = 0;
            $max_external_scan = 5000; // Safety limit

            foreach ($external_base_paths as $base) {
                $real_base = realpath($base);
                if (!$real_base || !is_dir($real_base)) {
                    continue;
                }
                if ($wp_root && strpos($real_base, $wp_root) === 0) {
                    continue;
                }

                try {
                    $iterator = new \RecursiveIteratorIterator(
                        new \RecursiveDirectoryIterator($real_base, \RecursiveDirectoryIterator::SKIP_DOTS),
                        \RecursiveIteratorIterator::LEAVES_ONLY
                    );

                    foreach ($iterator as $file) {
                        if (count($results) >= self::MAX_RESULTS) {
                            break 2;
                        }

                        $external_scanned++;
                        if ($external_scanned > $max_external_scan) {
                            break 2;
                        }

                        if (!$file->isFile() || !$file->isReadable()) {
                            continue;
                        }

                        $full_path = $file->getPathname();
                        $real_full = realpath($full_path);
                        if (!$real_full) {
                            continue;
                        }

                        if ($wp_root && strpos($real_full, $wp_root) === 0) {
                            continue;
                        }
                        
                        $lower_full = strtolower($real_full);
                        if (
                            strpos($lower_full, '/purescan/') !== false ||
                            strpos($lower_full, '\\purescan\\') !== false ||
                            strpos($lower_full, '/purescan-backups/') !== false ||
                            strpos($lower_full, '\\purescan-backups\\') !== false
                        ) {
                            continue;
                        }

                        $filename = $file->getFilename();
                        if (stripos($filename, $query) === false && stripos($full_path, $query) === false) {
                            continue;
                        }

                        if (!in_array($real_full, $seen_realpaths)) {
                            $seen_realpaths[] = $real_full;
                            $results[] = [
                                'path'  => $full_path, // Full absolute path for external files
                                'size'  => $file->getSize(),
                                'mtime' => date_i18n('Y-m-d H:i', $file->getMTime())
                            ];
                        }
                    }
                } catch (\Exception $e) {
                    continue;
                }
            }
        }

        // ==================================================================
        // 3. Standard internal WordPress search (preserves original logic)
        // ==================================================================
        $roots = self::get_search_roots();

        foreach ($roots as $root) {
            if (count($results) >= self::MAX_RESULTS) {
                break;
            }

            $real_root = realpath($root);
            if (!$real_root || !is_dir($real_root)) {
                continue;
            }

            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($real_root, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::LEAVES_ONLY
                );

                foreach ($iterator as $file) {
                    if (count($results) >= self::MAX_RESULTS) {
                        break 2;
                    }

                    if (!$file->isFile() || !$file->isReadable()) {
                        continue;
                    }

                    $full_path = $file->getPathname();
                    $real_full = realpath($full_path);
                    if (!$real_full || in_array($real_full, $seen_realpaths)) {
                        continue;
                    }

                    $seen_realpaths[] = $real_full;

                    $relative_path = ltrim(str_replace(ABSPATH, '', $full_path), '/');
                    
                    if (
                        strpos($relative_path, 'wp-content/plugins/purescan/') === 0 ||
                        strpos($relative_path, 'wp-content/purescan-backups/') === 0
                    ) {
                        continue;
                    }

                    if (!self::path_matches($relative_path, $query)) {
                        continue;
                    }

                    if (self::is_excluded($relative_path)) {
                        continue;
                    }

                    $results[] = [
                        'path'  => $relative_path,
                        'size'  => $file->getSize(),
                        'mtime' => date_i18n('Y-m-d H:i', $file->getMTime())
                    ];
                }
            } catch (\Exception $e) {
                continue;
            }
        }

        return $results;
    }

    /**
     * Check if path matches query (case-insensitive).
     *
     * @param string $path  File path.
     * @param string $query Search term.
     * @return bool
     */
    private static function path_matches($path, $query) {
        return stripos($path, $query) !== false;
    }

    /**
     * Get root directories to search.
     *
     * @return array
     */
    private static function get_search_roots() {
        $config = \PureScan\Settings\Settings_Handler::get();
        $include_paths = $config['include_paths'] ?? '';

        $paths = array_filter(array_map('trim', explode("\n", $include_paths)));
        return empty($paths) ? [ABSPATH] : array_map('realpath', $paths);
    }

    /**
     * Check if path is excluded.
     *
     * @param string $path Relative path.
     * @return bool
     */
    private static function is_excluded($path) {
        $config = \PureScan\Settings\Settings_Handler::get();
        $excludes = array_map('trim', explode("\n", $config['exclude_paths'] ?? ''));

        $norm_path = rtrim(str_replace('\\', '/', $path), '/');
        foreach ($excludes as $ex) {
            $ex = trim($ex, " /\t\n\r\0\x0B");
            if ($ex && strpos($norm_path . '/', $ex . '/') === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Scan a file from Live Search and return result.
     *
     * @param string $path Path (relative internal or absolute external).
     * @return array
     */
    public static function scan_file_from_search($path) {
        $config = \PureScan\Settings\Settings_Handler::get();
        $external_enabled = !empty($config['external_scan_enabled']);

        // Determine full path and display path
        if ($external_enabled && $path[0] === '/') {
            // External absolute path
            $full_path = realpath($path);
            if (!$full_path || !is_file($full_path) || !is_readable($full_path)) {
                return ['error' => 'External file not found or not readable'];
            }

            $wp_root = realpath(ABSPATH);
            if ($wp_root && strpos($full_path, $wp_root) === 0) {
                return ['error' => 'External path resolved to internal directory'];
            }

            $display_path = $path;
        } else {
            // Internal relative path
            $full_path = ABSPATH . ltrim($path, '/');
            $real_full = realpath($full_path);

            if (!$real_full || !is_file($real_full) || !is_readable($real_full)) {
                return ['error' => 'File not found or not readable'];
            }

            if (strpos($real_full, realpath(ABSPATH)) !== 0) {
                return ['error' => 'Invalid internal path'];
            }

            $display_path = ltrim(str_replace(ABSPATH, '', $real_full), '/');
            $full_path = $real_full;
        }

        $snippets = \PureScan\Scan\Scan_Engine::scan_single_file_standalone($full_path, $config);

        if (!empty($snippets) && !empty($config['ai_deep_scan_enabled'])) {
            $client = new \PureScan\AI_Client();
            if ($client->is_connected()) {
                foreach ($snippets as &$snippet_group) {
                    foreach ($snippet_group as &$snippet) {
                        if (empty($snippet['ai_status']) || $snippet['ai_status'] === 'skipped') {
                            $context = \PureScan\Scan\Scan_Engine::build_ai_context_from_snippets(
                                file_get_contents($full_path), [$snippet]
                            );
                            $ai_response = $client->analyze_code($context, $display_path);
                            if (!is_wp_error($ai_response) && is_string($ai_response)) {
                                $parsed = \PureScan\Scan\Scan_Engine::parse_structured_ai_response($ai_response);
                                $status = strtolower($parsed['status'] ?? 'malicious');
                                $status = in_array($status, ['clean','suspicious']) ? $status : 'malicious';
                                $snippet['ai_status'] = $status;
                                $snippet['ai_analysis'] = $parsed['analysis'] ?? $ai_response;
                                $snippet['without_ai'] = false;
                            }
                        }
                    }
                }
            }
        }

        $finding = !empty($snippets) ? [
            'path' => $display_path,
            'size' => filesize($full_path),
            'mtime' => date_i18n('Y-m-d H:i', filemtime($full_path)),
            'snippets' => $snippets
        ] : null;

        return [
            'clean' => empty($snippets),
            'findings' => $finding ? [$finding] : [],
            'path' => $display_path
        ];
    }
}
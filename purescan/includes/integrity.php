<?php
/**
 * PureScan Integrity Helper
 * @package PureScan
 */

if (!defined('ABSPATH')) {
    exit;
}

function purescan_compute_plugin_hashes(): array {
    static $cached_hashes = null;
    if ($cached_hashes !== null) return $cached_hashes;

    $cache_key = 'purescan_local_hashes_cache';
    $cached = get_transient($cache_key);
    if ($cached !== false) return $cached;

    $plugin_dir = rtrim(PURESCAN_DIR, '/');
    $hashes = [];

    $allowed_ext = ['php', 'inc', 'js', 'css', 'html', 'htm', 'json', 'xml', 'txt'];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($plugin_dir, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $full_path) {
        if (!is_file($full_path) || !is_readable($full_path)) continue;

        $ext = strtolower(pathinfo($full_path, PATHINFO_EXTENSION));
        if (!in_array($ext, $allowed_ext)) continue;

        $relative_path = ltrim(str_replace($plugin_dir, '', $full_path), '/\\');
        $relative_path = str_replace('\\', '/', $relative_path);
        $hashes[$relative_path] = hash_file('sha256', $full_path);
    }

    ksort($hashes);
    $cached_hashes = $hashes;
    set_transient($cache_key, $hashes, HOUR_IN_SECONDS);
    return $hashes;
}

/**
 * @return string
 */
function purescan_get_integrity_header_value(): string {
    $hashes = purescan_compute_plugin_hashes();
    return base64_encode(wp_json_encode($hashes));
}
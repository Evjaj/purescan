<?php
/**
 * PureScan Industrial External Scan Policy
 * Ultra-secure, adaptive and highly configurable policy engine for smart targeted external scanning.
 *
 * Optimized for current threats:
 * - Aggressive mode enabled by default for broader coverage
 * - High limits to support comprehensive collection in targeted mode
 * - CageFS fully allowed when external scan is enabled
 *
 * @package PureScan\External
 * @since 2.0 Industrial Edition
 */
namespace PureScan\External;
if (!defined('ABSPATH')) {
    exit;
}
final class IndustrialPolicy
{
    public static function defaults(): array
    {
        $max_exec_time = max(30, (int)ini_get('max_execution_time') ?: 30);
        $adaptive_max_files = min(100000, max(10000, $max_exec_time * 500)); // High for targeted mode
        return [
            'external_scan_enabled' => false,
            'external_max_files' => $adaptive_max_files,
            'external_max_file_size_mb' => 100, // Loose limit (handled in code)
            'external_max_depth' => 100, // Effectively unlimited
            'external_chunk_size' => 60,
            'external_forbidden_paths' => [
                '/proc', '/sys', '/dev', '/etc', '/root', '/boot', '/lost+found',
                '/var/lib/mysql', '/var/lib/postgresql', '/var/log', '/var/cache',
                '/tmp', '/var/tmp', '/run',
            ],
            'external_scannable_extensions' => [''], // Not strictly used in smart mode
            'external_aggressive_mode' => true, // Default aggressive for maximum coverage
            'external_ui_mode' => 'basic',
            'cagefs_allowed_paths' => ['/.cagefs'],
            'cagefs_max_depth' => 10,
            'cagefs_max_file_size_kb' => 102400, // 100 MB
            'cagefs_scannable_extensions' => ['php', 'phtml', 'inc', 'js', 'txt', 'log', 'zip', '']
        ];
    }

    public static function get_merged(array $user_settings = []): array
    {
        $defaults = self::defaults();
        $allowed_keys = array_keys($defaults);
        foreach ($allowed_keys as $key) {
            if (!isset($user_settings[$key])) {
                continue;
            }
            switch ($key) {
                case 'external_scan_enabled':
                case 'external_aggressive_mode':
                    $defaults[$key] = !empty($user_settings[$key]);
                    break;
                case 'external_ui_mode':
                    $valid = ['basic', 'expert'];
                    $defaults[$key] = in_array($user_settings[$key], $valid, true) ? $user_settings[$key] : 'basic';
                    break;
                case 'external_max_files':
                case 'external_max_file_size_mb':
                case 'external_max_depth':
                case 'external_chunk_size':
                case 'cagefs_max_depth':
                case 'cagefs_max_file_size_kb':
                    $value = (int)$user_settings[$key];
                    $defaults[$key] = max(($key === 'external_max_files' ? 500 : 1), $value);
                    if ($key === 'external_max_files') {
                        $defaults[$key] = min(200000, $defaults[$key]);
                    }
                    break;
            }
        }
        return $defaults;
    }
}
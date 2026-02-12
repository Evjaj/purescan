<?php
/**
 * PureScan Runtime Guard – Standalone & Safe
 *
 * This class is completely independent and can be used in any neutralized file
 * without requiring the main Core class to be loaded.
 */

namespace PureScan;

if (!defined('ABSPATH')) {
    exit;
}

final class Runtime_Guard {

    /**
     * Determine if execution should be blocked in frontend
     *
     * @return bool True if should block (frontend), false if allow (admin/ajax/cron)
     */
    public static function should_block(): bool {
        if (defined('PURESCAN_ALLOW_EXECUTION') && PURESCAN_ALLOW_EXECUTION) {
            return false;
        }

        if (defined('WP_ADMIN') && WP_ADMIN) {
            return false;
        }

        if (function_exists('wp_doing_ajax') && wp_doing_ajax()) {
            return false;
        }

        if (function_exists('wp_doing_cron') && wp_doing_cron()) {
            return false;
        }

        return true;
    }
}
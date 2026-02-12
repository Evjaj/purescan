<?php
/**
 * PureScan Activator
 * Handles plugin activation: secure token, cron scheduling, cleanup.
 *
 * @package PureScan
 */

namespace PureScan;

if (!defined('ABSPATH')) {
    exit;
}

class Activator {

    /**
     * Execute on plugin activation.
     */
    public static function activate() {
        // Generate secure admin token if not exists
        $settings = get_option(PURESCAN_OPTION, []);
        if (empty($settings['admin_token'])) {
            $settings['admin_token'] = wp_generate_uuid4();
            update_option(PURESCAN_OPTION, $settings);
        }

        // Schedule weekly cleanup of old scan results
        if (!wp_next_scheduled('purescan_cleanup_old_results')) {
            wp_schedule_event(time(), 'weekly', 'purescan_cleanup_old_results');
        }

        // Clear any stale scan state
        delete_option(PURESCAN_STATE);

        // Set initial version
        update_option('purescan_version', PURESCAN_VERSION);

    }
}
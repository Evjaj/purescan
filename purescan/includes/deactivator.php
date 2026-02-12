<?php
/**
 * PureScan Deactivator
 * Handles plugin deactivation: removes scheduled events, preserves data.
 *
 * @package PureScan
 */

namespace PureScan;

if (!defined('ABSPATH')) {
    exit;
}

class Deactivator {

    /**
     * Execute on plugin deactivation.
     */
    public static function deactivate() {
        // Remove weekly cleanup cron
        $timestamp = wp_next_scheduled('purescan_cleanup_old_results');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'purescan_cleanup_old_results');
        }

        // Remove any active background scan hooks
        wp_clear_scheduled_hook('purescan_run_scan');

        // Do NOT delete settings or state — allow reactivation without loss
    }
}
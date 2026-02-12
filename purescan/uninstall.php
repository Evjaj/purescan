<?php
/**
 * PureScan Uninstall (Current Version)
 *
 * This file is automatically executed by WordPress when the plugin is deleted.
 * It removes all plugin data, options, transients, and cron jobs.
 * Neutralized files and automatic backups are LEFT UNTOUCHED for maximum user safety.
 *
 * @package PureScan
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// === Delete all current plugin options ===
delete_option('purescan_settings');
delete_option(PURESCAN_STATE);                    // Main scan state (defined as constant in code)
delete_option('purescan_version');
delete_option('purescan_last_scheduled_missed');
delete_option('purescan_bne_quarantined');        // List of neutralized files (current name)
delete_option('purescan_ignored_files');         // Ignored files list
delete_option('purescan_background_flag');
delete_option('purescan_single_scan_state');      // Single-file scan state (if used)

// === Clear all scheduled cron jobs ===
wp_clear_scheduled_hook('purescan_scheduled_scan');
wp_clear_scheduled_hook('purescan_cleanup_old_results');
wp_clear_scheduled_hook('purescan_cleanup_ai_queue');

// === Delete all related transients ===
delete_transient('purescan_engine_lock');
delete_transient('purescan_bg_lock');
delete_transient('purescan_file_list_temp');
delete_transient('purescan_local_hashes_cache');
delete_transient('purescan_welcome');             // Welcome notice transient
delete_transient('purescan_patterns_remote_failed');

/**
 * SECURITY BEST PRACTICE:
 *
 * - Neutralized files (with guard header) are NOT deleted
 * - Automatic backups in wp-content/purescan-backups/ are NOT deleted
 *
 * This allows the user to manually recover files if needed after plugin removal.
 * Automatically deleting user files would be dangerous and against WordPress guidelines.
 */
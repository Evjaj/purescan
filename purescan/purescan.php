<?php
/**
 * Plugin Name: PureScan
 * Plugin URI:  https://github.com/Evjaj/purescan
 * Description: Advanced real-time malware scanner with deep scan, live file search, AI-powered analysis, safe quarantine, and ignored files management.
 * Version:     1.2.25
 * Author:      PureScan Team
 * License:     GPL-2.0+
 * Text Domain: purescan
 * Domain Path: /languages
 * Requires PHP: 7.4
 * Requires at least: 5.6
 * Tested up to: 6.9
 */

if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('PURESCAN_VERSION', '1.2.25');
define('PURESCAN_BASENAME', plugin_basename(__FILE__));
define('PURESCAN_DIR', plugin_dir_path(__FILE__));
define('PURESCAN_URL', plugin_dir_url(__FILE__));
define('PURESCAN_NONCE', 'purescan_nonce_action');
define('PURESCAN_OPTION', 'purescan_settings');
define('PURESCAN_STATE', 'purescan_scan_state');


// === Autoloader (PSR-4 + Legacy Fallback) ===
spl_autoload_register(function ($class) {
    $prefix   = 'PureScan\\';
    $base_dir = PURESCAN_DIR . 'includes/';

    // Only handle PureScan namespace
    if (strncmp($prefix, $class, strlen($prefix)) !== 0) {
        return;
    }

    $relative_class = substr($class, strlen($prefix));
    $file           = '';

    // 1. PSR-4: PureScan\Scan\Scan_Ajax → includes/scan/class-scan-ajax.php
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) {
        require_once $file;
        return;
    }

    // 2. Legacy: class-scan-ajax.php style (lowercase, hyphenated)
    $parts = explode('\\', $relative_class);
    $class_name = array_pop($parts);
    $subdir = $parts ? strtolower(implode('/', $parts)) . '/' : '';
    $file = $base_dir . $subdir . 'class-' . strtolower(str_replace('_', '-', $class_name)) . '.php';

    if (file_exists($file)) {
        require_once $file;
        return;
    }

    // 3. Flat fallback (rare)
    $file = $base_dir . 'class-' . strtolower(str_replace(['\\', '_'], '-', $relative_class)) . '.php';
    if (file_exists($file)) {
        require_once $file;
    }
});

require_once PURESCAN_DIR . 'includes/core.php';

require_once PURESCAN_DIR . 'includes/activator.php';
require_once PURESCAN_DIR . 'includes/deactivator.php';

// Activation & Deactivation
register_activation_hook(__FILE__, ['PureScan\Activator', 'activate']);
register_deactivation_hook(__FILE__, ['PureScan\Deactivator', 'deactivate']);

// Uninstall
if (defined('WP_UNINSTALL_PLUGIN')) {
    require_once PURESCAN_DIR . 'uninstall.php';
}

// Initialize Core
add_action('plugins_loaded', function () {
    if (class_exists('PureScan\Core')) {
        new \PureScan\Core();
    }
});
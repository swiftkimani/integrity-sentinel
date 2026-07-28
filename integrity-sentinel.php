<?php
/**
 * Plugin Name:       Integrity Sentinel — Malware & File Scanner
 * Plugin URI:        https://example.com/integrity-sentinel
 * Description:       Finds what's already on your site: verifies WordPress core and plugin files against official WordPress.org checksums, scans every PHP file for known malware/webshell patterns, and flags PHP files hiding in uploads. Batched, resumable scans with a live progress bar, a findings dashboard, and email alerts.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Your Org
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       integrity-sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'IS_VERSION', '1.0.0' );
define( 'IS_PLUGIN_FILE', __FILE__ );
define( 'IS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'IS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'IS_CRON_DAILY_SCAN', 'is_daily_scan_cron' );
define( 'IS_CRON_RESUME_SCAN', 'is_resume_scan_cron' );
define( 'IS_DB_VERSION', '1' );

/**
 * Simple class autoloader, same rationale as the directory plugin: this
 * has zero third-party runtime dependencies (no Composer) so it installs
 * anywhere plain WordPress runs.
 */
spl_autoload_register(
	function ( $class ) {
		if ( strpos( $class, 'IS_' ) !== 0 ) {
			return;
		}
		$file = IS_PLUGIN_DIR . 'includes/class-is-' . strtolower( str_replace( '_', '-', substr( $class, 3 ) ) ) . '.php';
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
);

function is_init() {
	load_plugin_textdomain( 'integrity-sentinel', false, dirname( plugin_basename( IS_PLUGIN_FILE ) ) . '/languages' );

	IS_DB::instance();
	IS_Cron::instance();

	if ( is_admin() ) {
		IS_Admin::instance();
		IS_Ajax::instance();
	}
}
add_action( 'plugins_loaded', 'is_init' );

/**
 * Activation: create the findings/runs tables and schedule the daily
 * background scan. Table creation uses dbDelta() so re-activating after
 * an update safely applies schema changes.
 */
function is_activate() {
	IS_DB::instance()->create_tables();

	if ( ! wp_next_scheduled( IS_CRON_DAILY_SCAN ) ) {
		wp_schedule_event( time() + ( 2 * HOUR_IN_SECONDS ), 'daily', IS_CRON_DAILY_SCAN );
	}
	if ( ! get_option( 'is_scan_settings' ) ) {
		update_option(
			'is_scan_settings',
			array(
				'batch_size'          => 40,
				'alert_email'         => get_option( 'admin_email' ),
				'alert_on_severity'   => 'high', // critical, high, medium, low
				'scan_uploads_for_php' => 1,
				'max_file_size_kb'    => 2048, // skip pattern-scanning (not hashing) files bigger than this
				'excluded_paths'      => "wp-content/cache\nwp-content/uploads/backup*\nwp-content/ai1wm-backups",
			),
			false
		);
	}
}
register_activation_hook( IS_PLUGIN_FILE, 'is_activate' );

function is_deactivate() {
	foreach ( array( IS_CRON_DAILY_SCAN, IS_CRON_RESUME_SCAN ) as $hook ) {
		$timestamp = wp_next_scheduled( $hook );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, $hook );
		}
	}
}
register_deactivation_hook( IS_PLUGIN_FILE, 'is_deactivate' );

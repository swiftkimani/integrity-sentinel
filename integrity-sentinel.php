<?php
/**
 * Plugin Name:       Integrity Sentinel — Malware Scanner & Hardening Suite
 * Plugin URI:        https://example.com/integrity-sentinel
 * Description:       File-integrity scanning (core/plugin checksums, malware/webshell patterns, obfuscation detection) plus a full hardening suite: access control, login/2FA protection, HTTP/REST hardening, hotlink and AI-bot blocking, and a human-in-the-loop quarantine engine. Batched, resumable scans, a findings dashboard, email alerts, and a WP-CLI command.
 * Version:           1.24.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Your Org
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       integrity-sentinel
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'IS_VERSION', '1.24.0' );
define( 'IS_PLUGIN_FILE', __FILE__ );
define( 'IS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'IS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'IS_CRON_DAILY_SCAN', 'is_daily_scan_cron' );
define( 'IS_CRON_RESUME_SCAN', 'is_resume_scan_cron' );
define( 'IS_DB_VERSION', '4' );

/**
 * Simple class autoloader, same rationale as the directory plugin: this
 * has zero third-party runtime dependencies (no Composer) so it installs
 * anywhere plain WordPress runs.
 */
spl_autoload_register(
	function ( $class_name ) {
		if ( strpos( $class_name, 'IS_' ) !== 0 ) {
			return;
		}
		$file = IS_PLUGIN_DIR . 'includes/class-is-' . strtolower( str_replace( '_', '-', substr( $class_name, 3 ) ) ) . '.php';
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
);

/**
 * Boots every module on 'plugins_loaded': loads the text domain, then
 * (main site only, on multisite) instantiates the DB, cron, and every
 * detection/hardening class, plus the admin UI and AJAX handlers when
 * in wp-admin.
 */
function is_init() {
	load_plugin_textdomain( 'integrity-sentinel', false, dirname( plugin_basename( IS_PLUGIN_FILE ) ) . '/languages' );

	// On multisite the filesystem is shared across every subsite, so
	// running the scanner (and its crons) once, from the main site, is
	// both sufficient and necessary -- per-subsite copies would all scan
	// the same tree and multiply cron load for zero extra coverage.
	if ( is_multisite() && ! is_main_site() ) {
		return;
	}

	IS_DB::instance();
	IS_Cron::instance();
	IS_Update_Monitor::instance();
	IS_Headers::instance();
	IS_IP_List::instance();
	IS_Login::instance();
	IS_Login_Design::instance();
	IS_Upload_Guard::instance();
	IS_Bot_Block::instance();
	IS_Rest_API::instance();
	IS_Rest_Posts::instance();
	IS_2FA::instance();
	IS_Sessions::instance();
	IS_Asset_Cloak::instance();
	IS_Password_Policy::instance();
	IS_Deception::instance();
	IS_Custom_Detections::instance();

	if ( is_admin() ) {
		IS_Admin::instance();
		IS_Ajax::instance();
	}
}
add_action( 'plugins_loaded', 'is_init' );

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'integrity-sentinel', 'IS_CLI' );
}

/**
 * Activation: create the findings/runs tables and schedule the daily
 * background scan. Table creation uses dbDelta() so re-activating after
 * an update safely applies schema changes.
 */
function is_activate() {
	if ( is_multisite() && ! is_main_site() ) {
		return;
	}

	IS_DB::instance()->create_tables();

	if ( ! wp_next_scheduled( IS_CRON_DAILY_SCAN ) ) {
		IS_Cron::reschedule_scan( 'daily' );
	}
	if ( ! get_option( 'is_scan_settings' ) ) {
		update_option(
			'is_scan_settings',
			array(
				'batch_size'           => 40,
				'alert_email'          => get_option( 'admin_email' ),
				'alert_on_severity'    => 'high', // critical, high, medium, low.
				'scan_uploads_for_php' => 1,
				'max_file_size_kb'     => 2048, // skip pattern-scanning (not hashing) files bigger than this.
				'excluded_paths'       => "wp-content/cache\nwp-content/uploads/backup*\nwp-content/ai1wm-backups",
				'webhook_url'          => '',
				'deadman_days'         => 2,
				'scan_frequency'       => 'daily', // hourly, twicedaily, daily, weekly.
			),
			false
		);
	}
}
register_activation_hook( IS_PLUGIN_FILE, 'is_activate' );

/**
 * Deactivation raises an alarm on purpose: disabling the security
 * plugin is step one of most real intrusions, so the alert address
 * hears about it immediately, with who and from where. A legitimate
 * admin doing maintenance can ignore one email; a site owner whose
 * scanner was silently switched off cannot ignore what they never saw.
 */
function is_deactivate() {
	if ( is_multisite() && ! is_main_site() ) {
		return;
	}

	foreach ( array( IS_CRON_DAILY_SCAN, IS_CRON_RESUME_SCAN ) as $hook ) {
		$timestamp = wp_next_scheduled( $hook );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, $hook );
		}
	}

	$user = wp_get_current_user();
	IS_Audit_Log::record( 'plugin_deactivated', array() );
	IS_Notifications::instance()->send_event(
		'plugin_deactivated',
		__( 'Integrity Sentinel was DEACTIVATED', 'integrity-sentinel' ),
		array(
			sprintf(
				/* translators: 1: user login, 2: IP address */
				__( 'Integrity Sentinel was deactivated by user "%1$s" from IP %2$s.', 'integrity-sentinel' ),
				$user && $user->ID ? $user->user_login : __( '(unknown)', 'integrity-sentinel' ),
				IS_Audit_Log::request_ip()
			),
			__( 'If this was not you, treat it as a possible intrusion: attackers commonly disable security plugins first.', 'integrity-sentinel' ),
		)
	);
}
register_deactivation_hook( IS_PLUGIN_FILE, 'is_deactivate' );

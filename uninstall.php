<?php
/**
 * Fires only on "Delete" from the Plugins screen. Drops the plugin's two
 * custom tables and removes its options/cron -- a security scanner's
 * findings history shouldn't linger in the database after the site
 * owner has deliberately removed it.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}is_findings" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}is_scan_runs" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}is_audit_log" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange

delete_option( 'is_scan_settings' );
delete_option( 'is_db_version' );
delete_option( 'is_deadman_last_alert' );
delete_option( 'is_known_admin_ids' );

foreach ( array( 'is_daily_scan_cron', 'is_resume_scan_cron' ) as $hook ) {
	$timestamp = wp_next_scheduled( $hook );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, $hook );
	}
}

// Clear cached checksum transients and any leftover scan-lock options
// we can identify by prefix.
global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_is_core_checksums_%' OR option_name LIKE '_transient_timeout_is_core_checksums_%' OR option_name LIKE '_transient_is_plugin_checksums_%' OR option_name LIKE '_transient_timeout_is_plugin_checksums_%' OR option_name LIKE '_transient_is_plugin_info_%' OR option_name LIKE '_transient_timeout_is_plugin_info_%' OR option_name LIKE 'is_scan_lock_%'" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery

<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Append-only audit trail of every security-relevant action: scans
 * started/completed, finding status changes, settings changes, plugin
 * deactivation, hardening actions. Deliberately exposes NO update or
 * delete methods -- rows only ever get added. (An attacker with raw
 * database access can still delete rows, of course; the value here is
 * that nothing done through WordPress -- a compromised admin session,
 * a rogue plugin calling our AJAX endpoints -- can act without trace.)
 */
class IS_Audit_Log {

	/**
	 * @param string $action Short machine-readable action slug.
	 * @param array  $detail Context stored as JSON (keep it small).
	 */
	public static function record( $action, array $detail = array() ) {
		global $wpdb;

		$user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;

		$wpdb->insert(
			IS_DB::instance()->audit_table(),
			array(
				'created_at' => current_time( 'mysql' ),
				'user_id'    => ( $user && $user->ID ) ? (int) $user->ID : 0,
				'user_login' => ( $user && $user->ID ) ? $user->user_login : 'system',
				'ip'         => self::request_ip(),
				'action'     => $action,
				'detail'     => wp_json_encode( $detail ),
			),
			array( '%s', '%d', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * REMOTE_ADDR only, on purpose: X-Forwarded-For and friends are
	 * client-controlled and would let an attacker forge the audit trail
	 * they're being recorded into.
	 */
	public static function request_ip() {
		if ( empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return '';
		}
		$ip = filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ), FILTER_VALIDATE_IP ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- FILTER_VALIDATE_IP is the sanitization
		return $ip ? $ip : '';
	}

	public static function entries( $limit = 50, $offset = 0 ) {
		global $wpdb;
		$table = IS_DB::instance()->audit_table();
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				max( 1, (int) $limit ),
				max( 0, (int) $offset )
			),
			ARRAY_A
		);
	}

	/** Same as entries(), filtered to one exact action slug -- used for small "recent triggers" lists (e.g. deception detections). */
	public static function entries_for_action( $action, $limit = 20 ) {
		global $wpdb;
		$table = IS_DB::instance()->audit_table();
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE action = %s ORDER BY id DESC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$action,
				max( 1, (int) $limit )
			),
			ARRAY_A
		);
	}

	public static function count() {
		global $wpdb;
		$table = IS_DB::instance()->audit_table();
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}
}

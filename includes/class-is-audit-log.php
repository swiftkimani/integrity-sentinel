<?php
/**
 * Append-only audit trail for Integrity Sentinel.
 *
 * @package Integrity_Sentinel
 */

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
	 * Default settings for this module.
	 */
	public static function default_settings() {
		return array( 'retention_days' => 0 ); // 0 = keep forever, matching this plugin's off-by-default posture for anything that changes existing behavior.
	}

	/**
	 * Current settings, merged over the defaults.
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_audit_log_settings', array() ), self::default_settings() );
	}

	/**
	 * Prunes rows older than the configured retention window, if one is
	 * set. Safe to call unconditionally (e.g. from a cron tick) --
	 * a no-op when retention_days is 0.
	 *
	 * @return int Number of rows deleted.
	 */
	public static function maybe_prune() {
		$days = (int) self::settings()['retention_days'];
		if ( $days <= 0 ) {
			return 0;
		}
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
		return self::prune( $cutoff );
	}

	/**
	 * Records one audit-log row.
	 *
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

	/**
	 * Most recent audit-log rows, newest first.
	 *
	 * @param int $limit  Maximum rows to return.
	 * @param int $offset Rows to skip, for pagination.
	 */
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

	/**
	 * Same as entries(), filtered to one exact action slug -- used for small "recent triggers" lists (e.g. deception detections).
	 *
	 * @param string $action Exact action slug to filter on.
	 * @param int    $limit  Maximum rows to return.
	 */
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

	/**
	 * Every audit-log row within a time window, regardless of action --
	 * used to pull "what else happened around the same time as this
	 * finding" for an incident bundle export.
	 *
	 * @param string $start_mysql Inclusive lower bound.
	 * @param string $end_mysql   Inclusive upper bound.
	 * @param int    $limit       Maximum rows to return.
	 */
	public static function entries_between( $start_mysql, $end_mysql, $limit = 100 ) {
		global $wpdb;
		$table = IS_DB::instance()->audit_table();
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE created_at BETWEEN %s AND %s ORDER BY id ASC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$start_mysql,
				$end_mysql,
				max( 1, (int) $limit )
			),
			ARRAY_A
		);
	}

	/**
	 * Same as count(), matching one exact action slug.
	 *
	 * @param string $action_like SQL LIKE pattern (already escaped/prepared -- pass a plain substring; wildcards are added here).
	 * @param string $since_mysql Only count rows at or after this MySQL datetime.
	 */
	public static function count_matching( $action_like, $since_mysql ) {
		global $wpdb;
		$table = IS_DB::instance()->audit_table();
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE action LIKE %s AND created_at >= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				'%' . $wpdb->esc_like( $action_like ) . '%',
				$since_mysql
			)
		);
	}

	/**
	 * Total number of audit-log rows.
	 */
	public static function count() {
		global $wpdb;
		$table = IS_DB::instance()->audit_table();
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/**
	 * The one deliberate exception to "append-only": a site-owner-
	 * configured retention policy (off by default, see
	 * is_audit_log_settings['retention_days']), not a general delete
	 * capability -- this only ever bulk-removes rows older than a
	 * cutoff the admin explicitly chose, never a single row by ID.
	 *
	 * @param string $cutoff_mysql Rows with created_at strictly before this MySQL datetime are removed.
	 * @return int Number of rows deleted.
	 */
	public static function prune( $cutoff_mysql ) {
		global $wpdb;
		$table = IS_DB::instance()->audit_table();
		return (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$cutoff_mysql
			)
		);
	}
}

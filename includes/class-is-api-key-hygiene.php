<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Surfaces staleness of WordPress core's own Application Passwords
 * (Users -> Profile -> Application Passwords, available since WP 5.6) --
 * no new credential storage of any kind here, just a site-wide read-only
 * view of metadata core already tracks per password (created, last_used,
 * last_ip) that otherwise has no single-page overview anywhere in stock
 * WordPress. A credential nobody has used in months is exactly the kind
 * of thing worth revoking before it becomes someone else's way in.
 */
class IS_Api_Key_Hygiene {

	public static function default_settings() {
		return array( 'stale_after_days' => 90 );
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_api_key_hygiene_settings', array() ), self::default_settings() );
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: is this application password stale? Judged against its
	 * last-used time if it has ever been used, otherwise against its
	 * creation time (a password created long ago and never once used is
	 * exactly as much of a dangling credential as one that went idle).
	 *
	 * @param array{created?:int,last_used?:int} $app_password
	 */
	public static function is_stale( array $app_password, $now, $stale_after_days ) {
		$last_used = isset( $app_password['last_used'] ) ? (int) $app_password['last_used'] : 0;
		$reference = $last_used > 0 ? $last_used : ( isset( $app_password['created'] ) ? (int) $app_password['created'] : 0 );
		if ( 0 === $reference ) {
			return false; // nothing to compare against
		}
		return ( $now - $reference ) > ( max( 1, (int) $stale_after_days ) * DAY_IN_SECONDS );
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * @return array<array{user_id:int,user_login:string,name:string,uuid:string,created:int,last_used:int,last_ip:string,is_stale:bool}>
	 */
	public static function list_all() {
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return array();
		}

		$settings = self::settings();
		$now      = time();
		$out      = array();

		foreach ( get_users( array( 'fields' => array( 'ID', 'user_login' ) ) ) as $user ) {
			foreach ( WP_Application_Passwords::get_user_application_passwords( $user->ID ) as $app_password ) {
				$out[] = array(
					'user_id'    => (int) $user->ID,
					'user_login' => $user->user_login,
					'name'       => isset( $app_password['name'] ) ? (string) $app_password['name'] : '',
					'uuid'       => isset( $app_password['uuid'] ) ? (string) $app_password['uuid'] : '',
					'created'    => isset( $app_password['created'] ) ? (int) $app_password['created'] : 0,
					'last_used'  => isset( $app_password['last_used'] ) ? (int) $app_password['last_used'] : 0,
					'last_ip'    => isset( $app_password['last_ip'] ) ? (string) $app_password['last_ip'] : '',
					'is_stale'   => self::is_stale( $app_password, $now, $settings['stale_after_days'] ),
				);
			}
		}

		return $out;
	}
}

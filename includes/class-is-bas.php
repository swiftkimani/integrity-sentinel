<?php
/**
 * Breach & Attack Simulation (BAS): an admin-triggered self-test that
 * verifies this plugin's own defensive controls actually behave
 * correctly against synthetic adversarial input.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The "offense" half of this plugin's threat model, scoped safely for a
 * tool that gets installed on arbitrary third-party sites: this makes
 * ZERO live HTTP requests, targets nothing external or configurable,
 * and never mutates any real user's data. Every check either calls an
 * existing pure function with synthetic adversarial input and asserts
 * the expected verdict, or (2FA) round-trips a value it generated
 * itself in the same request and immediately discards. This is
 * logic-level verification -- "does the code that's supposed to catch
 * this actually catch it, and is the control even turned on" -- not a
 * live-traffic replay, and is labeled as such everywhere it's shown.
 */
class IS_BAS {

	/**
	 * Runs every self-test and returns the results in a fixed, stable order.
	 *
	 * @return array<array{key:string,label:string,control_enabled:bool,passed:bool,detail:string}>
	 */
	public static function run_checks() {
		return array(
			self::check_rest_rate_limiting(),
			self::check_rest_enumeration_detection(),
			self::check_credential_stuffing(),
			self::check_honeypot_recognition(),
			self::check_ip_temp_ban(),
			self::check_impossible_travel(),
			self::check_totp_round_trip(),
			self::check_password_policy(),
			self::check_signature_matching(),
		);
	}

	/**
	 * Assembles one self-test's result row.
	 *
	 * @param string $key             Stable identifier for the check.
	 * @param string $label           Human-readable name shown in the admin UI.
	 * @param bool   $control_enabled Whether the underlying control is currently turned on.
	 * @param bool   $passed          Whether the synthetic verification passed.
	 * @param string $detail          Human-readable explanation of the result.
	 */
	private static function result( $key, $label, $control_enabled, $passed, $detail ) {
		return array(
			'key'             => $key,
			'label'           => $label,
			'control_enabled' => $control_enabled,
			'passed'          => $passed,
			'detail'          => $detail,
		);
	}

	/**
	 * Verifies that a synthetic burst at the configured REST rate limit is correctly identified as over-limit.
	 */
	private static function check_rest_rate_limiting() {
		$settings = IS_Rest_API::settings();
		$limit    = max( 1, (int) $settings['rate_limit'] );
		// Synthetic record already at the limit -- the next hit must be blocked.
		$record = array(
			'window_started_at' => time(),
			'count'             => $limit,
		);
		$passed = IS_Rate_Limiter::is_limited( $record, time(), $limit, 300 );
		return self::result(
			'rest_rate_limiting',
			__( 'REST API rate limiting', 'integrity-sentinel' ),
			! empty( $settings['rate_limit'] ),
			$passed,
			$passed
				? __( 'A synthetic burst at the configured limit was correctly identified as over-limit.', 'integrity-sentinel' )
				: __( 'A synthetic burst at the configured limit was NOT flagged as over-limit.', 'integrity-sentinel' )
		);
	}

	/**
	 * Verifies that a synthetic sequential-ID REST route is correctly recognized as an enumeration pattern.
	 */
	private static function check_rest_enumeration_detection() {
		$settings = IS_Rest_API::settings();
		$match    = IS_Rest_API::numeric_id_route_match( '/wp/v2/posts/12345' );
		$no_match = IS_Rest_API::numeric_id_route_match( '/wp/v2/posts/not-a-number' );
		$passed   = ( null !== $match && 'posts' === $match['type'] && 12345 === $match['id'] ) && null === $no_match;
		return self::result(
			'rest_enumeration_detection',
			__( 'REST API enumeration detection', 'integrity-sentinel' ),
			! empty( $settings['enumeration_detection'] ),
			$passed,
			$passed
				? __( 'A synthetic sequential-ID request was correctly recognized as an enumeration pattern.', 'integrity-sentinel' )
				: __( 'A synthetic sequential-ID request was NOT recognized correctly.', 'integrity-sentinel' )
		);
	}

	/**
	 * Verifies that a synthetic set of distinct usernames at the configured threshold is correctly flagged as credential stuffing.
	 */
	private static function check_credential_stuffing() {
		$settings  = IS_Login::throttle_settings();
		$threshold = max( 2, (int) $settings['credential_stuffing_threshold'] );
		$record    = IS_Login::default_username_record();
		for ( $i = 0; $i < $threshold; $i++ ) {
			$record = IS_Login::record_username_attempt( $record, 'synthetic-user-' . $i );
		}
		$passed = IS_Login::is_credential_stuffing( $record, $threshold );
		return self::result(
			'credential_stuffing',
			__( 'Credential-stuffing detection', 'integrity-sentinel' ),
			! empty( $settings['enabled'] ),
			$passed,
			$passed
				? __( 'A synthetic set of distinct usernames at the configured threshold was correctly flagged.', 'integrity-sentinel' )
				: __( 'A synthetic set of distinct usernames at the configured threshold was NOT flagged.', 'integrity-sentinel' )
		);
	}

	/**
	 * Verifies that every configured honeypot path is recognized, and an ordinary path is not.
	 */
	private static function check_honeypot_recognition() {
		$settings  = IS_Deception::settings();
		$all_match = true;
		foreach ( IS_Deception::honeypot_paths() as $path ) {
			if ( ! IS_Deception::is_honeypot_path( $path ) ) {
				$all_match = false;
				break;
			}
		}
		$no_false_positive = ! IS_Deception::is_honeypot_path( '/about' );
		$passed            = $all_match && $no_false_positive;
		return self::result(
			'honeypot_recognition',
			__( 'Honeypot path recognition', 'integrity-sentinel' ),
			! empty( $settings['enabled'] ),
			$passed,
			$passed
				? __( 'Every configured honeypot path is correctly recognized, and an ordinary path is correctly ignored.', 'integrity-sentinel' )
				: __( 'Honeypot path recognition did not behave as expected.', 'integrity-sentinel' )
		);
	}

	/**
	 * Verifies that a synthetic active ban is recognized as active, and a synthetic expired ban is not.
	 */
	private static function check_ip_temp_ban() {
		$now         = time();
		$active_ban  = array(
			'banned_until' => $now + 3600,
			'reason'       => 'bas_self_test',
		);
		$expired_ban = array(
			'banned_until' => $now - 3600,
			'reason'       => 'bas_self_test',
		);
		$passed      = IS_IP_List::is_ban_active( $active_ban, $now ) && ! IS_IP_List::is_ban_active( $expired_ban, $now );
		return self::result(
			'ip_temp_ban',
			__( 'Temporary IP ban logic', 'integrity-sentinel' ),
			true, // this is core logic with no on/off switch of its own -- always "enabled".
			$passed,
			$passed
				? __( 'A synthetic active ban was correctly recognized as active, and a synthetic expired ban as inactive.', 'integrity-sentinel' )
				: __( 'Temporary-ban expiry logic did not behave as expected.', 'integrity-sentinel' )
		);
	}

	/**
	 * Verifies that a synthetic rapid login from a different network is flagged as impossible travel.
	 */
	private static function check_impossible_travel() {
		$settings = IS_Sessions::settings();
		$now      = time();
		$previous = array(
			'ip'   => '203.0.113.9', // TEST-NET-3 (RFC 5737), never a real routable address.
			'time' => $now - ( 5 * MINUTE_IN_SECONDS ),
		);
		$passed   = IS_Sessions::is_impossible_travel( $previous, '198.51.100.1', $now, (int) $settings['impossible_travel_window_minutes'] * MINUTE_IN_SECONDS );
		return self::result(
			'impossible_travel',
			__( 'Impossible-travel session detection', 'integrity-sentinel' ),
			! empty( $settings['impossible_travel_detection'] ),
			$passed,
			$passed
				? __( 'A synthetic rapid login from a different network was correctly flagged.', 'integrity-sentinel' )
				: __( 'A synthetic rapid login from a different network was NOT flagged.', 'integrity-sentinel' )
		);
	}

	/**
	 * Generates a throwaway secret and code in memory, verifies the
	 * round-trip, and discards both -- never touches any real user's
	 * stored 2FA secret.
	 */
	private static function check_totp_round_trip() {
		$settings = IS_2FA::settings();
		$secret   = IS_TOTP::generate_secret();
		$now      = time();
		$code     = IS_TOTP::totp_at_time( $secret, $now );

		$accepts_correct = IS_TOTP::verify( $secret, $code, $now );
		$rejects_wrong   = ! IS_TOTP::verify( $secret, '000000', $now );
		$passed          = $accepts_correct && $rejects_wrong;

		return self::result(
			'totp_round_trip',
			__( 'Two-factor authentication (TOTP)', 'integrity-sentinel' ),
			! empty( $settings['enforced_roles'] ),
			$passed,
			$passed
				? __( 'A freshly generated, throwaway TOTP secret correctly accepted its own code and rejected an all-zeros code.', 'integrity-sentinel' )
				: __( 'The TOTP round-trip did not behave as expected.', 'integrity-sentinel' )
		);
	}

	/**
	 * Verifies that a known-weak password is flagged and a known-strong one is accepted.
	 */
	private static function check_password_policy() {
		$settings = IS_Password_Policy::settings();
		$weak     = IS_Password_Policy::password_issues( 'password', $settings );
		$strong   = IS_Password_Policy::password_issues( 'Tr0ub4dor&3xtra-Long!Passphrase', $settings );
		$passed   = ! empty( $weak ) && empty( $strong );
		return self::result(
			'password_policy',
			__( 'Password strength policy', 'integrity-sentinel' ),
			! empty( $settings['enabled'] ),
			$passed,
			$passed
				? __( 'A known-weak password was correctly flagged, and a known-strong one was correctly accepted.', 'integrity-sentinel' )
				: __( 'Password strength evaluation did not behave as expected.', 'integrity-sentinel' )
		);
	}

	/**
	 * Uses a temporary, in-memory known-hash map -- not the admin's
	 * real configured signature list -- so this verifies the matching
	 * MECHANISM, never touching or depending on real data.
	 */
	private static function check_signature_matching() {
		$settings       = IS_Signatures::settings();
		$synthetic_hash = hash( 'sha256', 'is-bas-self-test-' . wp_generate_password( 12, false ) );
		$known          = array( $synthetic_hash => 'bas-self-test' );

		$matches_known   = null !== IS_Signatures::match_hash( $synthetic_hash, $known );
		$ignores_unknown = null === IS_Signatures::match_hash( hash( 'sha256', 'something-else' ), $known );
		$passed          = $matches_known && $ignores_unknown;

		return self::result(
			'signature_matching',
			__( 'Exact-hash signature matching', 'integrity-sentinel' ),
			! empty( $settings['enabled'] ),
			$passed,
			$passed
				? __( 'A synthetic known-bad hash was correctly matched, and an unrelated hash was correctly ignored -- your real signature list was never read.', 'integrity-sentinel' )
				: __( 'Signature matching did not behave as expected.', 'integrity-sentinel' )
		);
	}
}

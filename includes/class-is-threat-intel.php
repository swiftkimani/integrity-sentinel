<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Opt-in, on-demand reputation lookups against external threat-intel
 * services -- AbuseIPDB for IP addresses, VirusTotal for file hashes.
 * Same template as IS_Vulnerability_Scanner's WPScan integration:
 * per-service API key, transient caching, a per-run request cap, and
 * distinct WP_Error codes for auth/quota/HTTP failures so a caller can
 * tell "not configured" from "temporarily unavailable, try again".
 *
 * Deliberately NOT wired into any live request path (login attempts,
 * REST requests): those already respond in well under a second, and an
 * external HTTP round-trip (even a fast one) has no business blocking
 * them. Lookups only ever happen on an admin's own explicit action --
 * see IS_Admin's "check reputation" handlers -- where a page load
 * taking an extra second is an acceptable, expected cost.
 */
class IS_Threat_Intel {

	const CACHE_TTL            = DAY_IN_SECONDS;
	const MAX_REQUESTS_PER_RUN = 20;

	public static function default_settings() {
		return array(
			'enabled'        => 0,
			'abuseipdb_key'  => '',
			'virustotal_key' => '',
		);
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_threat_intel_settings', array() ), self::default_settings() );
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/** Pure: AbuseIPDB's 0-100 confidence score, banded to our severity scale. */
	public static function severity_for_abuse_score( $score ) {
		$score = (int) $score;
		if ( $score >= 75 ) {
			return 'critical';
		}
		if ( $score >= 40 ) {
			return 'high';
		}
		if ( $score >= 10 ) {
			return 'medium';
		}
		return 'low';
	}

	/**
	 * Pure: extracts the fields we care about from AbuseIPDB's /check
	 * response body.
	 *
	 * @return array{score:int,severity:string,total_reports:int,country:string}|null
	 */
	public static function parse_ip_report( $body ) {
		$data = ( is_array( $body ) && isset( $body['data'] ) && is_array( $body['data'] ) ) ? $body['data'] : array();
		if ( empty( $data ) ) {
			return null;
		}
		$score = isset( $data['abuseConfidenceScore'] ) ? (int) $data['abuseConfidenceScore'] : 0;
		return array(
			'score'         => $score,
			'severity'      => self::severity_for_abuse_score( $score ),
			'total_reports' => isset( $data['totalReports'] ) ? (int) $data['totalReports'] : 0,
			'country'       => isset( $data['countryCode'] ) ? (string) $data['countryCode'] : '',
		);
	}

	/**
	 * Pure: extracts the fields we care about from VirusTotal's file
	 * report body.
	 *
	 * @return array{malicious:int,suspicious:int,severity:string}|null
	 */
	public static function parse_hash_report( $body ) {
		$attrs = ( is_array( $body ) && isset( $body['data']['attributes'] ) && is_array( $body['data']['attributes'] ) ) ? $body['data']['attributes'] : array();
		if ( empty( $attrs ) ) {
			return null;
		}
		$stats      = ( isset( $attrs['last_analysis_stats'] ) && is_array( $attrs['last_analysis_stats'] ) ) ? $attrs['last_analysis_stats'] : array();
		$malicious  = isset( $stats['malicious'] ) ? (int) $stats['malicious'] : 0;
		$suspicious = isset( $stats['suspicious'] ) ? (int) $stats['suspicious'] : 0;
		return array(
			'malicious'  => $malicious,
			'suspicious' => $suspicious,
			'severity'   => $malicious > 0 ? 'critical' : ( $suspicious > 0 ? 'medium' : 'low' ),
		);
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	private static function consume_request_budget() {
		$count = (int) get_transient( 'is_ti_request_count' );
		if ( $count >= self::MAX_REQUESTS_PER_RUN ) {
			return false;
		}
		set_transient( 'is_ti_request_count', $count + 1, HOUR_IN_SECONDS );
		return true;
	}

	/** @return array|WP_Error */
	public function lookup_ip( $ip ) {
		$settings = self::settings();
		if ( empty( $settings['enabled'] ) || '' === trim( (string) $settings['abuseipdb_key'] ) ) {
			return new WP_Error( 'is_threat_intel_disabled', __( 'Threat intelligence is not enabled, or no AbuseIPDB API key is configured.', 'integrity-sentinel' ) );
		}

		$cache_key = 'is_ti_ip_' . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		if ( ! self::consume_request_budget() ) {
			return new WP_Error( 'is_threat_intel_quota', __( 'Threat intelligence request quota reached — try again shortly.', 'integrity-sentinel' ) );
		}

		$response = wp_remote_get(
			add_query_arg(
				array(
					'ipAddress'    => $ip,
					'maxAgeInDays' => 90,
				),
				'https://api.abuseipdb.com/api/v2/check'
			),
			array(
				'timeout' => 10,
				'headers' => array(
					'Key'    => $settings['abuseipdb_key'],
					'Accept' => 'application/json',
				),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 401 === $code || 403 === $code ) {
			return new WP_Error( 'is_threat_intel_auth', __( 'AbuseIPDB API key was rejected.', 'integrity-sentinel' ) );
		}
		if ( 429 === $code ) {
			return new WP_Error( 'is_threat_intel_rate_limited', __( 'AbuseIPDB daily request limit reached.', 'integrity-sentinel' ) );
		}
		if ( 200 !== $code ) {
			return new WP_Error(
				'is_threat_intel_http',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'AbuseIPDB lookup returned HTTP %d.', 'integrity-sentinel' ),
					$code
				)
			);
		}

		$result = self::parse_ip_report( json_decode( wp_remote_retrieve_body( $response ), true ) );
		if ( null === $result ) {
			return new WP_Error( 'is_threat_intel_empty', __( 'AbuseIPDB returned no data for this IP.', 'integrity-sentinel' ) );
		}
		set_transient( $cache_key, $result, self::CACHE_TTL );
		return $result;
	}

	/** @return array|WP_Error */
	public function lookup_hash( $sha256 ) {
		$settings = self::settings();
		if ( empty( $settings['enabled'] ) || '' === trim( (string) $settings['virustotal_key'] ) ) {
			return new WP_Error( 'is_threat_intel_disabled', __( 'Threat intelligence is not enabled, or no VirusTotal API key is configured.', 'integrity-sentinel' ) );
		}

		$sha256    = strtolower( trim( (string) $sha256 ) );
		$cache_key = 'is_ti_hash_' . md5( $sha256 );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		if ( ! self::consume_request_budget() ) {
			return new WP_Error( 'is_threat_intel_quota', __( 'Threat intelligence request quota reached — try again shortly.', 'integrity-sentinel' ) );
		}

		$response = wp_remote_get(
			'https://www.virustotal.com/api/v3/files/' . rawurlencode( $sha256 ),
			array(
				'timeout' => 10,
				'headers' => array( 'x-apikey' => $settings['virustotal_key'] ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 401 === $code || 403 === $code ) {
			return new WP_Error( 'is_threat_intel_auth', __( 'VirusTotal API key was rejected.', 'integrity-sentinel' ) );
		}
		if ( 429 === $code ) {
			return new WP_Error( 'is_threat_intel_rate_limited', __( 'VirusTotal request limit reached.', 'integrity-sentinel' ) );
		}
		if ( 404 === $code ) {
			$result = array(
				'malicious'  => 0,
				'suspicious' => 0,
				'severity'   => 'low',
				'unknown'    => true,
			);
			set_transient( $cache_key, $result, self::CACHE_TTL );
			return $result;
		}
		if ( 200 !== $code ) {
			return new WP_Error(
				'is_threat_intel_http',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'VirusTotal lookup returned HTTP %d.', 'integrity-sentinel' ),
					$code
				)
			);
		}

		$result = self::parse_hash_report( json_decode( wp_remote_retrieve_body( $response ), true ) );
		if ( null === $result ) {
			return new WP_Error( 'is_threat_intel_empty', __( 'VirusTotal returned no data for this hash.', 'integrity-sentinel' ) );
		}
		set_transient( $cache_key, $result, self::CACHE_TTL );
		return $result;
	}
}

<?php
/**
 * Read-only TLS certificate expiry check for the site's own domain, via a
 * direct outbound TLS handshake -- no third-party service, no key.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Checks the certificate the site's own HTTPS endpoint presents, and how
 * many days remain before it expires -- a lapsed certificate is a routine,
 * entirely avoidable outage, but nothing else in this plugin watches for
 * it. Deliberately does NOT attempt to grade TLS protocol version or
 * cipher suite strength: negotiating a specific protocol/cipher from
 * plain PHP streams is unreliable across hosting environments and would
 * risk false "weak TLS" findings on a server that's actually fine --
 * expiry is the one thing that can be checked with full confidence.
 */
class IS_TLS_Check {

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: whole days between now and a certificate's expiry timestamp (negative if already expired).
	 *
	 * @param int $valid_to_unix Certificate's validTo_time_t.
	 * @param int $now           Current unix timestamp.
	 */
	public static function days_until_expiry( $valid_to_unix, $now ) {
		return (int) floor( ( (int) $valid_to_unix - (int) $now ) / DAY_IN_SECONDS );
	}

	/**
	 * Pure: severity band for days remaining until expiry.
	 *
	 * @param int $days_remaining Days remaining until certificate expiry (negative if already expired).
	 */
	public static function expiry_severity( $days_remaining ) {
		if ( $days_remaining < 0 ) {
			return 'critical';
		}
		if ( $days_remaining < 7 ) {
			return 'critical';
		}
		if ( $days_remaining < 30 ) {
			return 'high';
		}
		if ( $days_remaining < 90 ) {
			return 'medium';
		}
		return 'low';
	}

	/**
	 * Pure: parses the array shape returned by openssl_x509_parse() into
	 * just what this check needs.
	 *
	 * @param array $parsed openssl_x509_parse() output.
	 * @return array{valid_to:int,issuer:string,subject:string}
	 */
	public static function summarize_cert( array $parsed ) {
		return array(
			'valid_to' => isset( $parsed['validTo_time_t'] ) ? (int) $parsed['validTo_time_t'] : 0,
			'issuer'   => isset( $parsed['issuer']['CN'] ) ? (string) $parsed['issuer']['CN'] : '',
			'subject'  => isset( $parsed['subject']['CN'] ) ? (string) $parsed['subject']['CN'] : '',
		);
	}

	// -----------------------------------------------------------------
	// WP/PHP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * Opens a direct TLS connection to $host:443, captures the presented
	 * certificate, and reports how many days remain before it expires.
	 *
	 * @param string $host Hostname to check (no scheme, no port).
	 * @return array{host:string,ok:bool,valid_to:int,days_remaining:int,severity:string,issuer:string,error:string}
	 */
	public static function check_certificate( $host ) {
		$host   = trim( (string) $host );
		$result = array(
			'host'           => $host,
			'ok'             => false,
			'valid_to'       => 0,
			'days_remaining' => 0,
			'severity'       => '',
			'issuer'         => '',
			'error'          => '',
		);
		if ( '' === $host ) {
			$result['error'] = __( 'No hostname to check.', 'integrity-sentinel' );
			return $result;
		}

		$context = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => false, // We're reading OUR OWN cert, not validating trust of a remote party.
					'verify_peer_name'  => false,
					'SNI_enabled'       => true,
					'peer_name'         => $host,
				),
			)
		);

		$client = @stream_socket_client( // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreachable host is an expected outcome, not a code error
			'ssl://' . $host . ':443',
			$errno,
			$errstr,
			10,
			STREAM_CLIENT_CONNECT,
			$context
		);
		if ( false === $client ) {
			$result['error'] = $errstr ? $errstr : __( 'Could not open a TLS connection.', 'integrity-sentinel' );
			return $result;
		}

		$params = stream_context_get_params( $client );
		fclose( $client ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- a raw TLS socket, not a filesystem handle

		if ( empty( $params['options']['ssl']['peer_certificate'] ) ) {
			$result['error'] = __( 'No certificate was presented.', 'integrity-sentinel' );
			return $result;
		}

		$parsed = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
		if ( ! is_array( $parsed ) ) {
			$result['error'] = __( 'Could not parse the presented certificate.', 'integrity-sentinel' );
			return $result;
		}

		$summary                  = self::summarize_cert( $parsed );
		$result['ok']             = true;
		$result['valid_to']       = $summary['valid_to'];
		$result['issuer']         = $summary['issuer'];
		$result['days_remaining'] = self::days_until_expiry( $summary['valid_to'], time() );
		$result['severity']       = self::expiry_severity( $result['days_remaining'] );

		return $result;
	}
}

<?php
/**
 * Pure RFC 6238 TOTP / RFC 4226 HOTP implementation used by two-factor auth.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * RFC 6238 TOTP (built on RFC 4226 HOTP), implemented with only PHP's
 * built-in hash_hmac() -- no third-party library, consistent with this
 * plugin's zero-runtime-dependency design. Every method here is pure
 * (given a secret/time/code, no WordPress or I/O calls), which is what
 * makes the algorithm itself independently testable against the
 * official RFC 6238 Appendix B test vectors.
 */
class IS_TOTP {

	const SECRET_BYTES = 20; // 160-bit secret, the Google Authenticator/Authy convention.
	const PERIOD       = 30; // seconds per time step.
	const DIGITS       = 6;  // code length shown to the user.
	const WINDOW       = 1;  // accept ±1 time step either side, for clock drift.

	const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generates a new random TOTP secret (raw bytes), base32-encoded for storage/display.
	 */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( self::SECRET_BYTES ) );
	}

	/**
	 * Pure: RFC 4648 base32 encoding (no padding).
	 *
	 * @param string $data Raw bytes to encode.
	 */
	public static function base32_encode( $data ) {
		$binary = '';
		foreach ( str_split( (string) $data ) as $byte ) {
			$binary .= str_pad( decbin( ord( $byte ) ), 8, '0', STR_PAD_LEFT );
		}
		$output = '';
		foreach ( str_split( $binary, 5 ) as $chunk ) {
			$chunk   = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$output .= self::BASE32_ALPHABET[ bindec( $chunk ) ];
		}
		return $output;
	}

	/**
	 * Pure: RFC 4648 base32 decoding, tolerant of lowercase/whitespace.
	 *
	 * @param string $encoded Base32-encoded string to decode.
	 */
	public static function base32_decode( $encoded ) {
		$clean  = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', (string) $encoded ) );
		$binary = '';
		foreach ( str_split( $clean ) as $char ) {
			$pos = strpos( self::BASE32_ALPHABET, $char );
			if ( false === $pos ) {
				continue;
			}
			$binary .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$bytes = '';
		foreach ( str_split( $binary, 8 ) as $chunk ) {
			if ( 8 !== strlen( $chunk ) ) {
				continue; // leftover padding bits, not a full byte.
			}
			$bytes .= chr( bindec( $chunk ) );
		}
		return $bytes;
	}

	/**
	 * Pure: RFC 4226 HOTP -- HMAC-SHA1(secret, counter), dynamic
	 * truncation, N-digit code. $secret_binary is the raw decoded
	 * secret, not the base32 form.
	 *
	 * @param string $secret_binary Raw decoded secret bytes.
	 * @param int    $counter       HOTP counter value (time step for TOTP).
	 * @param int    $digits        Number of digits in the resulting code.
	 */
	public static function hotp( $secret_binary, $counter, $digits = self::DIGITS ) {
		$counter_bytes = pack( 'J', $counter ); // 8-byte big-endian counter (unsigned 64-bit, PHP 5.6.3+).
		$hash          = hash_hmac( 'sha1', $counter_bytes, $secret_binary, true );

		$offset      = ord( $hash[19] ) & 0x0F;
		$binary_code = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );

		$code = $binary_code % ( 10 ** $digits );
		return str_pad( (string) $code, $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * Pure: the TOTP code for a base32 secret at a given unix timestamp.
	 *
	 * @param string $secret_base32 Base32-encoded secret.
	 * @param int    $timestamp     Unix timestamp to compute the code for.
	 * @param int    $digits        Number of digits in the resulting code.
	 * @param int    $period        Seconds per time step.
	 */
	public static function totp_at_time( $secret_base32, $timestamp, $digits = self::DIGITS, $period = self::PERIOD ) {
		$counter = (int) floor( $timestamp / $period );
		return self::hotp( self::base32_decode( $secret_base32 ), $counter, $digits );
	}

	/**
	 * Pure: verifies a user-entered code against a window of time steps
	 * around $timestamp (clock drift tolerance). Constant-time
	 * comparison per candidate via hash_equals().
	 *
	 * @param string $secret_base32 Base32-encoded secret.
	 * @param string $code          User-entered code to verify.
	 * @param int    $timestamp     Unix timestamp to verify the code against.
	 * @param int    $window        Number of time steps to accept either side of $timestamp.
	 * @param int    $digits        Number of digits expected in $code.
	 * @param int    $period        Seconds per time step.
	 */
	public static function verify( $secret_base32, $code, $timestamp, $window = self::WINDOW, $digits = self::DIGITS, $period = self::PERIOD ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		if ( ! preg_match( '/^\d{' . $digits . '}$/', $code ) ) {
			return false;
		}
		for ( $i = -$window; $i <= $window; $i++ ) {
			$candidate = self::totp_at_time( $secret_base32, $timestamp + ( $i * $period ), $digits, $period );
			if ( hash_equals( $candidate, $code ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The otpauth:// URI an authenticator app would scan from a QR
	 * code. This plugin doesn't render an actual QR image (that would
	 * need either a bundled third-party JS library, which conflicts
	 * with its zero-dependency design, or calling an external QR
	 * generation service, which would leak the TOTP secret to a third
	 * party over the network) -- the admin UI shows this URI and the
	 * manual-entry secret instead, the same fallback every authenticator
	 * app already supports for "can't scan a code" setup.
	 *
	 * @param string $secret_base32 Base32-encoded secret.
	 * @param string $account_label Account label shown in the authenticator app.
	 * @param string $issuer        Issuer name shown in the authenticator app.
	 */
	public static function provisioning_uri( $secret_base32, $account_label, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $account_label )
			. '?secret=' . rawurlencode( $secret_base32 )
			. '&issuer=' . rawurlencode( $issuer )
			. '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
	}
}

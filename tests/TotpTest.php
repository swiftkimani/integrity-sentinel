<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for IS_TOTP, validated against the official RFC 6238
 * Appendix B test vectors (SHA1, 8-digit codes, 20-byte ASCII seed
 * "12345678901234567890"). If this plugin's TOTP implementation ever
 * disagrees with these published vectors, every authenticator app
 * (Google Authenticator, Authy, 1Password, ...) would disagree with it
 * too -- these are the ground truth, not just a regression baseline.
 */
class TotpTest extends TestCase {

	/** RFC 6238's own seed, base32-encoded (ASCII "12345678901234567890"). */
	private function rfc_secret() {
		return IS_TOTP::base32_encode( '12345678901234567890' );
	}

	// ---- base32 round-trip -------------------------------------------

	public function test_base32_round_trips_arbitrary_bytes() {
		$original = random_bytes( 20 );
		$this->assertSame( $original, IS_TOTP::base32_decode( IS_TOTP::base32_encode( $original ) ) );
	}

	public function test_base32_decode_is_case_insensitive() {
		$upper = IS_TOTP::base32_encode( 'hello world!' );
		$this->assertSame( IS_TOTP::base32_decode( $upper ), IS_TOTP::base32_decode( strtolower( $upper ) ) );
	}

	public function test_base32_decode_ignores_whitespace() {
		$encoded = IS_TOTP::base32_encode( 'test' );
		$spaced  = implode( ' ', str_split( $encoded, 4 ) );
		$this->assertSame( IS_TOTP::base32_decode( $encoded ), IS_TOTP::base32_decode( $spaced ) );
	}

	// ---- generate_secret -----------------------------------------------

	public function test_generated_secret_decodes_to_the_configured_byte_length() {
		$secret = IS_TOTP::generate_secret();
		$this->assertSame( IS_TOTP::SECRET_BYTES, strlen( IS_TOTP::base32_decode( $secret ) ) );
	}

	public function test_generated_secrets_are_not_all_identical() {
		$this->assertNotSame( IS_TOTP::generate_secret(), IS_TOTP::generate_secret() );
	}

	// ---- RFC 6238 Appendix B test vectors (SHA1, 8 digits) --------------

	public static function rfc_vectors() {
		return array(
			array( 59, '94287082' ),
			array( 1111111109, '07081804' ),
			array( 1111111111, '14050471' ),
			array( 1234567890, '89005924' ),
			array( 2000000000, '69279037' ),
			array( 20000000000, '65353130' ),
		);
	}

	/** @dataProvider rfc_vectors */
	public function test_matches_official_rfc_6238_test_vectors( $timestamp, $expected_code ) {
		$this->assertSame( $expected_code, IS_TOTP::totp_at_time( $this->rfc_secret(), $timestamp, 8, IS_TOTP::PERIOD ) );
	}

	// ---- verify() --------------------------------------------------------

	public function test_verify_accepts_the_current_code() {
		$secret = IS_TOTP::generate_secret();
		$now    = 1700000000;
		$code   = IS_TOTP::totp_at_time( $secret, $now );
		$this->assertTrue( IS_TOTP::verify( $secret, $code, $now ) );
	}

	public function test_verify_accepts_one_step_of_clock_drift_either_way() {
		$secret = IS_TOTP::generate_secret();
		$now    = 1700000000;
		$this->assertTrue( IS_TOTP::verify( $secret, IS_TOTP::totp_at_time( $secret, $now - IS_TOTP::PERIOD ), $now ) );
		$this->assertTrue( IS_TOTP::verify( $secret, IS_TOTP::totp_at_time( $secret, $now + IS_TOTP::PERIOD ), $now ) );
	}

	public function test_verify_rejects_a_code_outside_the_window() {
		$secret = IS_TOTP::generate_secret();
		$now    = 1700000000;
		$stale  = IS_TOTP::totp_at_time( $secret, $now - ( 5 * IS_TOTP::PERIOD ) );
		$this->assertFalse( IS_TOTP::verify( $secret, $stale, $now ) );
	}

	public function test_verify_rejects_wrong_code() {
		$secret = IS_TOTP::generate_secret();
		$now    = 1700000000;
		$real   = IS_TOTP::totp_at_time( $secret, $now );
		$wrong  = ( '000000' === $real ) ? '111111' : '000000';
		$this->assertFalse( IS_TOTP::verify( $secret, $wrong, $now ) );
	}

	public function test_verify_rejects_malformed_input() {
		$secret = IS_TOTP::generate_secret();
		$this->assertFalse( IS_TOTP::verify( $secret, 'abcdef', time() ) );
		$this->assertFalse( IS_TOTP::verify( $secret, '12345', time() ) ); // too short
		$this->assertFalse( IS_TOTP::verify( $secret, '1234567', time() ) ); // too long
		$this->assertFalse( IS_TOTP::verify( $secret, '', time() ) );
	}

	public function test_verify_tolerates_surrounding_whitespace() {
		$secret = IS_TOTP::generate_secret();
		$now    = 1700000000;
		$code   = IS_TOTP::totp_at_time( $secret, $now );
		$this->assertTrue( IS_TOTP::verify( $secret, " {$code} ", $now ) );
	}

	// ---- provisioning_uri --------------------------------------------------

	public function test_provisioning_uri_contains_the_secret_and_issuer() {
		$secret = IS_TOTP::generate_secret();
		$uri    = IS_TOTP::provisioning_uri( $secret, 'admin', 'My Site' );
		$this->assertStringStartsWith( 'otpauth://totp/', $uri );
		$this->assertStringContainsString( rawurlencode( $secret ), $uri );
		$this->assertStringContainsString( 'issuer=My%20Site', $uri );
	}
}

<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure logic in IS_TLS_Check. check_certificate()
 * itself opens a real TLS socket and is exercised in a real WordPress/
 * network environment, not here.
 */
class TlsCheckTest extends TestCase {

	const DAY = 86400;

	// ---- days_until_expiry --------------------------------------------------

	public function test_days_remaining_for_a_future_expiry() {
		$this->assertSame( 30, IS_TLS_Check::days_until_expiry( 1000000 + ( 30 * self::DAY ), 1000000 ) );
	}

	public function test_negative_days_for_an_already_expired_cert() {
		$this->assertSame( -5, IS_TLS_Check::days_until_expiry( 1000000 - ( 5 * self::DAY ), 1000000 ) );
	}

	// ---- expiry_severity ----------------------------------------------------

	public function test_already_expired_is_critical() {
		$this->assertSame( 'critical', IS_TLS_Check::expiry_severity( -1 ) );
	}

	public function test_expiring_within_a_week_is_critical() {
		$this->assertSame( 'critical', IS_TLS_Check::expiry_severity( 6 ) );
	}

	public function test_expiring_within_a_month_is_high() {
		$this->assertSame( 'high', IS_TLS_Check::expiry_severity( 29 ) );
	}

	public function test_expiring_within_ninety_days_is_medium() {
		$this->assertSame( 'medium', IS_TLS_Check::expiry_severity( 89 ) );
	}

	public function test_plenty_of_runway_is_low() {
		$this->assertSame( 'low', IS_TLS_Check::expiry_severity( 90 ) );
		$this->assertSame( 'low', IS_TLS_Check::expiry_severity( 365 ) );
	}

	// ---- summarize_cert -------------------------------------------------------

	public function test_extracts_the_fields_this_check_needs() {
		$parsed = array(
			'validTo_time_t' => 1999999999,
			'issuer'         => array( 'CN' => "Let's Encrypt" ),
			'subject'        => array( 'CN' => 'example.com' ),
		);
		$summary = IS_TLS_Check::summarize_cert( $parsed );
		$this->assertSame( 1999999999, $summary['valid_to'] );
		$this->assertSame( "Let's Encrypt", $summary['issuer'] );
		$this->assertSame( 'example.com', $summary['subject'] );
	}

	public function test_handles_a_missing_issuer_cn_gracefully() {
		$summary = IS_TLS_Check::summarize_cert( array( 'validTo_time_t' => 123 ) );
		$this->assertSame( '', $summary['issuer'] );
		$this->assertSame( '', $summary['subject'] );
	}
}

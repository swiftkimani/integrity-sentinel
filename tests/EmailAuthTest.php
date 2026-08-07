<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure record-parsing logic in IS_Email_Auth.
 * check_domain() itself performs real DNS lookups (dns_get_record) and
 * is exercised in a real WordPress/network environment, not here.
 */
class EmailAuthTest extends TestCase {

	// ---- has_spf ----------------------------------------------------------

	public function test_detects_a_valid_spf_record() {
		$this->assertTrue( IS_Email_Auth::has_spf( array( 'v=spf1 include:_spf.example.com ~all' ) ) );
	}

	public function test_ignores_unrelated_txt_records() {
		$this->assertFalse( IS_Email_Auth::has_spf( array( 'google-site-verification=abc123' ) ) );
	}

	public function test_no_spf_among_empty_records() {
		$this->assertFalse( IS_Email_Auth::has_spf( array() ) );
	}

	// ---- has_dmarc / dmarc_policy ------------------------------------------

	public function test_detects_a_valid_dmarc_record() {
		$this->assertTrue( IS_Email_Auth::has_dmarc( array( 'v=DMARC1; p=reject; rua=mailto:a@example.com' ) ) );
	}

	public function test_extracts_the_reject_policy() {
		$this->assertSame( 'reject', IS_Email_Auth::dmarc_policy( 'v=DMARC1; p=reject; rua=mailto:a@example.com' ) );
	}

	public function test_extracts_the_none_policy() {
		$this->assertSame( 'none', IS_Email_Auth::dmarc_policy( 'v=DMARC1; p=none' ) );
	}

	public function test_empty_policy_for_malformed_record() {
		$this->assertSame( '', IS_Email_Auth::dmarc_policy( 'not a dmarc record' ) );
	}

	// ---- has_dkim -----------------------------------------------------------

	public function test_detects_a_dkim_record_by_version_tag() {
		$this->assertTrue( IS_Email_Auth::has_dkim( array( 'v=DKIM1; k=rsa; p=MIGfMA0...' ) ) );
	}

	public function test_detects_a_dkim_record_by_key_type_alone() {
		$this->assertTrue( IS_Email_Auth::has_dkim( array( 'k=rsa; p=MIGfMA0...' ) ) );
	}

	public function test_no_dkim_among_unrelated_records() {
		$this->assertFalse( IS_Email_Auth::has_dkim( array( 'v=spf1 ~all' ) ) );
	}
}

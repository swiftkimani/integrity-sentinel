<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_IP_List. The WP-dependent
 * parts (enforce()'s wp_die(), get_option()-backed settings()) are
 * exercised in a real WordPress, not here.
 */
class IpListTest extends TestCase {

	// ---- parse_list_text ----------------------------------------------

	public function test_parses_one_entry_per_line() {
		$this->assertSame( array( '1.2.3.4', '5.6.7.0/24' ), IS_IP_List::parse_list_text( "1.2.3.4\n5.6.7.0/24" ) );
	}

	public function test_ignores_blank_lines() {
		$this->assertSame( array( '1.2.3.4' ), IS_IP_List::parse_list_text( "\n1.2.3.4\n\n" ) );
	}

	public function test_strips_trailing_comments() {
		$this->assertSame( array( '1.2.3.4' ), IS_IP_List::parse_list_text( '1.2.3.4 # office VPN' ) );
	}

	// ---- ip_in_entry: IPv4 ---------------------------------------------

	public function test_exact_ipv4_match() {
		$this->assertTrue( IS_IP_List::ip_in_entry( '203.0.113.5', '203.0.113.5' ) );
	}

	public function test_exact_ipv4_non_match() {
		$this->assertFalse( IS_IP_List::ip_in_entry( '203.0.113.6', '203.0.113.5' ) );
	}

	public function test_ipv4_cidr_match() {
		$this->assertTrue( IS_IP_List::ip_in_entry( '203.0.113.42', '203.0.113.0/24' ) );
	}

	public function test_ipv4_cidr_non_match_outside_range() {
		$this->assertFalse( IS_IP_List::ip_in_entry( '203.0.114.1', '203.0.113.0/24' ) );
	}

	public function test_ipv4_cidr_with_non_octet_aligned_prefix() {
		// 203.0.113.0/26 covers .0-.63
		$this->assertTrue( IS_IP_List::ip_in_entry( '203.0.113.63', '203.0.113.0/26' ) );
		$this->assertFalse( IS_IP_List::ip_in_entry( '203.0.113.64', '203.0.113.0/26' ) );
	}

	public function test_single_ip_cidr_slash_32() {
		$this->assertTrue( IS_IP_List::ip_in_entry( '203.0.113.5', '203.0.113.5/32' ) );
		$this->assertFalse( IS_IP_List::ip_in_entry( '203.0.113.6', '203.0.113.5/32' ) );
	}

	// ---- ip_in_entry: IPv6 ----------------------------------------------

	public function test_exact_ipv6_match() {
		$this->assertTrue( IS_IP_List::ip_in_entry( '2001:db8::1', '2001:db8::1' ) );
	}

	public function test_ipv6_cidr_match() {
		$this->assertTrue( IS_IP_List::ip_in_entry( '2001:db8::abcd', '2001:db8::/32' ) );
	}

	public function test_ipv6_cidr_non_match() {
		$this->assertFalse( IS_IP_List::ip_in_entry( '2001:db9::1', '2001:db8::/32' ) );
	}

	// ---- ip_in_entry: mismatches / malformed input ----------------------

	public function test_address_family_mismatch_never_matches() {
		$this->assertFalse( IS_IP_List::ip_in_entry( '203.0.113.5', '2001:db8::/32' ) );
		$this->assertFalse( IS_IP_List::ip_in_entry( '2001:db8::1', '203.0.113.0/24' ) );
	}

	public function test_invalid_ip_never_matches() {
		$this->assertFalse( IS_IP_List::ip_in_entry( 'not-an-ip', '203.0.113.0/24' ) );
	}

	public function test_invalid_entry_never_matches() {
		$this->assertFalse( IS_IP_List::ip_in_entry( '203.0.113.5', 'garbage/24' ) );
	}

	// ---- ip_matches_list -------------------------------------------------

	public function test_matches_list_true_when_any_entry_matches() {
		$this->assertTrue( IS_IP_List::ip_matches_list( '203.0.113.5', array( '10.0.0.0/8', '203.0.113.0/24' ) ) );
	}

	public function test_matches_list_false_when_no_entry_matches() {
		$this->assertFalse( IS_IP_List::ip_matches_list( '203.0.113.5', array( '10.0.0.0/8' ) ) );
	}

	public function test_matches_list_false_for_empty_ip() {
		$this->assertFalse( IS_IP_List::ip_matches_list( '', array( '0.0.0.0/0' ) ) );
	}

	// ---- resolve_client_ip -------------------------------------------------

	public function test_uses_remote_addr_when_no_header_configured() {
		$server   = array( 'REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.9' );
		$settings = array( 'trusted_ip_header' => '', 'trusted_proxy_ranges' => '' );
		$this->assertSame( '203.0.113.5', IS_IP_List::resolve_client_ip( $server, $settings ) );
	}

	public function test_ignores_forged_header_when_remote_addr_is_not_a_trusted_proxy() {
		// An attacker connecting directly can set X-Forwarded-For to
		// anything; since their REMOTE_ADDR isn't in the trusted range,
		// the header must be ignored entirely.
		$server   = array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_FOR' => '10.0.0.1' );
		$settings = array( 'trusted_ip_header' => 'X-Forwarded-For', 'trusted_proxy_ranges' => '203.0.113.0/24' );
		$this->assertSame( '198.51.100.9', IS_IP_List::resolve_client_ip( $server, $settings ) );
	}

	public function test_trusts_header_when_remote_addr_is_the_configured_proxy() {
		$server   = array( 'REMOTE_ADDR' => '203.0.113.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.9' );
		$settings = array( 'trusted_ip_header' => 'X-Forwarded-For', 'trusted_proxy_ranges' => '203.0.113.0/24' );
		$this->assertSame( '198.51.100.9', IS_IP_List::resolve_client_ip( $server, $settings ) );
	}

	public function test_uses_first_hop_of_a_forwarded_for_chain() {
		$server   = array( 'REMOTE_ADDR' => '203.0.113.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.9, 203.0.113.1' );
		$settings = array( 'trusted_ip_header' => 'X-Forwarded-For', 'trusted_proxy_ranges' => '203.0.113.0/24' );
		$this->assertSame( '198.51.100.9', IS_IP_List::resolve_client_ip( $server, $settings ) );
	}

	public function test_falls_back_to_remote_addr_when_trusted_but_header_missing() {
		$server   = array( 'REMOTE_ADDR' => '203.0.113.1' );
		$settings = array( 'trusted_ip_header' => 'X-Forwarded-For', 'trusted_proxy_ranges' => '203.0.113.0/24' );
		$this->assertSame( '203.0.113.1', IS_IP_List::resolve_client_ip( $server, $settings ) );
	}

	public function test_falls_back_to_remote_addr_when_header_value_is_garbage() {
		$server   = array( 'REMOTE_ADDR' => '203.0.113.1', 'HTTP_X_FORWARDED_FOR' => 'not-an-ip' );
		$settings = array( 'trusted_ip_header' => 'X-Forwarded-For', 'trusted_proxy_ranges' => '203.0.113.0/24' );
		$this->assertSame( '203.0.113.1', IS_IP_List::resolve_client_ip( $server, $settings ) );
	}

	// ---- temporary bans -------------------------------------------------

	public function test_default_ban_record_is_not_active() {
		$this->assertFalse( IS_IP_List::is_ban_active( IS_IP_List::default_ban_record(), 1000 ) );
	}

	public function test_ban_is_active_before_expiry() {
		$record = array( 'banned_until' => 2000, 'reason' => 'honeypot_triggered' );
		$this->assertTrue( IS_IP_List::is_ban_active( $record, 1000 ) );
	}

	public function test_ban_is_not_active_after_expiry() {
		$record = array( 'banned_until' => 1000, 'reason' => 'honeypot_triggered' );
		$this->assertFalse( IS_IP_List::is_ban_active( $record, 1000 ) );
		$this->assertFalse( IS_IP_List::is_ban_active( $record, 1001 ) );
	}

	public function test_ban_with_no_banned_until_is_not_active() {
		$this->assertFalse( IS_IP_List::is_ban_active( array( 'reason' => 'x' ), 1000 ) );
	}
}

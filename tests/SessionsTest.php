<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Sessions (new-IP detection,
 * the known-IPs list, and the user-agent label). The WP-dependent parts
 * (WP_Session_Tokens, the wp_login hook, admin-post handlers) are
 * exercised in a real WordPress, not here.
 */
class SessionsTest extends TestCase {

	// ---- is_new_ip -----------------------------------------------------

	public function test_flags_an_unseen_ip() {
		$this->assertTrue( IS_Sessions::is_new_ip( '203.0.113.9', array( '198.51.100.1' ) ) );
	}

	public function test_does_not_flag_a_known_ip() {
		$this->assertFalse( IS_Sessions::is_new_ip( '198.51.100.1', array( '198.51.100.1', '203.0.113.9' ) ) );
	}

	public function test_never_flags_when_known_list_is_empty() {
		// The account's very first recorded login -- everything would
		// trivially look "new" and the alert would be pure noise.
		$this->assertFalse( IS_Sessions::is_new_ip( '203.0.113.9', array() ) );
	}

	public function test_never_flags_an_empty_ip() {
		$this->assertFalse( IS_Sessions::is_new_ip( '', array( '198.51.100.1' ) ) );
	}

	// ---- record_known_ip -------------------------------------------------

	public function test_appends_a_new_ip() {
		$result = IS_Sessions::record_known_ip( array( '198.51.100.1' ), '203.0.113.9' );
		$this->assertSame( array( '198.51.100.1', '203.0.113.9' ), $result );
	}

	public function test_deduplicates_and_moves_a_repeated_ip_to_the_end() {
		$result = IS_Sessions::record_known_ip( array( '198.51.100.1', '203.0.113.9' ), '198.51.100.1' );
		$this->assertSame( array( '203.0.113.9', '198.51.100.1' ), $result );
	}

	public function test_caps_the_list_to_the_most_recent_entries() {
		$known  = array( 'a', 'b', 'c' );
		$result = IS_Sessions::record_known_ip( $known, 'd', 3 );
		$this->assertSame( array( 'b', 'c', 'd' ), $result );
	}

	public function test_ignores_an_empty_ip() {
		$this->assertSame( array( '198.51.100.1' ), IS_Sessions::record_known_ip( array( '198.51.100.1' ), '' ) );
	}

	// ---- describe_user_agent ----------------------------------------------

	public function test_describes_a_common_desktop_browser() {
		$ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
		$this->assertSame( 'Safari on macOS', IS_Sessions::describe_user_agent( $ua ) );
	}

	public function test_describes_chrome_on_windows() {
		$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
		$this->assertSame( 'Chrome on Windows', IS_Sessions::describe_user_agent( $ua ) );
	}

	public function test_describes_mobile_safari() {
		$ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
		$this->assertSame( 'Safari on iOS', IS_Sessions::describe_user_agent( $ua ) );
	}

	public function test_handles_an_empty_user_agent() {
		$this->assertSame( 'Unknown device', IS_Sessions::describe_user_agent( '' ) );
	}
}

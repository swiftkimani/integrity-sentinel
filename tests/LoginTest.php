<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Login (URL rename matching
 * and the login-attempt circuit breaker). The WP-dependent parts
 * (transients, wp_die(), the authenticate/wp_login_failed hooks) are
 * exercised in a real WordPress, not here.
 */
class LoginTest extends TestCase {

	const THRESHOLD = 5;
	const WINDOW    = 900;
	const LOCKOUT   = 900;

	// ---- sanitize_login_slug -------------------------------------------

	public function test_lowercases_and_trims_slashes() {
		$this->assertSame( 'my-secret-login', IS_Login::sanitize_login_slug( '/My-Secret-Login/' ) );
	}

	public function test_strips_disallowed_characters() {
		$this->assertSame( 'secret123', IS_Login::sanitize_login_slug( 'sec ret!123?' ) );
	}

	public function test_rejects_reserved_core_paths() {
		foreach ( array( 'wp-admin', 'wp-login', 'wp-login.php', 'xmlrpc.php', 'wp-json' ) as $reserved ) {
			$this->assertSame( '', IS_Login::sanitize_login_slug( $reserved ) );
		}
	}

	public function test_empty_input_yields_empty_slug() {
		$this->assertSame( '', IS_Login::sanitize_login_slug( '   ' ) );
	}

	// ---- normalize_path --------------------------------------------------

	public function test_normalize_path_strips_query_string() {
		$this->assertSame( '/wp-login.php', IS_Login::normalize_path( '/wp-login.php?action=logout&_wpnonce=abc' ) );
	}

	public function test_normalize_path_strips_trailing_slash_and_lowercases() {
		$this->assertSame( '/my-login', IS_Login::normalize_path( '/My-Login/' ) );
	}

	// ---- is_wp_login_request ----------------------------------------------

	public function test_detects_direct_wp_login_request() {
		$this->assertTrue( IS_Login::is_wp_login_request( '/wp-login.php' ) );
		$this->assertTrue( IS_Login::is_wp_login_request( '/subdir/wp-login.php' ) );
	}

	public function test_does_not_flag_unrelated_paths() {
		$this->assertFalse( IS_Login::is_wp_login_request( '/my-secret-login' ) );
		$this->assertFalse( IS_Login::is_wp_login_request( '/wp-login.php-lookalike' ) );
	}

	// ---- path_matches_slug -------------------------------------------------

	public function test_matches_exact_last_segment() {
		$this->assertTrue( IS_Login::path_matches_slug( '/my-secret-login', 'my-secret-login' ) );
	}

	public function test_does_not_match_when_slug_is_only_a_substring() {
		$this->assertFalse( IS_Login::path_matches_slug( '/my-secret-loginx', 'my-secret-login' ) );
	}

	public function test_no_match_when_slug_unset() {
		$this->assertFalse( IS_Login::path_matches_slug( '/anything', '' ) );
	}

	// ---- should_allow_direct_wp_login --------------------------------------

	public function test_allows_the_small_safe_action_list() {
		foreach ( array( 'postpass', 'logout', 'confirmaction', 'confirm_admin_email' ) as $action ) {
			$this->assertTrue( IS_Login::should_allow_direct_wp_login( array( 'action' => $action ) ) );
		}
	}

	public function test_blocks_a_plain_credential_attempt() {
		$this->assertFalse( IS_Login::should_allow_direct_wp_login( array() ) );
		$this->assertFalse( IS_Login::should_allow_direct_wp_login( array( 'action' => 'login' ) ) );
	}

	// ---- rewrite_login_url --------------------------------------------------

	public function test_rewrites_wp_login_php_to_the_slug() {
		$this->assertSame( 'https://example.com/my-secret-login', IS_Login::rewrite_login_url( 'https://example.com/wp-login.php', 'my-secret-login' ) );
	}

	public function test_leaves_unrelated_urls_untouched() {
		$url = 'https://example.com/wp-admin/';
		$this->assertSame( $url, IS_Login::rewrite_login_url( $url, 'my-secret-login' ) );
	}

	public function test_leaves_url_untouched_when_slug_unset() {
		$url = 'https://example.com/wp-login.php';
		$this->assertSame( $url, IS_Login::rewrite_login_url( $url, '' ) );
	}

	// ---- login attempt circuit breaker -------------------------------------

	public function test_default_attempt_record_is_not_locked() {
		$this->assertFalse( IS_Login::is_locked_out( IS_Login::default_attempt_record(), 1000 ) );
	}

	public function test_below_threshold_stays_unlocked() {
		$result = IS_Login::record_failure( IS_Login::default_attempt_record(), 1000, self::THRESHOLD, self::WINDOW, self::LOCKOUT );
		$this->assertNull( $result['record']['locked_until'] );
		$this->assertFalse( $result['just_locked'] );
	}

	public function test_reaching_threshold_locks_the_ip_out() {
		$record = array( 'failures' => array( 100, 200, 300, 400 ), 'locked_until' => null );
		$result = IS_Login::record_failure( $record, 500, self::THRESHOLD, self::WINDOW, self::LOCKOUT );

		$this->assertTrue( $result['just_locked'] );
		$this->assertSame( 500 + self::LOCKOUT, $result['record']['locked_until'] );
	}

	public function test_stale_failures_outside_the_window_do_not_count() {
		$record = array( 'failures' => array( 1, 2, 3, 4 ), 'locked_until' => null );
		$result = IS_Login::record_failure( $record, 100000, self::THRESHOLD, self::WINDOW, self::LOCKOUT );

		$this->assertCount( 1, $result['record']['failures'] );
		$this->assertFalse( $result['just_locked'] );
	}

	public function test_already_locked_ip_does_not_retrigger_the_alert() {
		$record = array( 'failures' => array( 100, 200, 300, 400 ), 'locked_until' => 10000 );
		$result = IS_Login::record_failure( $record, 500, self::THRESHOLD, self::WINDOW, self::LOCKOUT );

		$this->assertFalse( $result['just_locked'] );
	}
}

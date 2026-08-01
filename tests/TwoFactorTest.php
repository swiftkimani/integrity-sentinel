<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_2FA (recovery-code
 * handling and role-enforcement matching). The WP-dependent parts
 * (usermeta, transients, the login-interception/profile-screen hooks)
 * are exercised in a real WordPress, not here.
 */
class TwoFactorTest extends TestCase {

	// ---- normalize_recovery_code ---------------------------------------

	public function test_normalizes_dashes_and_case() {
		$this->assertSame( 'AB12CD34', IS_2FA::normalize_recovery_code( 'ab12-cd34' ) );
	}

	public function test_normalizes_spaces() {
		$this->assertSame( 'AB12CD34', IS_2FA::normalize_recovery_code( ' AB12 CD34 ' ) );
	}

	// ---- hash_recovery_code ------------------------------------------------

	public function test_hash_is_stable_across_equivalent_formatting() {
		$this->assertSame( IS_2FA::hash_recovery_code( 'ab12-cd34' ), IS_2FA::hash_recovery_code( 'AB12CD34' ) );
	}

	public function test_hash_differs_for_different_codes() {
		$this->assertNotSame( IS_2FA::hash_recovery_code( 'AB12CD34' ), IS_2FA::hash_recovery_code( 'EF56GH78' ) );
	}

	public function test_hash_is_not_the_plaintext() {
		$this->assertNotSame( 'AB12CD34', IS_2FA::hash_recovery_code( 'AB12CD34' ) );
	}

	// ---- consume_recovery_code ----------------------------------------------

	public function test_matches_and_removes_the_used_code() {
		$codes  = array_map( array( 'IS_2FA', 'hash_recovery_code' ), array( 'CODE1', 'CODE2', 'CODE3' ) );
		$result = IS_2FA::consume_recovery_code( $codes, 'CODE2' );

		$this->assertTrue( $result['matched'] );
		$this->assertCount( 2, $result['remaining'] );
		$this->assertNotContains( IS_2FA::hash_recovery_code( 'CODE2' ), $result['remaining'] );
		$this->assertContains( IS_2FA::hash_recovery_code( 'CODE1' ), $result['remaining'] );
	}

	public function test_accepts_dash_formatted_input_for_a_dashless_stored_hash() {
		$codes  = array( IS_2FA::hash_recovery_code( 'AB12CD34E5' ) );
		$result = IS_2FA::consume_recovery_code( $codes, 'AB12-CD34E5' );
		$this->assertTrue( $result['matched'] );
	}

	public function test_unknown_code_does_not_match_and_leaves_list_untouched() {
		$codes  = array_map( array( 'IS_2FA', 'hash_recovery_code' ), array( 'CODE1', 'CODE2' ) );
		$result = IS_2FA::consume_recovery_code( $codes, 'NOPE' );

		$this->assertFalse( $result['matched'] );
		$this->assertSame( $codes, $result['remaining'] );
	}

	public function test_a_used_code_cannot_be_used_again() {
		$codes  = array_map( array( 'IS_2FA', 'hash_recovery_code' ), array( 'CODE1', 'CODE2' ) );
		$first  = IS_2FA::consume_recovery_code( $codes, 'CODE1' );
		$second = IS_2FA::consume_recovery_code( $first['remaining'], 'CODE1' );

		$this->assertTrue( $first['matched'] );
		$this->assertFalse( $second['matched'] );
	}

	public function test_empty_list_never_matches() {
		$result = IS_2FA::consume_recovery_code( array(), 'ANYTHING' );
		$this->assertFalse( $result['matched'] );
	}

	// ---- role_requires_2fa --------------------------------------------------

	public function test_role_in_enforced_list_requires_2fa() {
		$this->assertTrue( IS_2FA::role_requires_2fa( array( 'editor' ), array( 'administrator', 'editor' ) ) );
	}

	public function test_role_not_in_enforced_list_does_not_require_2fa() {
		$this->assertFalse( IS_2FA::role_requires_2fa( array( 'subscriber' ), array( 'administrator', 'editor' ) ) );
	}

	public function test_empty_enforced_list_requires_nothing() {
		$this->assertFalse( IS_2FA::role_requires_2fa( array( 'administrator' ), array() ) );
	}

	public function test_user_with_multiple_roles_matches_if_any_is_enforced() {
		$this->assertTrue( IS_2FA::role_requires_2fa( array( 'subscriber', 'shop_manager' ), array( 'shop_manager' ) ) );
	}
}

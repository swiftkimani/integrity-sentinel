<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure staleness logic in IS_Api_Key_Hygiene.
 * list_all() itself needs get_users()/WP_Application_Passwords
 * (WP-dependent) and is exercised in a real WordPress, not here.
 */
class ApiKeyHygieneTest extends TestCase {

	const NOW           = 1000000;
	const DAY           = 86400;
	const STALE_AFTER   = 90;

	public function test_never_used_but_recently_created_is_not_stale() {
		$app_password = array( 'created' => self::NOW - self::DAY );
		$this->assertFalse( IS_Api_Key_Hygiene::is_stale( $app_password, self::NOW, self::STALE_AFTER ) );
	}

	public function test_never_used_and_old_creation_is_stale() {
		$app_password = array( 'created' => self::NOW - ( 100 * self::DAY ) );
		$this->assertTrue( IS_Api_Key_Hygiene::is_stale( $app_password, self::NOW, self::STALE_AFTER ) );
	}

	public function test_recently_used_is_not_stale_even_if_created_long_ago() {
		$app_password = array(
			'created'   => self::NOW - ( 400 * self::DAY ),
			'last_used' => self::NOW - self::DAY,
		);
		$this->assertFalse( IS_Api_Key_Hygiene::is_stale( $app_password, self::NOW, self::STALE_AFTER ) );
	}

	public function test_stale_if_last_used_exceeds_the_threshold() {
		$app_password = array(
			'created'   => self::NOW - ( 400 * self::DAY ),
			'last_used' => self::NOW - ( 91 * self::DAY ),
		);
		$this->assertTrue( IS_Api_Key_Hygiene::is_stale( $app_password, self::NOW, self::STALE_AFTER ) );
	}

	public function test_no_created_or_last_used_is_never_stale() {
		$this->assertFalse( IS_Api_Key_Hygiene::is_stale( array(), self::NOW, self::STALE_AFTER ) );
	}
}

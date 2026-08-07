<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure fixed-window logic in IS_Rate_Limiter. The
 * WP-dependent glue (hit(), which uses transients) is exercised in a
 * real WordPress, not here -- same split as IS_Rest_Posts's original
 * rate limiter this class was generalized from.
 */
class RateLimiterTest extends TestCase {

	const LIMIT  = 5;
	const WINDOW = 300;

	public function test_empty_record_has_zero_count() {
		$this->assertSame( 0, IS_Rate_Limiter::current_window_count( array(), 1000, self::WINDOW ) );
	}

	public function test_count_within_window_is_reported() {
		$record = array(
			'window_started_at' => 1000,
			'count'             => 3,
		);
		$this->assertSame( 3, IS_Rate_Limiter::current_window_count( $record, 1100, self::WINDOW ) );
	}

	public function test_expired_window_is_treated_as_zero() {
		$record = array(
			'window_started_at' => 1000,
			'count'             => 3,
		);
		$this->assertSame( 0, IS_Rate_Limiter::current_window_count( $record, 1000 + self::WINDOW + 1, self::WINDOW ) );
	}

	public function test_not_limited_below_threshold() {
		$record = array(
			'window_started_at' => 1000,
			'count'             => self::LIMIT - 1,
		);
		$this->assertFalse( IS_Rate_Limiter::is_limited( $record, 1000, self::LIMIT, self::WINDOW ) );
	}

	public function test_limited_at_threshold() {
		$record = array(
			'window_started_at' => 1000,
			'count'             => self::LIMIT,
		);
		$this->assertTrue( IS_Rate_Limiter::is_limited( $record, 1000, self::LIMIT, self::WINDOW ) );
	}

	public function test_record_hit_starts_a_fresh_window() {
		$result = IS_Rate_Limiter::record_hit( array(), 1000, self::WINDOW );
		$this->assertSame( 1000, $result['window_started_at'] );
		$this->assertSame( 1, $result['count'] );
	}

	public function test_record_hit_increments_within_the_same_window() {
		$record = array(
			'window_started_at' => 1000,
			'count'             => 2,
		);
		$result = IS_Rate_Limiter::record_hit( $record, 1050, self::WINDOW );
		$this->assertSame( 1000, $result['window_started_at'] );
		$this->assertSame( 3, $result['count'] );
	}

	public function test_record_hit_resets_after_the_window_expires() {
		$record = array(
			'window_started_at' => 1000,
			'count'             => 4,
		);
		$result = IS_Rate_Limiter::record_hit( $record, 1000 + self::WINDOW + 1, self::WINDOW );
		$this->assertSame( 1000 + self::WINDOW + 1, $result['window_started_at'] );
		$this->assertSame( 1, $result['count'] );
	}
}

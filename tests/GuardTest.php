<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure state-transition logic in IS_Guard. The
 * WP-dependent parts (get_option/update_option-backed run()/health()) are
 * exercised in a real WordPress, not here.
 */
class GuardTest extends TestCase {

	const THRESHOLD = 5;
	const WINDOW    = 3600;
	const COOLDOWN  = 3600;

	public function test_safe_mode_is_off_by_default() {
		$this->assertFalse( IS_Guard::is_safe_mode() );
	}

	public function test_default_health_is_ok_and_enabled() {
		$health = IS_Guard::default_health();
		$this->assertSame( 'ok', $health['status'] );
		$this->assertNull( $health['disabled_until'] );
	}

	public function test_is_disabled_false_when_no_disabled_until() {
		$this->assertFalse( IS_Guard::is_disabled( IS_Guard::default_health(), 1000 ) );
	}

	public function test_is_disabled_true_while_disabled_until_is_future() {
		$health = array( 'disabled_until' => 2000 );
		$this->assertTrue( IS_Guard::is_disabled( $health, 1000 ) );
	}

	public function test_is_disabled_false_once_disabled_until_has_passed() {
		$health = array( 'disabled_until' => 500 );
		$this->assertFalse( IS_Guard::is_disabled( $health, 1000 ) );
	}

	public function test_success_state_resets_status_and_failures() {
		$health = array(
			'status'         => 'degraded',
			'failures'       => array( 100, 200 ),
			'last_error'     => 'boom',
			'last_error_at'  => 200,
			'disabled_until' => 9999,
		);
		$state = IS_Guard::success_state( $health );

		$this->assertSame( 'ok', $state['status'] );
		$this->assertSame( array(), $state['failures'] );
		$this->assertNull( $state['disabled_until'] );
		// Last error is kept for the health panel's benefit even after recovery.
		$this->assertSame( 'boom', $state['last_error'] );
	}

	public function test_failure_below_threshold_stays_degraded_but_not_disabled() {
		$health = IS_Guard::default_health();
		$result = IS_Guard::failure_state( $health, 1000, 'oops', self::THRESHOLD, self::WINDOW, self::COOLDOWN );

		$this->assertSame( 'degraded', $result['state']['status'] );
		$this->assertNull( $result['state']['disabled_until'] );
		$this->assertFalse( $result['tripped'] );
		$this->assertCount( 1, $result['state']['failures'] );
	}

	public function test_reaching_threshold_trips_the_breaker() {
		$health = array(
			'status'         => 'degraded',
			'failures'       => array( 100, 200, 300, 400 ), // one more will hit the threshold of 5
			'last_error'     => '',
			'last_error_at'  => null,
			'disabled_until' => null,
		);
		$result = IS_Guard::failure_state( $health, 500, 'boom', self::THRESHOLD, self::WINDOW, self::COOLDOWN );

		$this->assertTrue( $result['tripped'] );
		$this->assertSame( 500 + self::COOLDOWN, $result['state']['disabled_until'] );
		// The window resets once tripped so it doesn't re-trip on every call for the whole cooldown.
		$this->assertSame( array(), $result['state']['failures'] );
	}

	public function test_failures_outside_the_window_are_pruned_before_counting() {
		$health = array(
			// All four of these are older than the 1-hour window relative to $now = 100000.
			'failures'       => array( 1, 2, 3, 4 ),
			'disabled_until' => null,
		);
		$result = IS_Guard::failure_state( $health, 100000, 'oops', self::THRESHOLD, self::WINDOW, self::COOLDOWN );

		// Stale failures pruned, only this new one counts -- nowhere near the threshold.
		$this->assertCount( 1, $result['state']['failures'] );
		$this->assertFalse( $result['tripped'] );
	}

	public function test_failure_while_already_disabled_does_not_retrip() {
		$health = array(
			'failures'       => array( 100, 200, 300, 400 ),
			'disabled_until' => 10000, // already disabled, well into the future relative to $now
		);
		$result = IS_Guard::failure_state( $health, 500, 'boom', self::THRESHOLD, self::WINDOW, self::COOLDOWN );

		// Reaches the threshold again, but since it was already disabled this
		// isn't a new trip -- no duplicate alert should fire for it.
		$this->assertFalse( $result['tripped'] );
	}
}

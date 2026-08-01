<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Cron (configurable scan
 * frequency) and IS_Scanner (self-tuning pace tracking). The
 * WP-dependent parts (the actual wp_schedule_event()/get_option() calls)
 * are exercised in a real WordPress, not here.
 */
class CronTest extends TestCase {

	// ---- IS_Cron::normalize_frequency -----------------------------------

	public function test_accepts_every_valid_frequency() {
		foreach ( IS_Cron::VALID_FREQUENCIES as $frequency ) {
			$this->assertSame( $frequency, IS_Cron::normalize_frequency( $frequency ) );
		}
	}

	public function test_falls_back_to_daily_for_unknown_input() {
		$this->assertSame( 'daily', IS_Cron::normalize_frequency( 'fortnightly' ) );
		$this->assertSame( 'daily', IS_Cron::normalize_frequency( '' ) );
		$this->assertSame( 'daily', IS_Cron::normalize_frequency( null ) );
	}

	// ---- IS_Scanner::next_pace_average -----------------------------------

	public function test_first_observation_becomes_the_average_with_no_history() {
		$this->assertSame( 12.5, IS_Scanner::next_pace_average( 0, 12.5 ) );
	}

	public function test_weights_recent_observation_at_thirty_percent() {
		// prev=10, observed=20 -> 10*0.7 + 20*0.3 = 13.0
		$this->assertEqualsWithDelta( 13.0, IS_Scanner::next_pace_average( 10, 20 ), 0.0001 );
	}

	public function test_stable_pace_stays_stable() {
		$this->assertEqualsWithDelta( 15.0, IS_Scanner::next_pace_average( 15, 15 ), 0.0001 );
	}

	public function test_repeated_observations_converge_toward_the_new_pace() {
		$avg = 10.0;
		for ( $i = 0; $i < 20; $i++ ) {
			$avg = IS_Scanner::next_pace_average( $avg, 50 );
		}
		$this->assertEqualsWithDelta( 50.0, $avg, 0.5 );
	}
}

<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Rest_Posts. The
 * WP-dependent parts (wp_insert_post(), the actual REST route/transient
 * glue) are exercised in a real WordPress, not here.
 */
class RestPostsTest extends TestCase {

	// ---- sanitize_status --------------------------------------------

	public function test_publisher_can_publish_directly() {
		$this->assertSame( 'publish', IS_Rest_Posts::sanitize_status( 'publish', true ) );
	}

	public function test_non_publisher_requesting_publish_is_downgraded_to_pending() {
		$this->assertSame( 'pending', IS_Rest_Posts::sanitize_status( 'publish', false ) );
	}

	public function test_non_publisher_requesting_private_is_downgraded_to_pending() {
		$this->assertSame( 'pending', IS_Rest_Posts::sanitize_status( 'private', false ) );
	}

	public function test_draft_is_always_allowed() {
		$this->assertSame( 'draft', IS_Rest_Posts::sanitize_status( 'draft', false ) );
	}

	public function test_unrecognized_status_defaults_to_draft() {
		$this->assertSame( 'draft', IS_Rest_Posts::sanitize_status( 'trash', true ) );
		$this->assertSame( 'draft', IS_Rest_Posts::sanitize_status( '', true ) );
		$this->assertSame( 'draft', IS_Rest_Posts::sanitize_status( null, true ) );
	}

	public function test_status_matching_is_case_insensitive() {
		$this->assertSame( 'publish', IS_Rest_Posts::sanitize_status( 'PUBLISH', true ) );
	}

	// ---- rate limiting ------------------------------------------------

	public function test_empty_record_is_not_rate_limited() {
		$this->assertFalse( IS_Rest_Posts::is_rate_limited( array(), 1000, 5, 3600 ) );
	}

	public function test_reaching_the_limit_within_the_window_blocks() {
		$record = array(
			'window_started_at' => 1000,
			'count'              => 5,
		);
		$this->assertTrue( IS_Rest_Posts::is_rate_limited( $record, 1500, 5, 3600 ) );
	}

	public function test_below_the_limit_within_the_window_is_allowed() {
		$record = array(
			'window_started_at' => 1000,
			'count'              => 4,
		);
		$this->assertFalse( IS_Rest_Posts::is_rate_limited( $record, 1500, 5, 3600 ) );
	}

	public function test_an_expired_window_resets_regardless_of_stored_count() {
		$record = array(
			'window_started_at' => 1000,
			'count'              => 999,
		);
		$this->assertFalse( IS_Rest_Posts::is_rate_limited( $record, 1000 + 3601, 5, 3600 ) );
	}

	public function test_record_request_starts_a_fresh_window_at_count_one() {
		$result = IS_Rest_Posts::record_request( array(), 1000, 3600 );
		$this->assertSame( 1000, $result['window_started_at'] );
		$this->assertSame( 1, $result['count'] );
	}

	public function test_record_request_increments_within_the_same_window() {
		$record = array(
			'window_started_at' => 1000,
			'count'              => 3,
		);
		$result = IS_Rest_Posts::record_request( $record, 1200, 3600 );
		$this->assertSame( 1000, $result['window_started_at'] );
		$this->assertSame( 4, $result['count'] );
	}

	public function test_record_request_starts_a_new_window_once_expired() {
		$record = array(
			'window_started_at' => 1000,
			'count'              => 30,
		);
		$result = IS_Rest_Posts::record_request( $record, 1000 + 3601, 3600 );
		$this->assertSame( 1000 + 3601, $result['window_started_at'] );
		$this->assertSame( 1, $result['count'] );
	}
}

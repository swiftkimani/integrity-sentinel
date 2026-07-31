<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic piece of IS_DB::record_finding()'s
 * upsert decision. The WP-dependent parts (the actual wpdb queries) are
 * exercised in a real WordPress, not here.
 */
class DbTest extends TestCase {

	public function test_new_status_always_reused() {
		$existing = array( 'status' => 'new', 'file_hash' => 'abc' );
		$incoming = array( 'file_hash' => 'xyz' ); // even with a different hash
		$this->assertTrue( IS_DB::should_reuse_existing_finding( $existing, $incoming ) );
	}

	public function test_acknowledged_status_always_reused() {
		$existing = array( 'status' => 'acknowledged', 'file_hash' => 'abc' );
		$incoming = array( 'file_hash' => 'xyz' );
		$this->assertTrue( IS_DB::should_reuse_existing_finding( $existing, $incoming ) );
	}

	public function test_resolved_status_is_not_reused() {
		// A resolved issue recurring deserves a fresh 'new' finding, not
		// silently reopening the old resolved row.
		$existing = array( 'status' => 'resolved', 'file_hash' => 'abc' );
		$incoming = array( 'file_hash' => 'abc' );
		$this->assertFalse( IS_DB::should_reuse_existing_finding( $existing, $incoming ) );
	}

	public function test_ignored_status_reused_when_hash_unchanged() {
		$existing = array( 'status' => 'ignored', 'file_hash' => 'abc123' );
		$incoming = array( 'file_hash' => 'abc123' );
		$this->assertTrue( IS_DB::should_reuse_existing_finding( $existing, $incoming ) );
	}

	public function test_ignored_status_not_reused_when_hash_changed() {
		// The file's content actually changed since it was ignored --
		// that's a legitimate reason for a fresh finding.
		$existing = array( 'status' => 'ignored', 'file_hash' => 'abc123' );
		$incoming = array( 'file_hash' => 'def456' );
		$this->assertFalse( IS_DB::should_reuse_existing_finding( $existing, $incoming ) );
	}

	public function test_ignored_status_reused_when_no_hash_to_compare() {
		// Hardening-style findings don't carry a file_hash -- treat as
		// still the same known issue rather than churn a new row.
		$existing = array( 'status' => 'ignored', 'file_hash' => null );
		$incoming = array();
		$this->assertTrue( IS_DB::should_reuse_existing_finding( $existing, $incoming ) );
	}
}

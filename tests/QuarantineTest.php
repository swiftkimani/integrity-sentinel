<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Quarantine: eligibility,
 * the protected-path guard, and quarantine filename generation. The
 * WP-dependent parts (the actual file move/restore/delete, DB records,
 * notifications) are exercised in a real WordPress, not here -- this is
 * the layer where getting it wrong could delete or misplace a real
 * file, so the eligibility/protection rules are the most important
 * thing to have airtight, independent test coverage for.
 */
class QuarantineTest extends TestCase {

	// ---- is_eligible_issue_type -----------------------------------------

	public function test_extra_file_issue_types_are_eligible() {
		foreach ( array( 'heuristic_match', 'php_in_uploads', 'core_unknown_file', 'plugin_unknown_file' ) as $type ) {
			$this->assertTrue( IS_Quarantine::is_eligible_issue_type( $type ), "$type should be eligible" );
		}
	}

	public function test_modified_file_issue_types_are_never_eligible() {
		// These point at a file WordPress/a plugin actually needs --
		// quarantining (removing) it would be actively harmful.
		foreach ( array( 'core_modified', 'plugin_modified' ) as $type ) {
			$this->assertFalse( IS_Quarantine::is_eligible_issue_type( $type ), "$type must never be eligible" );
		}
	}

	public function test_self_integrity_findings_are_never_eligible() {
		$this->assertFalse( IS_Quarantine::is_eligible_issue_type( 'self_integrity' ) );
	}

	public function test_hardening_findings_are_never_eligible() {
		$this->assertFalse( IS_Quarantine::is_eligible_issue_type( 'hardening' ) );
	}

	public function test_unknown_issue_type_is_not_eligible() {
		$this->assertFalse( IS_Quarantine::is_eligible_issue_type( 'made_up_type' ) );
	}

	// ---- is_protected_relative_path ---------------------------------------

	public function test_core_bootstrap_files_are_protected() {
		foreach ( array( 'wp-load.php', 'wp-config.php', 'wp-settings.php', 'index.php' ) as $path ) {
			$this->assertTrue( IS_Quarantine::is_protected_relative_path( $path, '' ), "$path should be protected" );
		}
	}

	public function test_leading_slash_is_normalized() {
		$this->assertTrue( IS_Quarantine::is_protected_relative_path( '/wp-config.php', '' ) );
	}

	public function test_files_inside_the_plugins_own_directory_are_protected() {
		$this->assertTrue( IS_Quarantine::is_protected_relative_path( 'wp-content/plugins/integrity-sentinel/includes/class-is-scanner.php', 'wp-content/plugins/integrity-sentinel' ) );
	}

	public function test_a_similarly_named_but_different_plugin_is_not_protected() {
		$this->assertFalse( IS_Quarantine::is_protected_relative_path( 'wp-content/plugins/integrity-sentinel-clone/evil.php', 'wp-content/plugins/integrity-sentinel' ) );
	}

	public function test_ordinary_dropped_file_is_not_protected() {
		$this->assertFalse( IS_Quarantine::is_protected_relative_path( 'wp-content/uploads/2024/01/shell.php', 'wp-content/plugins/integrity-sentinel' ) );
	}

	public function test_empty_plugin_dir_never_matches_anything_via_prefix() {
		$this->assertFalse( IS_Quarantine::is_protected_relative_path( 'wp-content/plugins/whatever/x.php', '' ) );
	}

	// ---- quarantine_filename -----------------------------------------------

	public function test_filename_ends_with_quarantined_extension() {
		$name = IS_Quarantine::quarantine_filename( 'wp-content/uploads/shell.php', 1700000000 );
		$this->assertStringEndsWith( '.quarantined', $name );
	}

	public function test_filename_includes_the_timestamp() {
		$name = IS_Quarantine::quarantine_filename( 'wp-content/uploads/shell.php', 1700000000 );
		$this->assertStringStartsWith( '1700000000-', $name );
	}

	public function test_filename_does_not_reveal_the_original_path() {
		$name = IS_Quarantine::quarantine_filename( 'wp-content/uploads/very-identifiable-shell-name.php', 1700000000 );
		$this->assertStringNotContainsString( 'very-identifiable-shell-name', $name );
		$this->assertStringNotContainsString( '.php', str_replace( '.quarantined', '', $name ) );
	}

	public function test_different_original_paths_yield_different_filenames_at_the_same_timestamp() {
		$a = IS_Quarantine::quarantine_filename( 'wp-content/uploads/a/shell.php', 1700000000 );
		$b = IS_Quarantine::quarantine_filename( 'wp-content/uploads/b/shell.php', 1700000000 );
		$this->assertNotSame( $a, $b );
	}

	public function test_same_original_path_yields_the_same_filename_deterministically() {
		$a = IS_Quarantine::quarantine_filename( 'wp-content/uploads/shell.php', 1700000000 );
		$b = IS_Quarantine::quarantine_filename( 'wp-content/uploads/shell.php', 1700000000 );
		$this->assertSame( $a, $b );
	}
}

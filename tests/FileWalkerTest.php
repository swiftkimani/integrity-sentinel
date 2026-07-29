<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the exclusion matching users configure in Settings.
 */
class FileWalkerTest extends TestCase {

	private function walker( array $patterns ) {
		return new IS_File_Walker( $patterns );
	}

	public function test_no_patterns_excludes_nothing() {
		$this->assertFalse( $this->walker( array() )->is_excluded( 'wp-content/uploads/photo.jpg' ) );
	}

	public function test_directory_prefix_excludes_whole_subtree() {
		$walker = $this->walker( array( 'wp-content/cache' ) );
		$this->assertTrue( $walker->is_excluded( 'wp-content/cache/page.html' ) );
		$this->assertTrue( $walker->is_excluded( 'wp-content/cache/deep/nested/file.php' ) );
		$this->assertFalse( $walker->is_excluded( 'wp-content/cachet/file.php' ) );
	}

	public function test_glob_pattern_matches_shell_style() {
		$walker = $this->walker( array( 'wp-content/uploads/backup*' ) );
		$this->assertTrue( $walker->is_excluded( 'wp-content/uploads/backup-2026.zip' ) );
		$this->assertFalse( $walker->is_excluded( 'wp-content/uploads/photo.jpg' ) );
	}

	public function test_blank_lines_in_settings_are_ignored() {
		$walker = $this->walker( array( '', '   ', 'wp-content/cache' ) );
		$this->assertTrue( $walker->is_excluded( 'wp-content/cache/x' ) );
		$this->assertFalse( $walker->is_excluded( 'index.php' ) );
	}
}

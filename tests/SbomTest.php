<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure diffing logic in IS_SBOM. generate()/
 * refresh_snapshot() themselves need get_plugins()/wp_get_theme()/
 * get_option() (WP-dependent) and are exercised in a real WordPress,
 * not here.
 */
class SbomTest extends TestCase {

	public function test_no_diff_for_identical_lists() {
		$components = array( array( 'name' => 'akismet', 'version' => '5.3' ) );
		$diff       = IS_SBOM::diff( $components, $components );
		$this->assertFalse( IS_SBOM::has_diff( $diff ) );
	}

	public function test_detects_an_added_component() {
		$previous = array();
		$current  = array( array( 'name' => 'new-plugin', 'version' => '1.0' ) );
		$diff     = IS_SBOM::diff( $previous, $current );
		$this->assertSame( array( 'new-plugin' ), $diff['added'] );
		$this->assertTrue( IS_SBOM::has_diff( $diff ) );
	}

	public function test_detects_a_removed_component() {
		$previous = array( array( 'name' => 'old-plugin', 'version' => '1.0' ) );
		$current  = array();
		$diff     = IS_SBOM::diff( $previous, $current );
		$this->assertSame( array( 'old-plugin' ), $diff['removed'] );
	}

	public function test_detects_a_version_change() {
		$previous = array( array( 'name' => 'akismet', 'version' => '5.2' ) );
		$current  = array( array( 'name' => 'akismet', 'version' => '5.3' ) );
		$diff     = IS_SBOM::diff( $previous, $current );
		$this->assertSame( array( array( 'name' => 'akismet', 'from' => '5.2', 'to' => '5.3' ) ), $diff['changed'] );
	}

	public function test_has_diff_is_false_for_empty_diff() {
		$diff = array( 'added' => array(), 'removed' => array(), 'changed' => array() );
		$this->assertFalse( IS_SBOM::has_diff( $diff ) );
	}
}

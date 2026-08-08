<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Deception. The WP-dependent
 * parts (the template_redirect/REST hooks, temp-banning, wp_die()) are
 * exercised in a real WordPress, not here.
 */
class DeceptionTest extends TestCase {

	public function test_recognizes_every_configured_honeypot_path() {
		foreach ( IS_Deception::honeypot_paths() as $path ) {
			$this->assertTrue( IS_Deception::is_honeypot_path( $path ) );
		}
	}

	public function test_does_not_flag_a_real_looking_path() {
		$this->assertFalse( IS_Deception::is_honeypot_path( '/wp-content/uploads/2026/01/photo.jpg' ) );
		$this->assertFalse( IS_Deception::is_honeypot_path( '/about-us' ) );
	}

	public function test_does_not_flag_an_empty_path() {
		$this->assertFalse( IS_Deception::is_honeypot_path( '' ) );
	}
}

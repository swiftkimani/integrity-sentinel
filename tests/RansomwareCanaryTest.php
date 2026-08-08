<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Ransomware_Canary
 * (changed-ratio math, alarm thresholding, scope classification). The
 * WP-dependent glue (per-file hashing, wp_upload_dir()/WP_CONTENT_DIR
 * resolution) is exercised in a real WordPress, not here.
 */
class RansomwareCanaryTest extends TestCase {

	// ---- changed_ratio ---------------------------------------------------

	public function test_changed_ratio_computes_fraction() {
		$this->assertSame( 0.5, IS_Ransomware_Canary::changed_ratio( 50, 100 ) );
	}

	public function test_changed_ratio_zero_total_is_zero() {
		$this->assertSame( 0.0, IS_Ransomware_Canary::changed_ratio( 5, 0 ) );
		$this->assertSame( 0.0, IS_Ransomware_Canary::changed_ratio( 5, -1 ) );
	}

	public function test_changed_ratio_never_negative() {
		$this->assertSame( 0.0, IS_Ransomware_Canary::changed_ratio( -5, 10 ) );
	}

	// ---- is_velocity_alarming ----------------------------------------------

	public function test_alarming_when_over_threshold_and_min_files_met() {
		$this->assertTrue( IS_Ransomware_Canary::is_velocity_alarming( 0.6, 100, 50, 0.5 ) );
	}

	public function test_not_alarming_when_under_threshold() {
		$this->assertFalse( IS_Ransomware_Canary::is_velocity_alarming( 0.4, 100, 50, 0.5 ) );
	}

	public function test_not_alarming_when_under_minimum_files_even_at_high_ratio() {
		$this->assertFalse( IS_Ransomware_Canary::is_velocity_alarming( 1.0, 2, 50, 0.5 ) );
	}

	public function test_alarming_at_exact_threshold() {
		$this->assertTrue( IS_Ransomware_Canary::is_velocity_alarming( 0.5, 100, 50, 0.5 ) );
	}

	// ---- classify_scope --------------------------------------------------------

	private function sample_prefixes() {
		return array(
			'uploads'    => 'wp-content/uploads',
			'themes'     => 'wp-content/themes',
			'mu_plugins' => 'wp-content/mu-plugins',
		);
	}

	public function test_classify_scope_matches_uploads() {
		$this->assertSame( 'uploads', IS_Ransomware_Canary::classify_scope( 'wp-content/uploads/2026/08/photo.jpg', $this->sample_prefixes() ) );
	}

	public function test_classify_scope_matches_themes() {
		$this->assertSame( 'themes', IS_Ransomware_Canary::classify_scope( 'wp-content/themes/twentytwentyfive/style.css', $this->sample_prefixes() ) );
	}

	public function test_classify_scope_matches_mu_plugins() {
		$this->assertSame( 'mu_plugins', IS_Ransomware_Canary::classify_scope( 'wp-content/mu-plugins/loader.php', $this->sample_prefixes() ) );
	}

	public function test_classify_scope_no_match_outside_tracked_scopes() {
		$this->assertNull( IS_Ransomware_Canary::classify_scope( 'wp-content/plugins/integrity-sentinel/includes/class-is-scanner.php', $this->sample_prefixes() ) );
	}

	public function test_classify_scope_does_not_match_a_lookalike_directory() {
		// 'wp-content/uploads-old' should not match the 'wp-content/uploads' prefix.
		$this->assertNull( IS_Ransomware_Canary::classify_scope( 'wp-content/uploads-old/file.txt', $this->sample_prefixes() ) );
	}

	public function test_classify_scope_ignores_empty_prefixes() {
		$prefixes = array(
			'uploads'    => 'wp-content/uploads',
			'themes'     => '',
			'mu_plugins' => null,
		);
		$this->assertNull( IS_Ransomware_Canary::classify_scope( 'wp-content/themes/x/style.css', $prefixes ) );
	}
}

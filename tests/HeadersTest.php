<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Headers. The WP-dependent
 * parts (actual header()/wp_die() calls, hook registration) are
 * exercised in a real WordPress, not here.
 */
class HeadersTest extends TestCase {

	// ---- security_header_lines --------------------------------------

	public function test_no_headers_when_everything_off() {
		$headers = IS_Headers::security_header_lines(
			array(
				'security_headers'     => 0,
				'prevent_clickjacking' => 0,
			)
		);
		$this->assertSame( array(), $headers );
	}

	public function test_security_headers_include_nosniff_and_referrer_policy() {
		$headers = IS_Headers::security_header_lines(
			array(
				'security_headers'     => 1,
				'prevent_clickjacking' => 0,
			)
		);
		$this->assertSame( 'nosniff', $headers['X-Content-Type-Options'] );
		$this->assertArrayHasKey( 'Referrer-Policy', $headers );
		$this->assertArrayNotHasKey( 'X-Frame-Options', $headers );
	}

	public function test_clickjacking_headers_use_sameorigin_not_deny() {
		$headers = IS_Headers::security_header_lines(
			array(
				'security_headers'     => 0,
				'prevent_clickjacking' => 1,
			)
		);
		$this->assertSame( 'SAMEORIGIN', $headers['X-Frame-Options'] );
		$this->assertStringContainsString( "'self'", $headers['Content-Security-Policy'] );
	}

	public function test_no_csp_header_when_both_clickjacking_and_policy_are_off() {
		$headers = IS_Headers::security_header_lines(
			array(
				'prevent_clickjacking'    => 0,
				'content_security_policy' => '',
			)
		);
		$this->assertArrayNotHasKey( 'Content-Security-Policy', $headers );
		$this->assertArrayNotHasKey( 'Content-Security-Policy-Report-Only', $headers );
	}

	// ---- build_csp -------------------------------------------------------

	public function test_build_csp_is_empty_when_nothing_enabled() {
		$this->assertSame( '', IS_Headers::build_csp( array( 'prevent_clickjacking' => 0, 'content_security_policy' => '' ) ) );
	}

	public function test_build_csp_falls_back_to_bare_frame_ancestors() {
		$this->assertSame(
			"frame-ancestors 'self'",
			IS_Headers::build_csp( array( 'prevent_clickjacking' => 1, 'content_security_policy' => '' ) )
		);
	}

	public function test_build_csp_uses_the_custom_policy_verbatim_when_clickjacking_is_off() {
		$policy = "default-src 'self'; object-src 'none';";
		$this->assertSame(
			$policy,
			IS_Headers::build_csp( array( 'prevent_clickjacking' => 0, 'content_security_policy' => $policy ) )
		);
	}

	public function test_build_csp_folds_frame_ancestors_into_a_custom_policy() {
		$result = IS_Headers::build_csp(
			array(
				'prevent_clickjacking'    => 1,
				'content_security_policy' => "default-src 'self'; object-src 'none';",
			)
		);
		$this->assertStringContainsString( "default-src 'self'", $result );
		$this->assertStringContainsString( "frame-ancestors 'self'", $result );
	}

	public function test_build_csp_does_not_duplicate_an_existing_frame_ancestors_directive() {
		$policy = "default-src 'self'; frame-ancestors 'none';";
		$result = IS_Headers::build_csp( array( 'prevent_clickjacking' => 1, 'content_security_policy' => $policy ) );
		$this->assertSame( 1, substr_count( $result, 'frame-ancestors' ) );
		// The admin's own directive wins -- not silently overridden.
		$this->assertStringContainsString( "frame-ancestors 'none'", $result );
	}

	public function test_security_header_lines_uses_report_only_header_name_when_configured() {
		$headers = IS_Headers::security_header_lines(
			array(
				'prevent_clickjacking'    => 0,
				'content_security_policy' => "default-src 'self';",
				'csp_report_only'         => 1,
			)
		);
		$this->assertArrayHasKey( 'Content-Security-Policy-Report-Only', $headers );
		$this->assertArrayNotHasKey( 'Content-Security-Policy', $headers );
	}

	public function test_security_header_lines_uses_enforcing_header_name_when_report_only_is_off() {
		$headers = IS_Headers::security_header_lines(
			array(
				'prevent_clickjacking'    => 0,
				'content_security_policy' => "default-src 'self';",
				'csp_report_only'         => 0,
			)
		);
		$this->assertArrayHasKey( 'Content-Security-Policy', $headers );
		$this->assertArrayNotHasKey( 'Content-Security-Policy-Report-Only', $headers );
	}

	// ---- suggested_csp -----------------------------------------------------

	public function test_suggested_csp_blocks_object_embeds_and_locks_base_uri() {
		$csp = IS_Headers::suggested_csp();
		$this->assertStringContainsString( "object-src 'none'", $csp );
		$this->assertStringContainsString( "base-uri 'self'", $csp );
	}

	// ---- generator_value ---------------------------------------------

	public function test_generator_kept_when_hide_version_off() {
		$this->assertSame( '<meta name="generator" content="WordPress 6.7">', IS_Headers::generator_value( '<meta name="generator" content="WordPress 6.7">', array( 'hide_wp_version' => 0 ) ) );
	}

	public function test_generator_stripped_when_hide_version_on() {
		$this->assertSame( '', IS_Headers::generator_value( '<meta name="generator" content="WordPress 6.7">', array( 'hide_wp_version' => 1 ) ) );
	}

	// ---- strip_version_query_string -----------------------------------

	public function test_strips_trailing_ver_argument() {
		$this->assertSame( '/wp-content/themes/x/style.css', IS_Headers::strip_version_query_string( '/wp-content/themes/x/style.css?ver=6.7' ) );
	}

	public function test_strips_ver_argument_among_others_and_keeps_the_rest() {
		$this->assertSame( '/script.js?foo=bar', IS_Headers::strip_version_query_string( '/script.js?foo=bar&ver=1.2.3' ) );
	}

	public function test_leaves_url_without_ver_untouched() {
		$url = '/wp-content/themes/x/style.css?foo=bar';
		$this->assertSame( $url, IS_Headers::strip_version_query_string( $url ) );
	}

	public function test_leaves_url_without_any_query_untouched() {
		$url = '/wp-content/themes/x/style.css';
		$this->assertSame( $url, IS_Headers::strip_version_query_string( $url ) );
	}

	public function test_preserves_fragment_after_stripping_ver() {
		$this->assertSame( '/a.js#frag', IS_Headers::strip_version_query_string( '/a.js?ver=1#frag' ) );
	}

	// ---- default settings ----------------------------------------------

	public function test_default_settings_enable_safe_headers_but_not_breaking_ones() {
		$defaults = IS_Headers::default_settings();
		$this->assertSame( 1, $defaults['security_headers'] );
		$this->assertSame( 1, $defaults['prevent_clickjacking'] );
		$this->assertSame( 1, $defaults['hide_wp_version'] );
		$this->assertSame( 1, $defaults['hide_meta_fingerprints'] );
		$this->assertSame( 0, $defaults['disable_xmlrpc'] );
		$this->assertSame( 0, $defaults['disable_feeds'] );
		$this->assertSame( '', $defaults['content_security_policy'] );
	}

	// ---- audit_score -----------------------------------------------------

	public function test_full_default_settings_score_high_but_not_full() {
		// Defaults enable everything except an enforced CSP (report-only
		// is the safe default), so the score should be one short of max.
		$score = IS_Headers::audit_score( IS_Headers::default_settings() );
		$this->assertSame( $score['max'] - 1, $score['score'] );
	}

	public function test_enforced_csp_reaches_full_score() {
		$settings                              = IS_Headers::default_settings();
		$settings['content_security_policy']   = "default-src 'self';";
		$settings['csp_report_only']           = 0;
		$score                                 = IS_Headers::audit_score( $settings );
		$this->assertSame( $score['max'], $score['score'] );
	}

	public function test_everything_off_scores_zero() {
		$settings = array(
			'security_headers'        => 0,
			'prevent_clickjacking'    => 0,
			'hide_wp_version'         => 0,
			'hide_meta_fingerprints'  => 0,
			'content_security_policy' => '',
			'csp_report_only'         => 1,
		);
		$score = IS_Headers::audit_score( $settings );
		$this->assertSame( 0, $score['score'] );
	}

	public function test_frame_ancestors_in_csp_counts_as_clickjacking_protection() {
		$settings = array(
			'security_headers'        => 0,
			'prevent_clickjacking'    => 0,
			'hide_wp_version'         => 0,
			'hide_meta_fingerprints'  => 0,
			'content_security_policy' => "frame-ancestors 'self';",
			'csp_report_only'         => 0,
		);
		$score = IS_Headers::audit_score( $settings );
		$clickjacking = null;
		foreach ( $score['items'] as $item ) {
			if ( 'clickjacking' === $item['key'] ) {
				$clickjacking = $item['passed'];
			}
		}
		$this->assertTrue( $clickjacking );
	}
}

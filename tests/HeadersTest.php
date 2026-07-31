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
		$this->assertSame( 0, $defaults['disable_xmlrpc'] );
		$this->assertSame( 0, $defaults['disable_feeds'] );
	}
}

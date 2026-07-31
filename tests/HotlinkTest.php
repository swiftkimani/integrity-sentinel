<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Hotlink. The WP-dependent
 * parts (the actual .htaccess file writes) are exercised in a real
 * WordPress, not here.
 */
class HotlinkTest extends TestCase {

	// ---- parse_domain_list ---------------------------------------------

	public function test_parses_one_domain_per_line() {
		$this->assertSame( array( 'cdn.example.com', 'partner.test' ), IS_Hotlink::parse_domain_list( "cdn.example.com\npartner.test" ) );
	}

	public function test_strips_scheme_from_a_pasted_url() {
		$this->assertSame( array( 'example.com' ), IS_Hotlink::parse_domain_list( 'https://example.com' ) );
	}

	public function test_strips_path_from_a_pasted_url() {
		$this->assertSame( array( 'example.com' ), IS_Hotlink::parse_domain_list( 'https://example.com/some/page' ) );
	}

	public function test_ignores_blank_lines_and_comments() {
		$this->assertSame( array( 'example.com' ), IS_Hotlink::parse_domain_list( "\nexample.com # our CDN\n\n" ) );
	}

	// ---- block_rules -----------------------------------------------------

	public function test_block_rules_are_marker_delimited() {
		$rules = IS_Hotlink::block_rules( 'example.com', array() );
		$this->assertStringStartsWith( IS_Hotlink::BLOCK_BEGIN, $rules );
		$this->assertStringContainsString( IS_Hotlink::BLOCK_END, $rules );
	}

	public function test_block_rules_always_allow_the_home_host() {
		// preg_quote()'d in the output, hence the escaped dot.
		$rules = IS_Hotlink::block_rules( 'example.com', array() );
		$this->assertStringContainsString( 'example\.com', $rules );
	}

	public function test_block_rules_include_allowed_domains() {
		$rules = IS_Hotlink::block_rules( 'example.com', array( 'cdn.example.com' ) );
		$this->assertStringContainsString( 'cdn\.example\.com', $rules );
	}

	public function test_block_rules_always_allow_empty_referer() {
		$rules = IS_Hotlink::block_rules( 'example.com', array() );
		$this->assertStringContainsString( 'HTTP_REFERER} !^$', $rules );
	}

	public function test_block_rules_cover_common_image_extensions() {
		$rules = IS_Hotlink::block_rules( 'example.com', array() );
		foreach ( array( 'jpe?g', 'png', 'gif', 'webp', 'svg' ) as $ext ) {
			$this->assertStringContainsString( $ext, $rules );
		}
	}

	public function test_nginx_snippet_lists_home_and_allowed_hosts() {
		$snippet = IS_Hotlink::nginx_snippet( 'example.com', array( 'cdn.example.com' ) );
		$this->assertStringContainsString( 'example.com', $snippet );
		$this->assertStringContainsString( 'cdn.example.com', $snippet );
		$this->assertStringContainsString( 'invalid_referer', $snippet );
	}
}

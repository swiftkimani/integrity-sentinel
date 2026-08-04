<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Asset_Cloak (alias
 * sanitization, URL rewriting, .htaccess block text). The WP-dependent
 * glue (the URL filters, the actual file read/write) is exercised in a
 * real WordPress, not here.
 */
class AssetCloakTest extends TestCase {

	// ---- sanitize_alias --------------------------------------------------

	public function test_lowercases_and_trims_slashes() {
		$this->assertSame( 'my-app', IS_Asset_Cloak::sanitize_alias( '/My-App/' ) );
	}

	public function test_strips_disallowed_characters() {
		$this->assertSame( 'app123', IS_Asset_Cloak::sanitize_alias( 'app 123!?' ) );
	}

	public function test_rejects_reserved_core_paths() {
		foreach ( array( 'wp', 'wp-content', 'wp-includes', 'wp-admin', 'content', 'includes', 'admin', 'wp-json', 'wp-login' ) as $reserved ) {
			$this->assertSame( '', IS_Asset_Cloak::sanitize_alias( $reserved ) );
		}
	}

	public function test_empty_input_yields_empty_alias() {
		$this->assertSame( '', IS_Asset_Cloak::sanitize_alias( '   ' ) );
	}

	// ---- rewrite_asset_url ------------------------------------------------

	public function test_rewrites_wp_content_and_wp_includes() {
		$this->assertSame(
			'https://example.com/app-content/themes/x/style.css',
			IS_Asset_Cloak::rewrite_asset_url( 'https://example.com/wp-content/themes/x/style.css', 'app', 'example.com' )
		);
		$this->assertSame(
			'https://example.com/app-includes/js/jquery/jquery.js',
			IS_Asset_Cloak::rewrite_asset_url( 'https://example.com/wp-includes/js/jquery/jquery.js', 'app', 'example.com' )
		);
	}

	public function test_rewrites_relative_and_protocol_relative_urls() {
		$this->assertSame( '/app-content/x.css', IS_Asset_Cloak::rewrite_asset_url( '/wp-content/x.css', 'app', 'example.com' ) );
		$this->assertSame(
			'//example.com/app-content/x.css',
			IS_Asset_Cloak::rewrite_asset_url( '//example.com/wp-content/x.css', 'app', 'example.com' )
		);
	}

	public function test_leaves_a_different_hosts_url_untouched() {
		$url = 'https://cdn.example.net/wp-content/x.js';
		$this->assertSame( $url, IS_Asset_Cloak::rewrite_asset_url( $url, 'app', 'example.com' ) );
	}

	public function test_leaves_url_untouched_when_alias_unset() {
		$url = 'https://example.com/wp-content/x.css';
		$this->assertSame( $url, IS_Asset_Cloak::rewrite_asset_url( $url, '', 'example.com' ) );
	}

	public function test_leaves_unrelated_urls_untouched() {
		$url = 'https://example.com/about-us/';
		$this->assertSame( $url, IS_Asset_Cloak::rewrite_asset_url( $url, 'app', 'example.com' ) );
	}

	// ---- .htaccess block --------------------------------------------------

	public function test_block_rules_include_the_alias() {
		$rules = IS_Asset_Cloak::block_rules( 'app' );
		$this->assertStringContainsString( 'RewriteRule ^app-content/(.*)$ wp-content/$1 [L]', $rules );
		$this->assertStringContainsString( 'RewriteRule ^app-includes/(.*)$ wp-includes/$1 [L]', $rules );
		$this->assertStringContainsString( IS_Asset_Cloak::BLOCK_BEGIN, $rules );
		$this->assertStringContainsString( IS_Asset_Cloak::BLOCK_END, $rules );
	}

	public function test_strip_block_removes_only_our_block() {
		$content = "SomeHostingRule On\n" . IS_Asset_Cloak::block_rules( 'app' ) . "\n# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n";
		$stripped = IS_Asset_Cloak::strip_block( $content );
		$this->assertStringNotContainsString( IS_Asset_Cloak::BLOCK_BEGIN, $stripped );
		$this->assertStringContainsString( 'SomeHostingRule On', $stripped );
		$this->assertStringContainsString( '# BEGIN WordPress', $stripped );
	}

	public function test_strip_block_is_a_noop_when_our_block_is_absent() {
		$content = "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n";
		$this->assertSame( $content, IS_Asset_Cloak::strip_block( $content ) );
	}
}

<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Login_Design (CSS/HTML
 * assembly). The WP-dependent glue (login_enqueue_scripts, the settings
 * filters, the preview transient) is exercised in a real WordPress, not
 * here -- see class-is-login.php's own note on this split.
 */
class LoginDesignTest extends TestCase {

	// ---- sanitize_css_for_style_tag ------------------------------------

	public function test_neutralizes_style_tag_breakout() {
		$css = IS_Login_Design::sanitize_css_for_style_tag( 'body{}</style><script>alert(1)</script>' );
		$this->assertStringNotContainsString( '</style>', $css );
		$this->assertStringContainsString( '<\\/style>', $css );
	}

	public function test_leaves_ordinary_css_untouched() {
		$css = 'body.login{background:#fff;}';
		$this->assertSame( $css, IS_Login_Design::sanitize_css_for_style_tag( $css ) );
	}

	// ---- is_hex_color ----------------------------------------------------

	public function test_accepts_valid_hex_colors() {
		foreach ( array( '#fff', '#ffffff', '#FF00aa', '#12345678' ) as $color ) {
			$this->assertTrue( IS_Login_Design::is_hex_color( $color ), $color );
		}
	}

	public function test_rejects_invalid_hex_colors() {
		foreach ( array( 'red', '#gggggg', 'ffffff', '#12345', 'javascript:alert(1)' ) as $color ) {
			$this->assertFalse( IS_Login_Design::is_hex_color( $color ), $color );
		}
	}

	// ---- clamp_radius ------------------------------------------------------

	public function test_clamps_radius_to_a_sane_range() {
		$this->assertSame( 0, IS_Login_Design::clamp_radius( -5 ) );
		$this->assertSame( 40, IS_Login_Design::clamp_radius( 999 ) );
		$this->assertSame( 14, IS_Login_Design::clamp_radius( 14 ) );
	}

	public function test_clamp_radius_coerces_non_numeric_input() {
		$this->assertSame( 0, IS_Login_Design::clamp_radius( 'not-a-number' ) );
	}

	// ---- is_http_url -----------------------------------------------------

	public function test_accepts_http_and_https_urls() {
		$this->assertTrue( IS_Login_Design::is_http_url( 'https://example.com/x.png' ) );
		$this->assertTrue( IS_Login_Design::is_http_url( 'http://example.com/x.png' ) );
	}

	public function test_rejects_non_http_schemes() {
		foreach ( array( 'javascript:alert(1)', 'data:text/html,x', 'ftp://example.com/x', '' ) as $url ) {
			$this->assertFalse( IS_Login_Design::is_http_url( $url ), $url );
		}
	}

	// ---- is_split_template -------------------------------------------------

	public function test_split_templates_have_a_hero_panel() {
		foreach ( array( 'sunrise', 'aurora-night', 'bubblegum' ) as $template ) {
			$this->assertTrue( IS_Login_Design::is_split_template( $template ), $template );
		}
	}

	public function test_minimal_is_not_a_split_template() {
		$this->assertFalse( IS_Login_Design::is_split_template( 'minimal' ) );
		$this->assertFalse( IS_Login_Design::is_split_template( 'unknown-key' ) );
	}

	// ---- build_css -----------------------------------------------------------

	public function test_build_css_includes_the_chosen_accent_color_and_radius() {
		$css = IS_Login_Design::build_css(
			array(
				'template'      => 'minimal',
				'primary_color' => '#123456',
				'border_radius' => 20,
			)
		);
		$this->assertStringContainsString( '--is-login-color:#123456', $css );
		$this->assertStringContainsString( '--is-login-radius:20px', $css );
	}

	public function test_build_css_falls_back_to_defaults_for_invalid_color() {
		$css = IS_Login_Design::build_css( array( 'primary_color' => 'not-a-color' ) );
		$this->assertStringContainsString( '--is-login-color:#6366f1', $css );
	}

	public function test_build_css_falls_back_to_default_template_for_unknown_key() {
		$default_template = IS_Login_Design::default_settings()['template'];
		$css_unknown       = IS_Login_Design::build_css( array( 'template' => 'does-not-exist' ) );
		$css_default       = IS_Login_Design::build_css( array( 'template' => $default_template ) );
		$this->assertSame( $css_default, $css_unknown );
	}

	public function test_build_css_only_accepts_http_s_logo_urls() {
		$safe   = IS_Login_Design::build_css( array( 'logo_url' => 'https://example.com/logo.png' ) );
		$unsafe = IS_Login_Design::build_css( array( 'logo_url' => 'javascript:alert(1)' ) );
		$this->assertStringContainsString( 'background-image:url("https://example.com/logo.png")', $safe );
		$this->assertStringNotContainsString( 'javascript:alert(1)', $unsafe );
	}

	public function test_build_css_strips_quotes_from_logo_url_to_prevent_style_breakout() {
		// Even though logo_url is already esc_url_raw()'d + scheme-checked
		// at save time, build_css() defends independently: an https:// URL
		// that smuggles a closing quote (e.g. a crafted query string)
		// could otherwise escape the url("...") context and inject
		// arbitrary CSS/attempt further breakout into the <style> tag.
		$css = IS_Login_Design::build_css(
			array( 'logo_url' => 'https://evil.example/x");}body{background:url(https://evil.example/track.gif)}/*' )
		);
		$this->assertStringNotContainsString( '");}body', $css );
		$this->assertStringContainsString( 'url("https://evil.example/x);}body{background:url(https://evil.example/track.gif)}/*")', $css );
	}

	public function test_build_css_strips_quotes_from_hero_image_url() {
		$css = IS_Login_Design::build_css(
			array(
				'template'       => 'sunrise',
				'hero_image_url' => 'https://evil.example/x");}body{color:red}/*',
			)
		);
		$this->assertStringNotContainsString( '");}body', $css );
	}

	public function test_build_css_hides_generated_blobs_when_a_hero_image_is_set() {
		$css = IS_Login_Design::build_css(
			array(
				'template'       => 'sunrise',
				'hero_image_url' => 'https://example.com/photo.jpg',
			)
		);
		$this->assertStringContainsString( 'url("https://example.com/photo.jpg")', $css );
		$this->assertStringContainsString( '.is-login-hero .is-login-blob{display:none;}', $css );
	}

	public function test_build_css_only_adds_split_layout_for_split_templates() {
		$split   = IS_Login_Design::build_css( array( 'template' => 'sunrise' ) );
		$minimal = IS_Login_Design::build_css( array( 'template' => 'minimal' ) );
		$this->assertStringContainsString( '.is-login-hero{', $split );
		$this->assertStringNotContainsString( '.is-login-hero{', $minimal );
	}

	public function test_build_css_always_suppresses_the_default_wordpress_logo_mark() {
		// Unconditional -- not just when a custom logo is set -- per the
		// "no mention of WordPress anywhere on this page" requirement.
		$css = IS_Login_Design::build_css( array() );
		$this->assertStringContainsString( 'background-image:none', $css );
	}

	public function test_build_css_appends_custom_css_with_breakout_guard() {
		$css = IS_Login_Design::build_css( array( 'custom_css' => '.foo{}</style><script>x</script>' ) );
		$this->assertStringContainsString( '.foo{}', $css );
		$this->assertStringNotContainsString( '</style><script>', $css );
	}

	public function test_build_css_is_stable_for_each_built_in_template() {
		foreach ( array_keys( IS_Login_Design::templates() ) as $template ) {
			$css = IS_Login_Design::build_css( array( 'template' => $template ) );
			$this->assertNotSame( '', trim( $css ), $template );
		}
	}

	// ---- build_hero_html --------------------------------------------------

	public function test_build_hero_html_escapes_heading_and_subheading() {
		$html = IS_Login_Design::build_hero_html(
			array(
				'hero_heading'    => '<script>alert(1)</script>',
				'hero_subheading' => 'Tom & Jerry "quoted"',
			)
		);
		$this->assertStringNotContainsString( '<script>alert(1)</script>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
		$this->assertStringContainsString( 'Tom &amp; Jerry &quot;quoted&quot;', $html );
	}

	public function test_build_hero_html_omits_empty_heading_and_subheading() {
		$html = IS_Login_Design::build_hero_html( array( 'hero_heading' => '', 'hero_subheading' => '' ) );
		$this->assertStringNotContainsString( '<h2>', $html );
		$this->assertStringNotContainsString( '<p>', $html );
	}

	public function test_build_hero_html_shows_generated_blobs_without_an_image() {
		$html = IS_Login_Design::build_hero_html( array( 'hero_image_url' => '' ) );
		$this->assertStringContainsString( 'is-login-blob', $html );
	}

	public function test_build_hero_html_omits_generated_blobs_with_an_image() {
		$html = IS_Login_Design::build_hero_html( array( 'hero_image_url' => 'https://example.com/photo.jpg' ) );
		$this->assertStringNotContainsString( 'is-login-blob', $html );
	}

	public function test_build_hero_html_is_marked_decorative() {
		$html = IS_Login_Design::build_hero_html( array() );
		$this->assertStringContainsString( 'aria-hidden="true"', $html );
	}
}

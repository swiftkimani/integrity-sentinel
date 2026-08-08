<?php
/**
 * Cosmetic customization layer for wp-login.php: built-in templates, an
 * accent-color/logo/corner-radius/hero customizer, custom CSS, and an
 * optional custom HTML banner.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cosmetic layer for wp-login.php: ten built-in templates (one plain
 * centered card, nine "split-screen" designs with a decorative hero
 * panel down either side, in the style of modern SaaS sign-in pages --
 * including an interactive image Carousel with dot/arrow navigation, a
 * monospace Terminal look, and a tilted-photo Polaroid style), a
 * customizer (accent color, logo, corner radius, hero position/heading/
 * subheading/image/gallery) layered on top, an escape hatch for raw
 * custom CSS, and an optional sanitized HTML banner above the form.
 *
 * Two things this class deliberately owns beyond styling:
 *  - It scrubs every WordPress-branding surface on the login page (the
 *    default logo mark, its link target, and the <title> tag) when
 *    "Hide WordPress branding" is on -- the default, and not gated on a
 *    custom logo being set -- see header_url()/header_text()/
 *    filter_login_title().
 *  - It supports previewing an *unsaved* draft: settings() transparently
 *    swaps in a short-lived per-admin transient when the request carries
 *    `?is_preview=1` from a signed-in admin -- see preview_override().
 *    That gives a real preview of in-progress edits without saving them.
 *    The draft is written by IS_Ajax::preview_login_design(), which
 *    reuses IS_Admin's real sanitizer, so a preview can never render
 *    anything a genuine save wouldn't also allow.
 *
 * Sanitization on write, not on read: every value stored in
 * `is_login_design_settings` (or in the preview transient) has already
 * been validated/escaped by IS_Admin's sanitizer (hex colors,
 * esc_url_raw'd URLs, wp_kses_post'd HTML, a </style>-breakout guard on
 * the CSS box, plain-text hero copy). build_css()/build_hero_html()
 * re-validate shape defensively (in case the option was ever hand-edited
 * in the database) but otherwise stay pure WordPress-call-free string
 * assembly, so they're unit-testable the same way the rest of this
 * plugin's pure logic is -- see class-is-login.php's own note on this.
 */
class IS_Login_Design {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Returns the singleton instance, creating and hooking it up on first call.
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	/**
	 * Registers the WordPress hooks that render and customize the login page.
	 */
	private function hooks() {
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue' ) );
		add_filter( 'login_headerurl', array( $this, 'header_url' ) );
		add_filter( 'login_headertext', array( $this, 'header_text' ) );
		add_filter( 'login_title', array( $this, 'filter_login_title' ) );
		add_filter( 'login_message', array( $this, 'inject_custom_html' ) );
	}

	// ===================================================================
	// Settings
	// ===================================================================

	/**
	 * The full set of built-in login-page templates, keyed by slug.
	 */
	public static function templates() {
		return array(
			'minimal'      => __( 'Minimal', 'integrity-sentinel' ),
			'sunrise'      => __( 'Sunrise', 'integrity-sentinel' ),
			'aurora-night' => __( 'Aurora Night', 'integrity-sentinel' ),
			'bubblegum'    => __( 'Bubblegum', 'integrity-sentinel' ),
			'forest'       => __( 'Forest', 'integrity-sentinel' ),
			'monochrome'   => __( 'Monochrome', 'integrity-sentinel' ),
			'ocean'        => __( 'Ocean', 'integrity-sentinel' ),
			'carousel'     => __( 'Carousel', 'integrity-sentinel' ),
			'terminal'     => __( 'Terminal', 'integrity-sentinel' ),
			'polaroid'     => __( 'Polaroid', 'integrity-sentinel' ),
		);
	}

	/**
	 * Pure: which templates use the split-screen hero-panel layout (everything but the plain card).
	 *
	 * @param string $template Template slug.
	 */
	public static function is_split_template( $template ) {
		return in_array( $template, array( 'sunrise', 'aurora-night', 'bubblegum', 'forest', 'monochrome', 'ocean', 'carousel', 'terminal', 'polaroid' ), true );
	}

	/**
	 * Default settings, used to fill in anything missing from the stored option.
	 */
	public static function default_settings() {
		return array(
			'template'           => 'sunrise',
			'logo_url'           => '',
			'primary_color'      => '#6366f1',
			'border_radius'      => 18,
			'hero_position'      => 'left',
			'hero_heading'       => 'Welcome back',
			'hero_subheading'    => '',
			'hero_image_url'     => '',
			'hero_gallery'       => array(),
			'carousel_indicator' => 'bars',
			'hide_branding'      => 1,
			'custom_css'         => '',
			'custom_html'        => '',
		);
	}

	/**
	 * Pure: the three hero placements. 'left'/'right' are the classic
	 * split-screen (artwork one side, form the other); 'center' floats the
	 * form as a frosted card dead-center over a full-bleed hero (gradient,
	 * photo, or the live carousel) -- see center_layout_css()/center_hero_css().
	 */
	public static function hero_positions() {
		return array( 'left', 'right', 'center' );
	}

	/** Pure: the selectable carousel slide-indicator styles. */
	public static function carousel_indicators() {
		return array(
			'bars'       => __( 'Bars', 'integrity-sentinel' ),
			'dots'       => __( 'Dots', 'integrity-sentinel' ),
			'numbers'    => __( 'Numbers', 'integrity-sentinel' ),
			'thumbnails' => __( 'Thumbnails', 'integrity-sentinel' ),
			'none'       => __( 'None (arrows only)', 'integrity-sentinel' ),
		);
	}

	/**
	 * Pure: validated carousel indicator style, defaulting to 'bars'.
	 *
	 * @param array $settings Settings array (shaped like default_settings()).
	 */
	public static function carousel_indicator( array $settings ) {
		$value = isset( $settings['carousel_indicator'] ) ? (string) $settings['carousel_indicator'] : 'bars';
		return array_key_exists( $value, self::carousel_indicators() ) ? $value : 'bars';
	}

	/**
	 * Pure: validated hero placement, defaulting to 'left'.
	 *
	 * @param array $settings Settings array (shaped like default_settings()).
	 */
	public static function hero_position( array $settings ) {
		$value = isset( $settings['hero_position'] ) ? (string) $settings['hero_position'] : 'left';
		return in_array( $value, self::hero_positions(), true ) ? $value : 'left';
	}

	/**
	 * Stored settings, merged over default_settings() -- or, when the
	 * current request qualifies (see preview_override()), an admin's
	 * unsaved live preview draft.
	 */
	public static function settings() {
		$preview = self::preview_override();
		if ( null !== $preview ) {
			return $preview;
		}
		return wp_parse_args( get_option( 'is_login_design_settings', array() ), self::default_settings() );
	}

	/**
	 * When the request is `?is_preview=1` from a signed-in administrator
	 * AND that admin has a live draft stored (via store_preview(), called
	 * from IS_Ajax::preview_login_design()), render that draft instead of
	 * the saved option -- lets the settings page show a genuine preview
	 * of in-progress edits without persisting anything. Returns null
	 * (fall through to the saved option) in every other case.
	 */
	private static function preview_override() {
		if ( empty( $_GET['is_preview'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only feature flag; the transient lookup below (keyed to the current user, capability-checked) is what actually gates content, not this flag
			return null;
		}
		if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
			return null;
		}
		$draft = get_transient( self::preview_transient_key( get_current_user_id() ) );
		return is_array( $draft ) ? wp_parse_args( $draft, self::default_settings() ) : null;
	}

	/**
	 * Transient key a given admin's live preview draft is stored under.
	 *
	 * @param int $user_id Admin user ID.
	 */
	private static function preview_transient_key( $user_id ) {
		return 'is_login_design_preview_' . (int) $user_id;
	}

	/**
	 * Stores a draft for THIS admin only, for a few minutes -- called from
	 * the ajax handler with an already-sanitized array (see the class
	 * docblock). Never touches the real saved option.
	 *
	 * @param array $draft Sanitized draft settings array.
	 */
	public static function store_preview( array $draft ) {
		set_transient( self::preview_transient_key( get_current_user_id() ), $draft, 5 * MINUTE_IN_SECONDS );
	}

	// ===================================================================
	// Pure CSS/HTML assembly
	// ===================================================================

	/**
	 * Pure: neutralizes a </style breakout sequence before raw CSS is echoed inside a <style> tag.
	 *
	 * @param mixed $css Raw CSS to sanitize.
	 */
	public static function sanitize_css_for_style_tag( $css ) {
		return str_ireplace( '</style', '<\\/style', (string) $css );
	}

	/**
	 * Pure: is this a plausible #rgb/#rrggbb/#rrggbbaa hex color?
	 *
	 * @param mixed $value Value to test.
	 */
	public static function is_hex_color( $value ) {
		return (bool) preg_match( '/^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i', (string) $value );
	}

	/**
	 * Pure: clamps a border-radius setting to a sane, renderable range.
	 *
	 * @param mixed $radius Border-radius setting to clamp.
	 */
	public static function clamp_radius( $radius ) {
		return max( 0, min( 40, (int) $radius ) );
	}

	/**
	 * Pure: is this a plausible http(s) image URL (the only scheme we'll ever emit into CSS/HTML)?
	 *
	 * @param mixed $value Value to test.
	 */
	public static function is_http_url( $value ) {
		return 0 === strpos( (string) $value, 'http://' ) || 0 === strpos( (string) $value, 'https://' );
	}

	/**
	 * Pure: strips characters that would let a URL escape a quoted CSS url("...") context.
	 *
	 * @param mixed $url URL to sanitize.
	 */
	private static function css_safe_url( $url ) {
		return str_replace( array( '"', '\\' ), '', (string) $url );
	}

	/**
	 * Pure: assembles the full login-page <style> contents for a given
	 * settings array (shaped like default_settings()). Unknown/invalid
	 * values fall back to sane defaults rather than producing broken CSS.
	 *
	 * @param array $settings Settings array (shaped like default_settings()).
	 */
	public static function build_css( array $settings ) {
		$defaults = self::default_settings();
		$settings = array_merge( $defaults, $settings );

		$color    = self::is_hex_color( $settings['primary_color'] ) ? $settings['primary_color'] : $defaults['primary_color'];
		$radius   = self::clamp_radius( $settings['border_radius'] );
		$template = array_key_exists( $settings['template'], self::templates() ) ? $settings['template'] : $defaults['template'];
		$logo     = self::is_http_url( $settings['logo_url'] ) ? $settings['logo_url'] : '';
		$hero_img = self::is_http_url( $settings['hero_image_url'] ) ? $settings['hero_image_url'] : '';

		$position = self::hero_position( $settings );

		$css  = sprintf( ':root{--is-login-color:%s;--is-login-radius:%dpx;}', $color, $radius );
		$css .= self::base_css( ! empty( $settings['hide_branding'] ) );

		if ( '' !== $logo ) {
			$css .= sprintf(
				'body.login #login h1 a{background-image:url("%s");background-repeat:no-repeat;background-position:center;background-size:contain;width:240px;max-width:100%%;height:76px;text-indent:-9999px;margin:0 0 20px;}',
				self::css_safe_url( $logo )
			);
		}

		// Carousel and Polaroid render the hero image as a real <img> tag
		// (build_hero_html()) instead of a full-bleed CSS background --
		// applying the background-image rule too would visually fight
		// with it, so it's skipped for just these two. Every other
		// template's behavior here is completely unchanged.
		$uses_img_tag = in_array( $template, array( 'carousel', 'polaroid' ), true );

		if ( self::is_split_template( $template ) ) {
			if ( 'center' === $position ) {
				$css .= self::center_layout_css();
				$css .= self::template_hero_css( $template );
				$css .= self::center_hero_css( $template );
			} else {
				$css .= self::split_layout_css( $position );
				$css .= self::template_hero_css( $template );
			}
			if ( '' !== $hero_img && ! $uses_img_tag ) {
				$css .= sprintf(
					'.is-login-hero{background-image:linear-gradient(180deg, rgba(15,15,25,.15), rgba(15,15,25,.6)), url("%s");background-size:cover;background-position:center;}.is-login-hero .is-login-blob{display:none;}',
					self::css_safe_url( $hero_img )
				);
			}
		}

		$css .= self::template_form_css( $template );

		// Center placement re-skins the card into a translucent, frosted
		// panel that floats over the hero -- it has to win over
		// template_form_css()'s solid-white card, so it's appended after it.
		if ( self::is_split_template( $template ) && 'center' === $position ) {
			$css .= self::center_form_css();
		}

		$css .= self::sanitize_css_for_style_tag( $settings['custom_css'] );

		return $css;
	}

	/**
	 * Pure: rules that apply to every template. When $hide_branding is
	 * true (the default), strips the default WordPress logo mark --
	 * without a custom logo, the site name (already forced by
	 * header_text() while this setting is on) shows as a plain text
	 * wordmark instead of the WordPress icon. When false, the stock
	 * WordPress logo/branding is left alone.
	 *
	 * @param bool $hide_branding Whether to strip the default WordPress branding.
	 */
	private static function base_css( $hide_branding ) {
		$css = '
			body.login div#login p#nav,body.login div#login p#backtoblog{font-size:13px;}
		';
		if ( $hide_branding ) {
			// Same selector specificity as the logo override below
			// (body.login #login h1 a, not body.login div#login h1 a) --
			// build_css() relies on source order to let a configured logo
			// win over this rule; mismatched specificity would make this
			// one win regardless of order, since it's added first.
			$css .= '
				body.login #login h1 a{background-image:none;width:auto;height:auto;text-indent:0;overflow:visible;display:inline-block;font-size:1.5em;font-weight:800;letter-spacing:-0.02em;padding:0;margin:0 0 20px;text-decoration:none;}
			';
		}
		return $css;
	}

	/**
	 * Pure: repositions the real #login card into one half of the
	 * viewport (left or right), leaving the other half for
	 * .is-login-hero -- see hero_position in default_settings().
	 *
	 * @param string $position Hero placement: 'left' or 'right'.
	 */
	private static function split_layout_css( $position ) {
		$justify = 'right' === $position ? 'flex-start' : 'flex-end';
		$side    = 'right' === $position ? 'right' : 'left';
		return '
			body.login{min-height:100vh;box-sizing:border-box;display:flex;align-items:center;justify-content:' . $justify . ';padding:5vh 7vw;background:#fff;}
			body.login #login{width:380px;max-width:100%;margin:0;position:relative;z-index:2;}
			.is-login-hero{' . $side . ':0;}
			/* Tablet and below: the hero panel is fixed-width-percentage and
			   would crush the form, so it drops out entirely and the card
			   recenters -- a standard, well-supported pattern for
			   split-screen sign-in pages at this viewport size. */
			@media screen and (max-width: 900px) {
				.is-login-hero{display:none;}
				body.login{justify-content:center;padding:5vh 6vw;}
			}
			/* Small phones: the card itself gets tighter side padding so it
			   is not flush against the viewport edges. */
			@media screen and (max-width: 480px) {
				body.login{padding:5vh 4vw;}
				body.login #login{width:100%;}
			}
		';
	}

	/**
	 * Pure: the 'center' placement scaffold -- the real #login card is
	 * centered in the viewport and lifted above a full-bleed hero (set up
	 * by center_hero_css()). Unlike the left/right split, the hero is never
	 * hidden on smaller screens here: it *is* the backdrop the form sits on.
	 */
	private static function center_layout_css() {
		return '
			body.login{min-height:100vh;box-sizing:border-box;display:flex;align-items:center;justify-content:center;padding:6vh 5vw;background:#0b0b14;}
			body.login #login{width:400px;max-width:100%;margin:0;position:relative;z-index:3;}
			@media screen and (max-width: 480px) {
				body.login{padding:4vh 4vw;}
				body.login #login{width:100%;}
			}
		';
	}

	/**
	 * Pure: promotes a split template's hero from a half-width side panel
	 * to a full-bleed backdrop for the centered card, darkens it for form
	 * legibility, and tucks the (now-behind-the-card) hero copy away. For
	 * the Carousel template the slides stay live behind the card and the
	 * nav controls drop to the bottom-center so they clear it.
	 *
	 * @param string $template Template slug.
	 */
	private static function center_hero_css( $template ) {
		// WordPress prints the hero inside #login (via login_message), just
		// above the form. Since the hero is positioned, a positive z-index
		// would paint it *over* the in-flow form; a negative one drops it
		// behind every in-flow sibling (form, wordmark, nav links) while
		// still covering the viewport, which is exactly what a full-bleed
		// backdrop wants.
		$css = '
			.is-login-hero{position:fixed;inset:0;width:100%;height:100%;padding:0;align-items:center;justify-content:center;z-index:-1;}
			.is-login-hero::after{content:"";position:absolute;inset:0;background:radial-gradient(130% 130% at 50% 0%, rgba(6,6,16,.12) 0%, rgba(6,6,16,.5) 70%, rgba(6,6,16,.72) 100%);z-index:1;pointer-events:none;}
			.is-login-hero .is-login-hero-copy{display:none;}
		';
		if ( 'carousel' === $template ) {
			$css .= '
				.is-login-hero.is-login-carousel::after{display:none;}
				.is-login-carousel .is-carousel-controls{position:absolute;left:0;right:0;bottom:28px;justify-content:center;}
			';
		}
		return $css;
	}

	/**
	 * Pure: the frosted-glass card treatment used only by the 'center'
	 * placement, appended after template_form_css() so it overrides the
	 * solid-white card. #nav/#backtoblog and the wordmark now sit over the
	 * dark hero (not a white column), so their color flips to light here.
	 */
	private static function center_form_css() {
		return '
			.login form{background:rgba(255,255,255,.92);border:1px solid rgba(255,255,255,.5);box-shadow:0 30px 90px rgba(0,0,0,.5),0 2px 10px rgba(0,0,0,.3);backdrop-filter:blur(16px) saturate(1.3);-webkit-backdrop-filter:blur(16px) saturate(1.3);}
			body.login div#login h1 a{color:#fff;text-align:center;text-shadow:0 2px 14px rgba(0,0,0,.55);}
			.login #nav a,.login #backtoblog a{color:rgba(255,255,255,.9);text-shadow:0 1px 6px rgba(0,0,0,.5);}
			.login #nav a:hover,.login #backtoblog a:hover{color:#fff;}
		';
	}

	/**
	 * Pure: the decorative hero-panel background for one split template. Colors tint from --is-login-color via color-mix().
	 *
	 * @param string $template Template slug.
	 */
	private static function template_hero_css( $template ) {
		$shared = '
			.is-login-hero{position:fixed;top:0;bottom:0;width:50%;box-sizing:border-box;display:flex;flex-direction:column;justify-content:center;padding:8vh 6vw;overflow:hidden;z-index:1;}
			.is-login-hero-scrim{position:absolute;inset:0;}
			.is-login-hero-copy{position:relative;z-index:2;color:#fff;}
			.is-login-hero-copy h2{font-size:clamp(28px,4vw,46px);font-weight:800;line-height:1.12;letter-spacing:-0.02em;margin:0 0 14px;}
			.is-login-hero-copy p{font-size:15px;line-height:1.6;opacity:.88;max-width:38ch;margin:0;}
			.is-login-blob{position:absolute;border-radius:50%;filter:blur(6px);pointer-events:none;}
			@media (prefers-reduced-motion: no-preference) {
				.is-login-blob{animation:is-login-float 7s ease-in-out infinite alternate;}
			}
			@keyframes is-login-float{from{transform:translateY(0) scale(1);}to{transform:translateY(-18px) scale(1.04);}}
		';

		switch ( $template ) {
			case 'aurora-night':
				return $shared . '
					.is-login-hero{background:radial-gradient(1200px circle at 20% 0%, color-mix(in srgb, var(--is-login-color) 45%, #4338ca) 0%, transparent 55%),radial-gradient(900px circle at 90% 90%, color-mix(in srgb, var(--is-login-color) 30%, #7c3aed) 0%, transparent 50%),linear-gradient(160deg,#0b0f2b 0%,#151132 55%,#1c1440 100%);}
					.is-login-hero::before{content:"";position:absolute;inset:0;background-image:radial-gradient(1.5px 1.5px at 10% 20%, rgba(255,255,255,.8) 50%, transparent 51%),radial-gradient(1.5px 1.5px at 80% 15%, rgba(255,255,255,.7) 50%, transparent 51%),radial-gradient(1px 1px at 60% 70%, rgba(255,255,255,.6) 50%, transparent 51%),radial-gradient(1.5px 1.5px at 30% 85%, rgba(255,255,255,.7) 50%, transparent 51%),radial-gradient(1px 1px at 90% 55%, rgba(255,255,255,.5) 50%, transparent 51%),radial-gradient(1.5px 1.5px at 45% 40%, rgba(255,255,255,.6) 50%, transparent 51%);}
					.is-login-blob-1{top:12%;right:10%;width:180px;height:180px;background:color-mix(in srgb, var(--is-login-color) 55%, #a855f7);opacity:.35;filter:blur(40px);}
					.is-login-blob-2{bottom:14%;left:8%;width:220px;height:220px;background:#22d3ee;opacity:.18;filter:blur(50px);}
					.is-login-blob-3{top:50%;left:55%;width:90px;height:90px;background:#f472b6;opacity:.2;filter:blur(30px);}
				';

			case 'bubblegum':
				return $shared . '
					.is-login-hero{background:linear-gradient(150deg, color-mix(in srgb, var(--is-login-color) 55%, #f9a8d4) 0%, color-mix(in srgb, var(--is-login-color) 35%, #c084fc) 50%, #fbcfe8 100%);}
					.is-login-blob-1{top:8%;left:12%;width:120px;height:120px;background:rgba(255,255,255,.55);}
					.is-login-blob-2{bottom:10%;right:14%;width:170px;height:170px;background:rgba(255,255,255,.35);}
					.is-login-blob-3{top:55%;left:65%;width:70px;height:70px;background:rgba(255,255,255,.5);}
					.is-login-blob-1{animation-delay:.2s;}
					.is-login-blob-2{animation-delay:1.4s;}
					.is-login-blob-3{animation-delay:.8s;}
				';

			case 'forest':
				return $shared . '
					.is-login-hero{background:linear-gradient(160deg, color-mix(in srgb, var(--is-login-color) 35%, #14532d) 0%, color-mix(in srgb, var(--is-login-color) 45%, #166534) 45%, #052e16 100%);}
					.is-login-blob-1{top:-10%;left:-10%;width:220px;height:220px;border-radius:38% 62% 63% 37% / 41% 44% 56% 59%;background:color-mix(in srgb, var(--is-login-color) 50%, #4ade80);opacity:.3;filter:blur(10px);}
					.is-login-blob-2{bottom:-12%;right:-8%;width:260px;height:260px;border-radius:63% 37% 30% 70% / 50% 45% 55% 50%;background:color-mix(in srgb, var(--is-login-color) 40%, #a3e635);opacity:.22;filter:blur(14px);}
					.is-login-blob-3{top:45%;right:15%;width:60px;height:60px;border-radius:42% 58% 70% 30% / 45% 45% 55% 55%;background:rgba(255,255,255,.18);filter:blur(4px);}
				';

			case 'monochrome':
				return $shared . '
					.is-login-hero{background:linear-gradient(160deg,#18181b 0%,#27272a 100%);}
					.is-login-hero::before{content:"";position:absolute;inset:0;background-image:repeating-linear-gradient(135deg, rgba(255,255,255,.035) 0px, rgba(255,255,255,.035) 1px, transparent 1px, transparent 14px);}
					.is-login-blob-1{top:-6%;right:-6%;width:200px;height:200px;border-radius:50%;border:1px solid rgba(255,255,255,.18);background:transparent;filter:none;}
					.is-login-blob-2{bottom:-10%;left:-10%;width:260px;height:260px;border-radius:50%;border:1px solid rgba(255,255,255,.1);background:transparent;filter:none;}
					.is-login-blob-3{top:40%;left:20%;width:8px;height:8px;background:var(--is-login-color);border-radius:50%;filter:none;opacity:1;}
				';

			case 'ocean':
				return $shared . '
					.is-login-hero{background:linear-gradient(170deg, color-mix(in srgb, var(--is-login-color) 40%, #0c4a6e) 0%, color-mix(in srgb, var(--is-login-color) 50%, #0369a1) 45%, #164e63 100%);}
					.is-login-hero::before{content:"";position:absolute;left:0;right:0;bottom:0;height:40%;background:linear-gradient(0deg, rgba(255,255,255,.08), transparent), repeating-radial-gradient(circle at 20% 100%, rgba(255,255,255,.05) 0, rgba(255,255,255,.05) 2px, transparent 2px, transparent 40px);}
					.is-login-blob-1{top:10%;right:-8%;width:220px;height:220px;border-radius:50%;background:color-mix(in srgb, var(--is-login-color) 40%, #22d3ee);opacity:.25;filter:blur(20px);}
					.is-login-blob-2{bottom:-14%;left:-10%;width:280px;height:280px;border-radius:50%;background:#0891b2;opacity:.3;filter:blur(20px);}
					.is-login-blob-3{top:55%;left:30%;width:40px;height:40px;border-radius:50%;background:rgba(255,255,255,.25);filter:blur(2px);}
				';

			case 'carousel':
				// Full-bleed, immersive gallery: the slides fill the entire
				// hero panel (a slow Ken Burns zoom on the active one, unless
				// reduced-motion is set), a gradient scrim keeps the overlaid
				// heading/controls legible, and the visitor's chosen indicator
				// style (bars/dots/numbers/thumbnails/none) renders at the
				// bottom. Markup: build_carousel_html(); interaction:
				// carousel_js().
				return $shared . '
					.is-login-hero.is-login-carousel{justify-content:flex-end;padding:8vh 6vw;background:linear-gradient(160deg, #1a0b2e 0%, color-mix(in srgb, var(--is-login-color) 40%, #2d1b4e) 55%, #0f0620 100%);}
					.is-carousel-frame{position:absolute;inset:0;width:100%;height:100%;overflow:hidden;z-index:0;background:#0f0620;}
					.is-carousel-slide{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;opacity:0;transition:opacity .8s ease;}
					.is-carousel-slide.is-active{opacity:1;}
					@media (prefers-reduced-motion: no-preference){
						.is-carousel-slide.is-active{animation:is-carousel-kenburns 14s ease-out both;}
					}
					@keyframes is-carousel-kenburns{from{transform:scale(1.12);}to{transform:scale(1);}}
					.is-carousel-scrim{position:absolute;inset:0;z-index:1;pointer-events:none;background:linear-gradient(180deg, rgba(10,6,25,.15) 0%, rgba(10,6,25,.3) 50%, rgba(10,6,25,.85) 100%);}
					.is-login-carousel .is-login-hero-copy{position:relative;z-index:2;margin-bottom:22px;}
					.is-carousel-controls{position:relative;z-index:2;display:flex;align-items:center;gap:14px;}
					.is-carousel-dots{display:flex;gap:6px;align-items:center;}
					.is-carousel-dot{border:none;cursor:pointer;padding:0;}
					.is-ind-bars .is-carousel-dot{width:22px;height:3px;border-radius:2px;background:rgba(255,255,255,.3);transition:background .2s ease, width .2s ease;}
					.is-ind-bars .is-carousel-dot.is-active{background:#fff;width:34px;}
					.is-ind-dots .is-carousel-dot{width:9px;height:9px;border-radius:50%;background:rgba(255,255,255,.4);transition:background .2s ease, transform .2s ease;}
					.is-ind-dots .is-carousel-dot.is-active{background:#fff;transform:scale(1.35);}
					.is-ind-thumbs{gap:8px;}
					.is-ind-thumbs .is-carousel-dot{width:46px;height:34px;border-radius:7px;overflow:hidden;background:none;border:2px solid transparent;opacity:.5;transition:opacity .2s ease, border-color .2s ease;}
					.is-ind-thumbs .is-carousel-dot img{width:100%;height:100%;object-fit:cover;display:block;}
					.is-ind-thumbs .is-carousel-dot.is-active{opacity:1;border-color:#fff;}
					.is-carousel-counter{display:flex;align-items:center;gap:5px;color:#fff;font-size:14px;font-weight:600;letter-spacing:.03em;font-variant-numeric:tabular-nums;}
					.is-carousel-counter .is-carousel-sep{opacity:.5;}
					.is-carousel-counter .is-carousel-total{opacity:.6;}
					.is-carousel-prev,.is-carousel-next{width:36px;height:36px;flex:none;border-radius:50%;border:1px solid rgba(255,255,255,.3);background:rgba(255,255,255,.08);color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;line-height:1;transition:background .2s ease;}
					.is-carousel-prev:hover,.is-carousel-next:hover{background:rgba(255,255,255,.2);}
				';

			case 'terminal':
				// A window-chrome bar (three "traffic light" dots drawn via
				// box-shadow, not text/images) plus a blinking cursor after
				// the heading -- generated blobs are switched off since
				// soft blurred shapes clash with the sharp, geeky look.
				return $shared . '
					.is-login-hero{background:#0a0e14;font-family:"SF Mono",Monaco,"Cascadia Code","Roboto Mono",Consolas,monospace;}
					.is-login-hero::before{content:"";position:absolute;top:0;left:0;right:0;height:34px;background:#161b22;border-bottom:1px solid rgba(255,255,255,.08);z-index:1;}
					.is-login-hero::after{content:"";position:absolute;top:13px;left:16px;width:8px;height:8px;border-radius:50%;background:#ff5f56;box-shadow:16px 0 0 #ffbd2e, 32px 0 0 #27c93f;z-index:2;}
					.is-login-hero-copy{position:relative;z-index:2;margin-top:44px;}
					.is-login-hero-copy h2{font-family:inherit;color:color-mix(in srgb, var(--is-login-color) 65%, #7ee787);}
					.is-login-hero-copy h2::after{content:"▍";display:inline-block;margin-left:4px;color:inherit;}
					@media (prefers-reduced-motion: no-preference) {
						.is-login-hero-copy h2::after{animation:is-login-blink 1s step-end infinite;}
					}
					@keyframes is-login-blink{50%{opacity:0;}}
					.is-login-hero-copy p{font-family:inherit;color:#8b949e;font-size:13px;}
					.is-login-blob{display:none;}
				';

			case 'polaroid':
				// The hero image (if set) renders as a real, tilted,
				// white-bordered <img> "photo" via build_hero_html(), not
				// a full-bleed background -- see is-login-polaroid-photo.
				return $shared . '
					.is-login-hero{align-items:center;justify-content:center;text-align:center;background:linear-gradient(160deg, color-mix(in srgb, var(--is-login-color) 16%, #fdf6f0) 0%, color-mix(in srgb, var(--is-login-color) 10%, #fbeee6) 100%);}
					.is-login-hero-copy{order:2;margin-top:22px;}
					.is-login-hero-copy h2{color:#4a3f35;}
					.is-login-hero-copy p{color:#8a7c6f;margin-left:auto;margin-right:auto;}
					.is-login-polaroid-photo{order:1;width:78%;max-width:300px;background:#fff;padding:14px 14px 42px;box-shadow:0 18px 40px rgba(74,63,53,.25);transform:rotate(-4deg);border-radius:2px;}
					.is-login-polaroid-photo img{display:block;width:100%;height:auto;aspect-ratio:1/1;object-fit:cover;border-radius:1px;}
					.is-login-blob-1{top:6%;left:8%;width:50px;height:50px;background:rgba(255,255,255,.6);}
					.is-login-blob-2{bottom:8%;right:10%;width:70px;height:70px;background:rgba(255,255,255,.4);}
					.is-login-blob-3{display:none;}
				';

			case 'sunrise':
			default:
				return $shared . '
					.is-login-hero{background:linear-gradient(160deg, color-mix(in srgb, var(--is-login-color) 45%, #fb923c) 0%, color-mix(in srgb, var(--is-login-color) 55%, #f43f5e) 55%, color-mix(in srgb, var(--is-login-color) 70%, #7c3aed) 100%);}
					.is-login-blob-1{top:-8%;right:-6%;width:260px;height:260px;background:rgba(255,214,140,.55);}
					.is-login-blob-2{bottom:-10%;left:-8%;width:280px;height:280px;background:rgba(124,58,237,.4);}
					.is-login-blob-3{top:38%;left:60%;width:36px;height:36px;border-radius:50%;border:2px dashed rgba(255,255,255,.35);background:transparent;filter:none;}
				';
		}
	}

	/**
	 * Pure: form/card/input/button styling for one template.
	 *
	 * @param string $template Template slug.
	 */
	private static function template_form_css( $template ) {
		if ( 'minimal' === $template ) {
			return '
				body.login{background:#f8fafc;}
				body.login div#login h1 a{color:#0f172a;}
				.login form{background:#fff;border:1px solid #e2e8f0;border-radius:var(--is-login-radius);box-shadow:0 8px 30px rgba(15,23,42,.06);}
				.login form .input,.login input[type=text],.login input[type=password]{border-radius:calc(var(--is-login-radius) * 0.35);box-shadow:none;border-color:#cbd5e1;}
				.login form .input:focus,.login input[type=text]:focus,.login input[type=password]:focus{border-color:var(--is-login-color);box-shadow:0 0 0 1px var(--is-login-color);}
				.login .button-primary{background:var(--is-login-color);border-color:var(--is-login-color);border-radius:calc(var(--is-login-radius) * 0.35);text-shadow:none;box-shadow:none;}
				.login .button-primary:hover,.login .button-primary:focus{background:color-mix(in srgb, var(--is-login-color) 85%, black);border-color:color-mix(in srgb, var(--is-login-color) 85%, black);}
				.login #nav a,.login #backtoblog a{color:#64748b;}
				.login .message,.login #login_error{border-left-color:var(--is-login-color);border-radius:calc(var(--is-login-radius) * 0.35);}
			';
		}

		// #nav/#backtoblog always sit on the right-hand white card column
		// (see split_layout_css()), never on the hero panel itself, so
		// their color only needs to work against white -- true regardless
		// of which template's hero is showing.
		$button = 'monochrome' === $template
			? 'background:#18181b;border-color:#18181b;'
			: 'background:linear-gradient(135deg, var(--is-login-color), color-mix(in srgb, var(--is-login-color) 60%, #f43f5e));border-color:transparent;';

		return '
			body.login div#login h1 a{color:#0f172a;}
			.login form{background:#fff;border-radius:var(--is-login-radius);box-shadow:0 20px 60px rgba(15,23,42,.18);border:1px solid rgba(15,23,42,.04);}
			.login form .input,.login input[type=text],.login input[type=password]{border-radius:calc(var(--is-login-radius) * 0.45);box-shadow:none;border-color:#e2e8f0;}
			.login form .input:focus,.login input[type=text]:focus,.login input[type=password]:focus{border-color:var(--is-login-color);box-shadow:0 0 0 3px color-mix(in srgb, var(--is-login-color) 25%, transparent);}
			.login .button-primary{' . $button . 'border-radius:calc(var(--is-login-radius) * 0.45);text-shadow:none;box-shadow:0 8px 20px color-mix(in srgb, var(--is-login-color) 40%, transparent);}
			.login .button-primary:hover,.login .button-primary:focus{filter:brightness(1.15);}
			.login #nav a,.login #backtoblog a{color:#64748b;}
			.login .message,.login #login_error{border-left-color:var(--is-login-color);border-radius:calc(var(--is-login-radius) * 0.45);}
		';
	}

	/**
	 * Pure: the decorative hero panel markup for split templates --
	 * heading/subheading text (already sanitize_text_field()'d at save
	 * time) is HTML-escaped here defensively before output. Purely
	 * decorative, so the whole block is aria-hidden; the accessible page
	 * title/heading/form remain untouched elsewhere on the page.
	 *
	 * @param array $settings Settings array (shaped like default_settings()).
	 */
	public static function build_hero_html( array $settings ) {
		$defaults    = self::default_settings();
		$settings    = array_merge( $defaults, $settings );
		$template    = $settings['template'];
		$heading     = trim( (string) $settings['hero_heading'] );
		$subheading  = trim( (string) $settings['hero_subheading'] );
		$has_image   = self::is_http_url( $settings['hero_image_url'] );
		$is_polaroid = 'polaroid' === $template;

		if ( 'carousel' === $template ) {
			return self::build_carousel_html( $settings );
		}

		$html  = '<div class="is-login-hero" aria-hidden="true">';
		$html .= '<span class="is-login-hero-scrim"></span>';
		if ( $is_polaroid && $has_image ) {
			// A real <img>, not a background -- lets it take a genuine
			// white photo-border + rotation via CSS border/transform,
			// which a background-image can't do cleanly.
			$html .= '<div class="is-login-polaroid-photo"><img src="' . htmlspecialchars( $settings['hero_image_url'], ENT_QUOTES, 'UTF-8' ) . '" alt=""></div>';
		} elseif ( ! $has_image ) {
			$html .= '<span class="is-login-blob is-login-blob-1"></span><span class="is-login-blob is-login-blob-2"></span><span class="is-login-blob is-login-blob-3"></span>';
		}
		$html .= '<div class="is-login-hero-copy">';
		if ( '' !== $heading ) {
			$html .= '<h2>' . htmlspecialchars( $heading, ENT_QUOTES, 'UTF-8' ) . '</h2>';
		}
		if ( '' !== $subheading ) {
			$html .= '<p>' . htmlspecialchars( $subheading, ENT_QUOTES, 'UTF-8' ) . '</p>';
		}
		$html .= '</div></div>';
		return $html;
	}

	/**
	 * Pure: the image list a Carousel template actually shows -- the
	 * multi-image gallery if one is set, else the single hero_image_url
	 * as a one-slide fallback (no dot/arrow controls render for a single
	 * slide -- see build_carousel_html()), else empty (falls back to the
	 * same generated blob pattern every other split template uses
	 * without an image).
	 *
	 * @param array $settings Settings array (shaped like default_settings()).
	 */
	public static function carousel_images( array $settings ) {
		$gallery = isset( $settings['hero_gallery'] ) && is_array( $settings['hero_gallery'] ) ? $settings['hero_gallery'] : array();
		$gallery = array_values( array_filter( $gallery, array( __CLASS__, 'is_http_url' ) ) );
		if ( ! empty( $gallery ) ) {
			return array_slice( $gallery, 0, 8 );
		}
		if ( self::is_http_url( $settings['hero_image_url'] ?? '' ) ) {
			return array( $settings['hero_image_url'] );
		}
		return array();
	}

	/**
	 * Pure: the Carousel template's hero markup -- a heading/subheading
	 * above a framed image gallery, with dot/arrow controls when there's
	 * more than one image. The controls are inert without JS (the first
	 * image just shows statically); carousel_js() wires them up.
	 *
	 * @param array $settings Settings array (shaped like default_settings()).
	 */
	private static function build_carousel_html( array $settings ) {
		$heading    = trim( (string) $settings['hero_heading'] );
		$subheading = trim( (string) $settings['hero_subheading'] );
		$images     = self::carousel_images( $settings );

		$html = '<div class="is-login-hero is-login-carousel" aria-hidden="true">';

		// No images: fall back to the same soft generated pattern every
		// other split template uses (copy above the blobs).
		if ( empty( $images ) ) {
			$html .= '<div class="is-login-hero-copy">';
			if ( '' !== $heading ) {
				$html .= '<h2>' . htmlspecialchars( $heading, ENT_QUOTES, 'UTF-8' ) . '</h2>';
			}
			if ( '' !== $subheading ) {
				$html .= '<p>' . htmlspecialchars( $subheading, ENT_QUOTES, 'UTF-8' ) . '</p>';
			}
			$html .= '</div>';
			$html .= '<span class="is-login-blob is-login-blob-1"></span><span class="is-login-blob is-login-blob-2"></span><span class="is-login-blob is-login-blob-3"></span>';
			$html .= '</div>';
			return $html;
		}

		// Full-bleed slide stack + scrim (behind the overlaid copy/controls).
		$html .= '<div class="is-carousel-frame">';
		foreach ( $images as $i => $url ) {
			$html .= '<img class="is-carousel-slide' . ( 0 === $i ? ' is-active' : '' ) . '" src="' . htmlspecialchars( $url, ENT_QUOTES, 'UTF-8' ) . '" alt="">';
		}
		$html .= '<span class="is-carousel-scrim"></span>';
		$html .= '</div>';

		// Overlaid heading/subheading.
		$html .= '<div class="is-login-hero-copy">';
		if ( '' !== $heading ) {
			$html .= '<h2>' . htmlspecialchars( $heading, ENT_QUOTES, 'UTF-8' ) . '</h2>';
		}
		if ( '' !== $subheading ) {
			$html .= '<p>' . htmlspecialchars( $subheading, ENT_QUOTES, 'UTF-8' ) . '</p>';
		}
		$html .= '</div>';

		if ( count( $images ) > 1 ) {
			$html .= '<div class="is-carousel-controls">';
			$html .= '<button type="button" class="is-carousel-prev" aria-label="Previous">&larr;</button>';
			$html .= self::carousel_indicator_html( self::carousel_indicator( $settings ), $images );
			$html .= '<button type="button" class="is-carousel-next" aria-label="Next">&rarr;</button>';
			$html .= '</div>';
		}

		$html .= '</div>';
		return $html;
	}

	/**
	 * Pure: the slide-indicator markup for a chosen style. 'bars', 'dots'
	 * and 'thumbnails' all emit clickable .is-carousel-dot buttons (the JS
	 * treats them identically, toggling .is-active); the parent modifier
	 * class (is-ind-*) is what makes them look different. 'numbers' emits a
	 * live "current / total" counter, 'none' emits nothing (arrows only).
	 *
	 * @param string $indicator Indicator style key (see carousel_indicators()).
	 * @param array  $images    Slide image URLs.
	 */
	private static function carousel_indicator_html( $indicator, array $images ) {
		if ( 'none' === $indicator ) {
			return '';
		}

		if ( 'numbers' === $indicator ) {
			return '<div class="is-carousel-counter"><span class="is-carousel-current">1</span>'
				. '<span class="is-carousel-sep">/</span>'
				. '<span class="is-carousel-total">' . count( $images ) . '</span></div>';
		}

		$modifier = 'dots' === $indicator ? 'is-ind-dots' : ( 'thumbnails' === $indicator ? 'is-ind-thumbs' : 'is-ind-bars' );

		$html = '<div class="is-carousel-dots ' . $modifier . '">';
		foreach ( $images as $i => $url ) {
			$inner = 'thumbnails' === $indicator
				? '<img src="' . htmlspecialchars( $url, ENT_QUOTES, 'UTF-8' ) . '" alt="">'
				: '';
			$html .= '<button type="button" class="is-carousel-dot' . ( 0 === $i ? ' is-active' : '' ) . '">' . $inner . '</button>';
		}
		$html .= '</div>';
		return $html;
	}

	/**
	 * Pure: the small, self-contained, dependency-free vanilla-JS
	 * carousel controller -- no build step, matches this plugin's
	 * existing JS elsewhere. Auto-advances every 6s unless the visitor's
	 * OS-level prefers-reduced-motion is set; dot/arrow clicks always
	 * work and reset the timer.
	 */
	public static function carousel_js() {
		return <<<'JS'
(function(){
	var root = document.querySelector('.is-login-carousel');
	if (!root) { return; }
	var slides = root.querySelectorAll('.is-carousel-slide');
	var dots = root.querySelectorAll('.is-carousel-dot');
	var current = root.querySelector('.is-carousel-current');
	var prevBtn = root.querySelector('.is-carousel-prev');
	var nextBtn = root.querySelector('.is-carousel-next');
	var index = 0;
	var timer = null;

	function show(i) {
		index = (i + slides.length) % slides.length;
		for (var n = 0; n < slides.length; n++) {
			slides[n].classList.toggle('is-active', n === index);
		}
		for (var d = 0; d < dots.length; d++) {
			dots[d].classList.toggle('is-active', d === index);
		}
		if (current) { current.textContent = String(index + 1); }
	}
	function restart() {
		if (timer) { clearInterval(timer); }
		if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
			timer = setInterval(function () { show(index + 1); }, 6000);
		}
	}
	for (var k = 0; k < dots.length; k++) {
		(function (n) {
			dots[n].addEventListener('click', function () { show(n); restart(); });
		})(k);
	}
	if (prevBtn) { prevBtn.addEventListener('click', function () { show(index - 1); restart(); }); }
	if (nextBtn) { nextBtn.addEventListener('click', function () { show(index + 1); restart(); }); }
	restart();
})();
JS;
	}

	// ===================================================================
	// WordPress glue
	// ===================================================================

	/**
	 * Builds the settings-derived CSS (and, for a multi-image Carousel,
	 * the carousel JS) and enqueues them as inline styles/scripts on the
	 * login page.
	 */
	public function enqueue() {
		IS_Guard::run(
			'login_design',
			function () {
				$settings = self::settings();
				$css      = self::build_css( $settings );
				if ( '' !== trim( $css ) ) {
					wp_register_style( 'is-login-design', false, array(), IS_VERSION );
					wp_enqueue_style( 'is-login-design' );
					wp_add_inline_style( 'is-login-design', $css );
				}

				if ( 'carousel' === $settings['template'] && count( self::carousel_images( $settings ) ) > 1 ) {
					wp_register_script( 'is-login-carousel', false, array(), IS_VERSION, true );
					wp_enqueue_script( 'is-login-carousel' );
					wp_add_inline_script( 'is-login-carousel', self::carousel_js() );
				}
			}
		);
	}

	/**
	 * When "Hide WordPress branding" is on (the default), points the logo link at the site's own homepage -- never wordpress.org.
	 *
	 * @param string $url Default login header URL.
	 */
	public function header_url( $url ) {
		return IS_Guard::run(
			'login_design',
			function () use ( $url ) {
				return empty( self::settings()['hide_branding'] ) ? $url : home_url( '/' );
			},
			$url
		);
	}

	/**
	 * When "Hide WordPress branding" is on (the default), uses the site name instead of WordPress core's default "Powered by WordPress".
	 *
	 * @param string $text Default login header text.
	 */
	public function header_text( $text ) {
		return IS_Guard::run(
			'login_design',
			function () use ( $text ) {
				return empty( self::settings()['hide_branding'] ) ? $text : get_bloginfo( 'name' );
			},
			$text
		);
	}

	/**
	 * When "Hide WordPress branding" is on (the default), rebuilds the <title> tag from the site name so core's default "... — WordPress" suffix never appears.
	 *
	 * @param string $title Default login page title.
	 */
	public function filter_login_title( $title ) {
		return IS_Guard::run(
			'login_design',
			function () use ( $title ) {
				if ( empty( self::settings()['hide_branding'] ) ) {
					return $title;
				}
				return get_bloginfo( 'name' ) . ' — ' . __( 'Log In', 'integrity-sentinel' );
			},
			$title
		);
	}

	/**
	 * Prepends the split-template hero panel (if applicable) and the
	 * admin's custom HTML banner to login_message's output. Both stored
	 * values are already sanitized at save time -- see the class
	 * docblock.
	 *
	 * @param string $message Default login_message output.
	 */
	public function inject_custom_html( $message ) {
		return IS_Guard::run(
			'login_design',
			function () use ( $message ) {
				$settings = self::settings();
				$out      = '';

				if ( self::is_split_template( $settings['template'] ) ) {
					$out .= self::build_hero_html( $settings );
				}

				$html = trim( $settings['custom_html'] );
				if ( '' !== $html ) {
					$out .= '<div class="is-login-custom-html">' . $html . '</div>';
				}

				return $out . $message;
			},
			$message
		);
	}
}

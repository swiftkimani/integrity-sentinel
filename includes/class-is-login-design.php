<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cosmetic layer for wp-login.php: seven built-in templates (one plain
 * centered card, six "split-screen" designs with a decorative hero
 * panel down either side, in the style of modern SaaS sign-in pages), a
 * customizer (accent color, logo, corner radius, hero position/heading/
 * subheading/image) layered on top, an escape hatch for raw custom CSS,
 * and an optional sanitized HTML banner above the form.
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

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

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

	public static function templates() {
		return array(
			'minimal'      => __( 'Minimal', 'integrity-sentinel' ),
			'sunrise'      => __( 'Sunrise', 'integrity-sentinel' ),
			'aurora-night' => __( 'Aurora Night', 'integrity-sentinel' ),
			'bubblegum'    => __( 'Bubblegum', 'integrity-sentinel' ),
			'forest'       => __( 'Forest', 'integrity-sentinel' ),
			'monochrome'   => __( 'Monochrome', 'integrity-sentinel' ),
			'ocean'        => __( 'Ocean', 'integrity-sentinel' ),
		);
	}

	/** Pure: which templates use the split-screen hero-panel layout (everything but the plain card). */
	public static function is_split_template( $template ) {
		return in_array( $template, array( 'sunrise', 'aurora-night', 'bubblegum', 'forest', 'monochrome', 'ocean' ), true );
	}

	public static function default_settings() {
		return array(
			'template'        => 'sunrise',
			'logo_url'        => '',
			'primary_color'   => '#6366f1',
			'border_radius'   => 18,
			'hero_position'   => 'left',
			'hero_heading'    => 'Welcome back',
			'hero_subheading' => '',
			'hero_image_url'  => '',
			'hide_branding'   => 1,
			'custom_css'      => '',
			'custom_html'     => '',
		);
	}

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

	private static function preview_transient_key( $user_id ) {
		return 'is_login_design_preview_' . (int) $user_id;
	}

	/**
	 * Stores a draft for THIS admin only, for a few minutes -- called from
	 * the ajax handler with an already-sanitized array (see the class
	 * docblock). Never touches the real saved option.
	 */
	public static function store_preview( array $draft ) {
		set_transient( self::preview_transient_key( get_current_user_id() ), $draft, 5 * MINUTE_IN_SECONDS );
	}

	// ===================================================================
	// Pure CSS/HTML assembly
	// ===================================================================

	/** Pure: neutralizes a </style breakout sequence before raw CSS is echoed inside a <style> tag. */
	public static function sanitize_css_for_style_tag( $css ) {
		return str_ireplace( '</style', '<\\/style', (string) $css );
	}

	/** Pure: is this a plausible #rgb/#rrggbb/#rrggbbaa hex color? */
	public static function is_hex_color( $value ) {
		return (bool) preg_match( '/^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i', (string) $value );
	}

	/** Pure: clamps a border-radius setting to a sane, renderable range. */
	public static function clamp_radius( $radius ) {
		return max( 0, min( 40, (int) $radius ) );
	}

	/** Pure: is this a plausible http(s) image URL (the only scheme we'll ever emit into CSS/HTML)? */
	public static function is_http_url( $value ) {
		return 0 === strpos( (string) $value, 'http://' ) || 0 === strpos( (string) $value, 'https://' );
	}

	/** Pure: strips characters that would let a URL escape a quoted CSS url("...") context. */
	private static function css_safe_url( $url ) {
		return str_replace( array( '"', '\\' ), '', (string) $url );
	}

	/**
	 * Pure: assembles the full login-page <style> contents for a given
	 * settings array (shaped like default_settings()). Unknown/invalid
	 * values fall back to sane defaults rather than producing broken CSS.
	 */
	public static function build_css( array $settings ) {
		$defaults = self::default_settings();
		$settings = array_merge( $defaults, $settings );

		$color    = self::is_hex_color( $settings['primary_color'] ) ? $settings['primary_color'] : $defaults['primary_color'];
		$radius   = self::clamp_radius( $settings['border_radius'] );
		$template = array_key_exists( $settings['template'], self::templates() ) ? $settings['template'] : $defaults['template'];
		$logo     = self::is_http_url( $settings['logo_url'] ) ? $settings['logo_url'] : '';
		$hero_img = self::is_http_url( $settings['hero_image_url'] ) ? $settings['hero_image_url'] : '';

		$position = 'right' === $settings['hero_position'] ? 'right' : 'left';

		$css  = sprintf( ':root{--is-login-color:%s;--is-login-radius:%dpx;}', $color, $radius );
		$css .= self::base_css( ! empty( $settings['hide_branding'] ) );

		if ( '' !== $logo ) {
			$css .= sprintf(
				'body.login #login h1 a{background-image:url("%s");background-repeat:no-repeat;background-position:center;background-size:contain;width:240px;max-width:100%%;height:76px;text-indent:-9999px;margin:0 0 20px;}',
				self::css_safe_url( $logo )
			);
		}

		if ( self::is_split_template( $template ) ) {
			$css .= self::split_layout_css( $position );
			$css .= self::template_hero_css( $template );
			if ( '' !== $hero_img ) {
				$css .= sprintf(
					'.is-login-hero{background-image:linear-gradient(180deg, rgba(15,15,25,.15), rgba(15,15,25,.6)), url("%s");background-size:cover;background-position:center;}.is-login-hero .is-login-blob{display:none;}',
					self::css_safe_url( $hero_img )
				);
			}
		}

		$css .= self::template_form_css( $template );
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
	 */
	private static function base_css( $hide_branding ) {
		$css = '
			body.login div#login p#nav,body.login div#login p#backtoblog{font-size:13px;}
		';
		if ( $hide_branding ) {
			$css .= '
				body.login div#login h1 a{background-image:none;width:auto;height:auto;text-indent:0;overflow:visible;display:inline-block;font-size:1.5em;font-weight:800;letter-spacing:-0.02em;padding:0;margin:0 0 20px;text-decoration:none;}
			';
		}
		return $css;
	}

	/**
	 * Pure: repositions the real #login card into one half of the
	 * viewport (left or right), leaving the other half for
	 * .is-login-hero -- see hero_position in default_settings().
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

	/** Pure: the decorative hero-panel background for one split template. Colors tint from --is-login-color via color-mix(). */
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

	/** Pure: form/card/input/button styling for one template. */
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
	 */
	public static function build_hero_html( array $settings ) {
		$defaults   = self::default_settings();
		$settings   = array_merge( $defaults, $settings );
		$heading    = trim( (string) $settings['hero_heading'] );
		$subheading = trim( (string) $settings['hero_subheading'] );
		$has_image  = self::is_http_url( $settings['hero_image_url'] );

		$html  = '<div class="is-login-hero" aria-hidden="true">';
		$html .= '<span class="is-login-hero-scrim"></span>';
		if ( ! $has_image ) {
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

	// ===================================================================
	// WordPress glue
	// ===================================================================

	public function enqueue() {
		IS_Guard::run(
			'login_design',
			function () {
				$css = self::build_css( self::settings() );
				if ( '' === trim( $css ) ) {
					return;
				}
				wp_register_style( 'is-login-design', false, array(), IS_VERSION );
				wp_enqueue_style( 'is-login-design' );
				wp_add_inline_style( 'is-login-design', $css );
			}
		);
	}

	/** When "Hide WordPress branding" is on (the default), points the logo link at the site's own homepage -- never wordpress.org. */
	public function header_url( $url ) {
		return IS_Guard::run(
			'login_design',
			function () use ( $url ) {
				return empty( self::settings()['hide_branding'] ) ? $url : home_url( '/' );
			},
			$url
		);
	}

	/** When "Hide WordPress branding" is on (the default), uses the site name instead of WordPress core's default "Powered by WordPress". */
	public function header_text( $text ) {
		return IS_Guard::run(
			'login_design',
			function () use ( $text ) {
				return empty( self::settings()['hide_branding'] ) ? $text : get_bloginfo( 'name' );
			},
			$text
		);
	}

	/** When "Hide WordPress branding" is on (the default), rebuilds the <title> tag from the site name so core's default "... — WordPress" suffix never appears. */
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

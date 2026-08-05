<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * HTTP response hardening: security headers (including clickjacking
 * protection), version disclosure removal, XML-RPC, and RSS/Atom feeds.
 * Each is independently toggleable in is_hardening_settings -- some are
 * safe to default on (headers, hiding the version), others can break a
 * real integration (XML-RPC for Jetpack/mobile apps, feeds for
 * subscribers) and default off until the site owner opts in.
 *
 * Every hook callback runs through IS_Guard::run() under its own module
 * key, so a fault in one of these (a bad regex, a missing function on an
 * unusual host) degrades only that one behavior rather than the site.
 */
class IS_Headers {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	public static function default_settings() {
		return array(
			'security_headers'        => 1,
			'prevent_clickjacking'    => 1,
			'hide_wp_version'         => 1,
			'hide_meta_fingerprints'  => 1,
			'disable_xmlrpc'          => 0,
			'disable_feeds'           => 0,
			'content_security_policy' => '',
			'csp_report_only'         => 1,
		);
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_hardening_settings', array() ), self::default_settings() );
	}

	private function hooks() {
		add_action( 'send_headers', array( $this, 'send_security_headers' ) );
		add_action( 'login_init', array( $this, 'send_security_headers' ) );

		add_action( 'init', array( $this, 'remove_version_generator' ) );
		add_action( 'init', array( $this, 'remove_meta_fingerprints' ) );
		add_filter( 'the_generator', array( $this, 'filter_the_generator' ) );
		add_filter( 'style_loader_src', array( $this, 'filter_asset_version' ), 9999 );
		add_filter( 'script_loader_src', array( $this, 'filter_asset_version' ), 9999 );

		add_filter( 'xmlrpc_enabled', array( $this, 'filter_xmlrpc_enabled' ) );
		add_filter( 'wp_headers', array( $this, 'filter_pingback_header' ) );
		add_action( 'wp_head', array( $this, 'maybe_remove_rsd_link' ), 1 );

		foreach ( array( 'do_feed', 'do_feed_rdf', 'do_feed_rss', 'do_feed_rss2', 'do_feed_atom', 'do_feed_rss2_comments', 'do_feed_atom_comments' ) as $feed_hook ) {
			add_action( $feed_hook, array( $this, 'maybe_block_feed' ), 1 );
		}
	}

	// -----------------------------------------------------------------
	// Security headers (including clickjacking protection)
	// -----------------------------------------------------------------

	/**
	 * Pure: the header name => value pairs to send for a given settings
	 * array. No WordPress calls -- fully unit-testable.
	 */
	public static function security_header_lines( array $settings ) {
		$headers = array();

		if ( ! empty( $settings['security_headers'] ) ) {
			$headers['X-Content-Type-Options'] = 'nosniff';
			$headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';
			$headers['Permissions-Policy']     = 'geolocation=(), microphone=(), camera=()';
		}

		if ( ! empty( $settings['prevent_clickjacking'] ) ) {
			// Older-browser fallback; frame-ancestors (below, part of the
			// CSP header) is the modern, more flexible replacement.
			// SAMEORIGIN rather than DENY so a site's own admin/customizer
			// preview iframes keep working.
			$headers['X-Frame-Options'] = 'SAMEORIGIN';
		}

		$csp = self::build_csp( $settings );
		if ( '' !== $csp ) {
			// Report-only sends violations to the browser console (and an
			// optional report-uri) without blocking anything -- the safe
			// way to test a policy on a site whose exact plugin/theme
			// asset mix isn't known in advance.
			$header_name             = ! empty( $settings['csp_report_only'] ) ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
			$headers[ $header_name ] = $csp;
		}

		return $headers;
	}

	/**
	 * Pure: assembles the effective Content-Security-Policy string, or ''
	 * to send no CSP header at all. With the full policy feature off,
	 * this preserves the previous behavior exactly -- a bare
	 * frame-ancestors directive whenever clickjacking protection is on,
	 * nothing otherwise. With a full policy set, frame-ancestors is
	 * folded into it (rather than sent as a second, separate directive)
	 * unless the admin's own policy already specifies one.
	 */
	public static function build_csp( array $settings ) {
		$policy = trim( (string) ( $settings['content_security_policy'] ?? '' ) );

		if ( '' === $policy ) {
			return ! empty( $settings['prevent_clickjacking'] ) ? "frame-ancestors 'self'" : '';
		}

		if ( ! empty( $settings['prevent_clickjacking'] ) && false === stripos( $policy, 'frame-ancestors' ) ) {
			$policy = rtrim( $policy, "; \t\n\r" ) . "; frame-ancestors 'self'";
		}

		return $policy;
	}

	/** A conservative, WordPress-compatible starting policy -- permissive enough not to break a typical theme/plugin mix, while still closing off the classic object-embed and base-tag-hijack vectors. Pre-fills the settings textarea; not auto-applied. */
	public static function suggested_csp() {
		return "default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' https: data:; font-src 'self' https: data:; object-src 'none'; base-uri 'self';";
	}

	/**
	 * Frontend coverage via send_headers, login page via login_init --
	 * wp-admin intentionally isn't covered here: WP core doesn't send
	 * these there either, admin pages already require authentication,
	 * and some page-builder/preview iframes rely on framing admin.
	 */
	public function send_security_headers() {
		IS_Guard::run(
			'security_headers',
			function () {
				if ( headers_sent() ) {
					return;
				}
				foreach ( self::security_header_lines( self::settings() ) as $name => $value ) {
					header( "{$name}: {$value}" );
				}
			}
		);
	}

	// -----------------------------------------------------------------
	// Hide WordPress version
	// -----------------------------------------------------------------

	public function remove_version_generator() {
		IS_Guard::run(
			'hide_wp_version',
			function () {
				if ( ! empty( self::settings()['hide_wp_version'] ) ) {
					remove_action( 'wp_head', 'wp_generator' );
				}
			}
		);
	}

	/** Pure: the_generator filter callback logic. */
	public static function generator_value( $generator, array $settings ) {
		return empty( $settings['hide_wp_version'] ) ? $generator : '';
	}

	public function filter_the_generator( $generator ) {
		return IS_Guard::run(
			'hide_wp_version',
			function () use ( $generator ) {
				return self::generator_value( $generator, self::settings() );
			},
			$generator
		);
	}

	/**
	 * Pure: strips a `ver` query argument from an enqueued asset URL
	 * (e.g. style.css?ver=6.7 -> style.css) without depending on any
	 * WordPress URL helper, so this is unit-testable on its own.
	 */
	public static function strip_version_query_string( $src ) {
		if ( ! is_string( $src ) || false === strpos( $src, 'ver=' ) ) {
			return $src;
		}

		$query_pos = strpos( $src, '?' );
		if ( false === $query_pos ) {
			return $src;
		}

		$base     = substr( $src, 0, $query_pos );
		$query    = substr( $src, $query_pos + 1 );
		$frag     = '';
		$hash_pos = strpos( $query, '#' );
		if ( false !== $hash_pos ) {
			$frag  = substr( $query, $hash_pos );
			$query = substr( $query, 0, $hash_pos );
		}

		parse_str( $query, $args );
		unset( $args['ver'] );

		$rebuilt = $args ? ( '?' . http_build_query( $args ) ) : '';
		return $base . $rebuilt . $frag;
	}

	public function filter_asset_version( $src ) {
		return IS_Guard::run(
			'hide_wp_version',
			function () use ( $src ) {
				return empty( self::settings()['hide_wp_version'] ) ? $src : self::strip_version_query_string( $src );
			},
			$src
		);
	}

	// -----------------------------------------------------------------
	// Fingerprint reduction (head links + REST discovery header)
	// -----------------------------------------------------------------

	/**
	 * Removes the head <link> tags and REST API discovery HTTP header
	 * that advertise WordPress-specific endpoints on every single page
	 * -- purely a discovery/fingerprint removal, not a functional
	 * lockdown. A client that already knows the REST API's URL (or any
	 * RSD-discoverable endpoint) can still use it exactly as before;
	 * this only stops broadcasting the URL in page source and response
	 * headers. Deliberately independent of disable_xmlrpc, which is a
	 * real functional change with compatibility risk (Jetpack, mobile
	 * apps) -- this one has none, so it's safe to default on.
	 */
	public function remove_meta_fingerprints() {
		IS_Guard::run(
			'hide_meta_fingerprints',
			function () {
				if ( empty( self::settings()['hide_meta_fingerprints'] ) ) {
					return;
				}
				remove_action( 'wp_head', 'wlwmanifest_link' );
				remove_action( 'wp_head', 'wp_shortlink_wp_head' );
				remove_action( 'wp_head', 'rest_output_link_wp_head' );
				remove_action( 'template_redirect', 'rest_output_link_header', 11 );
			}
		);
	}

	// -----------------------------------------------------------------
	// XML-RPC
	// -----------------------------------------------------------------

	/**
	 * Filters the requests XML-RPC serves rather than blocking the file
	 * outright: xmlrpc.php still answers (with every method disabled),
	 * which needs no server-config changes and works identically on
	 * every host, unlike a hard 403/404 that would need .htaccess/nginx
	 * rules this plugin can't guarantee are applied.
	 */
	public function filter_xmlrpc_enabled( $enabled ) {
		return IS_Guard::run(
			'disable_xmlrpc',
			function () use ( $enabled ) {
				return empty( self::settings()['disable_xmlrpc'] ) ? $enabled : false;
			},
			$enabled
		);
	}

	public function filter_pingback_header( $headers ) {
		return IS_Guard::run(
			'disable_xmlrpc',
			function () use ( $headers ) {
				if ( ! empty( self::settings()['disable_xmlrpc'] ) && is_array( $headers ) ) {
					unset( $headers['X-Pingback'] );
				}
				return $headers;
			},
			$headers
		);
	}

	public function maybe_remove_rsd_link() {
		IS_Guard::run(
			'disable_xmlrpc',
			function () {
				if ( ! empty( self::settings()['disable_xmlrpc'] ) ) {
					remove_action( 'wp_head', 'rsd_link' );
				}
			}
		);
	}

	// -----------------------------------------------------------------
	// RSS/Atom feeds
	// -----------------------------------------------------------------

	public function maybe_block_feed() {
		IS_Guard::run(
			'disable_feeds',
			function () {
				if ( empty( self::settings()['disable_feeds'] ) ) {
					return;
				}
				wp_die(
					esc_html__( 'Feeds are disabled on this site.', 'integrity-sentinel' ),
					'',
					array( 'response' => 403 )
				);
			}
		);
	}
}

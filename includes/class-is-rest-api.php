<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST API hardening: two safe-by-default protections against user
 * enumeration, plus an opt-in full lockdown for unauthenticated REST
 * access.
 *
 *  - Blocking /wp/v2/users (and /wp/v2/users/<id>) for logged-out
 *    requests stops the single most common REST-based username
 *    enumeration technique, with essentially no legitimate unauthenticated
 *    use case to break.
 *  - Blocking the old ?author=N query-string enumeration (WordPress
 *    core redirects it to the author's archive URL, revealing the
 *    username in the resulting slug) closes the pre-REST version of the
 *    same problem.
 *  - Restricting ALL unauthenticated REST access is opt-in and off by
 *    default: many themes/plugins (search, forms, WooCommerce's store
 *    API, block-editor previews) depend on public REST routes, so this
 *    can break real functionality -- same off-by-default posture as
 *    XML-RPC/feed disabling.
 *
 * Application-Password-authenticated requests (used by the
 * integrity-sentinel/v1/posts endpoint in IS_Rest_Posts) are resolved to
 * a logged-in user by WordPress core before these hooks run, so they are
 * never treated as "unauthenticated" here.
 */
class IS_Rest_API {

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
			'block_user_enumeration'   => 1,
			'restrict_unauthenticated' => 0,
			'allowed_routes'           => '',
		);
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_rest_api_settings', array() ), self::default_settings() );
	}

	private function hooks() {
		add_filter( 'rest_pre_dispatch', array( $this, 'guard_request' ), 10, 3 );
		add_action( 'template_redirect', array( $this, 'block_author_query_enumeration' ) );
	}

	// -----------------------------------------------------------------
	// Pure route-matching logic
	// -----------------------------------------------------------------

	public static function is_user_enumeration_route( $route ) {
		return (bool) preg_match( '#^/wp/v2/users(?:/\d+)?/?$#', (string) $route );
	}

	/**
	 * Pure: whether an unauthenticated request to $route should be let
	 * through when full restriction is enabled -- our own namespace is
	 * always allowed (it enforces its own auth per-route), plus any
	 * admin-configured prefix.
	 *
	 * @param string[] $allowed_prefixes
	 */
	public static function route_is_allowlisted( $route, array $allowed_prefixes ) {
		$route = ltrim( (string) $route, '/' );
		if ( 0 === strpos( $route, 'integrity-sentinel/v1' ) ) {
			return true;
		}
		foreach ( $allowed_prefixes as $prefix ) {
			$prefix = ltrim( trim( (string) $prefix ), '/' );
			if ( '' !== $prefix && 0 === strpos( $route, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	public static function parse_route_list( $text ) {
		return array_values( array_filter( array_map( 'trim', preg_split( '/\r\n|\r|\n/', (string) $text ) ) ) );
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	public function guard_request( $result, $server, $request ) {
		return IS_Guard::run(
			'rest_api',
			function () use ( $result, $request ) {
				if ( is_wp_error( $result ) ) {
					return $result;
				}

				$settings  = self::settings();
				$route     = $request->get_route();
				$logged_in = is_user_logged_in();

				if ( ! empty( $settings['block_user_enumeration'] ) && ! $logged_in && self::is_user_enumeration_route( $route ) ) {
					IS_Audit_Log::record( 'rest_user_enumeration_blocked', array( 'route' => $route ) );
					return new WP_Error( 'is_rest_user_enumeration_disabled', __( 'REST access to the users endpoint is disabled for unauthenticated requests.', 'integrity-sentinel' ), array( 'status' => 401 ) );
				}

				if ( ! empty( $settings['restrict_unauthenticated'] ) && ! $logged_in ) {
					$allowed = self::parse_route_list( $settings['allowed_routes'] );
					if ( ! self::route_is_allowlisted( $route, $allowed ) ) {
						return new WP_Error( 'is_rest_restricted', __( 'The REST API is restricted to authenticated requests on this site.', 'integrity-sentinel' ), array( 'status' => 401 ) );
					}
				}

				return $result;
			},
			$result
		);
	}

	/**
	 * The classic pre-REST enumeration technique: /?author=1 302s to
	 * /author/theusername/, revealing the username in the redirect URL
	 * even though no REST endpoint was involved.
	 */
	public function block_author_query_enumeration() {
		IS_Guard::run(
			'rest_api',
			function () {
				if ( is_user_logged_in() || ! isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only detection, not a state change
					return;
				}
				if ( empty( self::settings()['block_user_enumeration'] ) ) {
					return;
				}
				if ( preg_match( '/^\d+$/', wp_unslash( $_GET['author'] ) ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Recommended -- validated by the regex itself
					wp_die( esc_html__( 'Not Found', 'integrity-sentinel' ), '', array( 'response' => 404 ) );
				}
			}
		);
	}
}

<?php
/**
 * REST API hardening against user enumeration and, optionally, all
 * unauthenticated access.
 *
 * @package Integrity_Sentinel
 */

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

	/**
	 * Singleton instance.
	 *
	 * @var IS_Rest_API|null
	 */
	private static $instance = null;

	/**
	 * Gets (and lazily creates) the singleton instance, wiring up hooks
	 * the first time it is created.
	 *
	 * @return IS_Rest_API
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	const RATE_LIMIT_WINDOW = 5 * MINUTE_IN_SECONDS;

	/** HTTP methods that mutate state -- an unprotected route accepting one of these is materially more dangerous than an unprotected read-only route. */
	const WRITE_METHODS = array( 'POST', 'PUT', 'PATCH', 'DELETE' );

	/**
	 * Default settings for this module.
	 *
	 * @return array
	 */
	public static function default_settings() {
		return array(
			'block_user_enumeration'   => 1,
			'restrict_unauthenticated' => 0,
			'allowed_routes'           => '',
			'rate_limit'               => 120,
			'enumeration_detection'    => 1,
			'enumeration_threshold'    => 20,
			'block_on_enumeration'     => 0,
			'route_audit_exclusions'   => '',
		);
	}

	/**
	 * Current settings, merged with the defaults.
	 *
	 * @return array
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_rest_api_settings', array() ), self::default_settings() );
	}

	/**
	 * Registers the REST-dispatch guard and the author-enumeration check.
	 */
	private function hooks() {
		add_filter( 'rest_pre_dispatch', array( $this, 'guard_request' ), 10, 3 );
		add_action( 'template_redirect', array( $this, 'block_author_query_enumeration' ) );
	}

	// -----------------------------------------------------------------
	// Pure route-matching logic
	// -----------------------------------------------------------------

	/**
	 * Pure: whether $route is the core users collection or a single-user
	 * lookup on it.
	 *
	 * @param string $route REST route being requested.
	 * @return bool
	 */
	public static function is_user_enumeration_route( $route ) {
		return (bool) preg_match( '#^/wp/v2/users(?:/\d+)?/?$#', (string) $route );
	}

	/**
	 * Pure: whether an unauthenticated request to $route should be let
	 * through when full restriction is enabled -- our own namespace is
	 * always allowed (it enforces its own auth per-route), plus any
	 * admin-configured prefix.
	 *
	 * @param string   $route            REST route being requested.
	 * @param string[] $allowed_prefixes Admin-configured allowed route prefixes.
	 * @return bool
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

	/**
	 * Splits an admin-entered, newline-separated list of route prefixes
	 * into a clean array (trimmed, blank lines dropped).
	 *
	 * @param string $text Raw newline-separated route-prefix list.
	 * @return string[]
	 */
	public static function parse_route_list( $text ) {
		return array_values( array_filter( array_map( 'trim', preg_split( '/\r\n|\r|\n/', (string) $text ) ) ) );
	}

	/**
	 * Pure: whether $route is a single-object numeric-ID lookup on one of
	 * WordPress core's own collection endpoints (e.g. /wp/v2/posts/123).
	 * Used to spot enumeration -- a scanner walking IDs sequentially --
	 * without needing to understand every possible custom post type or
	 * namespace; the core collections are the ones enumeration actually
	 * targets in practice (usernames, unpublished posts, private pages).
	 *
	 * @param string $route REST route being requested.
	 * @return array{type: string, id: int}|null
	 */
	public static function numeric_id_route_match( $route ) {
		if ( preg_match( '#^/wp/v2/(posts|pages|users|comments|media)/(\d+)/?$#', (string) $route, $m ) ) {
			return array(
				'type' => $m[1],
				'id'   => (int) $m[2],
			);
		}
		return null;
	}

	/**
	 * Pure: normalizes a route handler's 'methods' entry (a comma-list
	 * string, a flat list of method names, or the ['GET'=>true,...]
	 * assoc shape WordPress core typically stores) to a flat, deduped
	 * array of uppercase method names. Handled defensively across all
	 * three shapes since exactly which one appears has varied across
	 * WordPress versions and how a given plugin registered the route.
	 *
	 * @param array $handler One route's registration args, as found in rest_get_server()->get_routes().
	 * @return string[]
	 */
	public static function route_methods( array $handler ) {
		$methods = isset( $handler['methods'] ) ? $handler['methods'] : array();
		if ( is_string( $methods ) ) {
			$methods = array_filter( array_map( 'trim', explode( ',', $methods ) ) );
			return array_values( array_unique( array_map( 'strtoupper', $methods ) ) );
		}
		if ( ! is_array( $methods ) ) {
			return array();
		}
		$out = array();
		foreach ( $methods as $key => $value ) {
			if ( is_string( $key ) && $value ) {
				$out[] = strtoupper( $key );
			} elseif ( is_int( $key ) && is_string( $value ) ) {
				$out[] = strtoupper( $value );
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Pure: whether a route handler has no real permission check --
	 * missing entirely, null, or the literal '__return_true' callback.
	 *
	 * @param array $handler One route's registration args.
	 */
	public static function is_route_unprotected( array $handler ) {
		if ( ! array_key_exists( 'permission_callback', $handler ) ) {
			return true;
		}
		$callback = $handler['permission_callback'];
		return null === $callback || '' === $callback || '__return_true' === $callback;
	}

	/**
	 * Pure: the finding severity for an unprotected route, or null if it
	 * shouldn't become a finding at all. WordPress core intentionally
	 * leaves large numbers of *read* routes public by design (post/page/
	 * category listings, etc.), and several popular plugins intentionally
	 * expose unauthenticated *write* routes too (WooCommerce's Store API
	 * cart/checkout, contact-form submission) -- flagging every
	 * '__return_true' route indiscriminately would flood a vanilla
	 * install with noise on day one. So: only an unprotected route
	 * accepting a write method becomes a finding (high, not critical --
	 * legitimate public-write endpoints genuinely exist); an unprotected
	 * read-only route is visibility-only, never a finding.
	 *
	 * @param string[] $methods     route_methods() output.
	 * @param bool     $unprotected is_route_unprotected() output.
	 * @return string|null 'high', 'info', or null.
	 */
	public static function route_finding_severity( array $methods, $unprotected ) {
		if ( ! $unprotected ) {
			return null;
		}
		return array_intersect( $methods, self::WRITE_METHODS ) ? 'high' : 'info';
	}

	/**
	 * Pure: given rest_get_server()->get_routes()'s raw shape (route =>
	 * list of handler-arrays -- a route can have more than one handler,
	 * e.g. separate GET and POST registrations), returns every
	 * unprotected handler flattened with its computed severity. Written
	 * generically -- this audits every plugin's routes, not just this
	 * plugin's own.
	 *
	 * @param array<string,array> $routes rest_get_server()->get_routes() output.
	 * @return array<array{route:string,methods:string[],severity:string}>
	 */
	public static function classify_routes( array $routes ) {
		$out = array();
		foreach ( $routes as $route => $handlers ) {
			if ( ! is_array( $handlers ) ) {
				continue;
			}
			foreach ( $handlers as $handler ) {
				if ( ! is_array( $handler ) ) {
					continue;
				}
				$methods     = self::route_methods( $handler );
				$unprotected = self::is_route_unprotected( $handler );
				$severity    = self::route_finding_severity( $methods, $unprotected );
				if ( null === $severity ) {
					continue;
				}
				$out[] = array(
					'route'    => (string) $route,
					'methods'  => $methods,
					'severity' => $severity,
				);
			}
		}
		return $out;
	}

	/**
	 * Pure: whether $route starts with one of the admin-configured
	 * audit-exclusion prefixes (a reviewed-and-intentional public write
	 * route the admin doesn't want flagged).
	 *
	 * @param string   $route              REST route.
	 * @param string[] $exclusion_prefixes Admin-configured route prefixes to exclude from the audit.
	 */
	public static function route_excluded_from_audit( $route, array $exclusion_prefixes ) {
		$route = ltrim( (string) $route, '/' );
		foreach ( $exclusion_prefixes as $prefix ) {
			$prefix = ltrim( trim( (string) $prefix ), '/' );
			if ( '' !== $prefix && 0 === strpos( $route, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * Enumerates every REST route currently registered -- WordPress
	 * core's and every installed plugin's, not just this plugin's own --
	 * and returns the unprotected ones with their computed severity.
	 * Note: rest_get_server() lazily fires the 'rest_api_init' action the
	 * first time it's called in a request if it hasn't already run;
	 * that's safe/idempotent to trigger from a cron-driven scan.
	 *
	 * @return array<array{route:string,methods:string[],severity:string}>
	 */
	public static function audit_registered_routes() {
		if ( ! function_exists( 'rest_get_server' ) ) {
			return array();
		}
		return self::classify_routes( rest_get_server()->get_routes() );
	}

	/**
	 * Filters 'rest_pre_dispatch' to apply rate limiting, user-enumeration
	 * blocking, full unauthenticated-access restriction, and enumeration
	 * detection before the request reaches its actual handler.
	 *
	 * @param mixed           $result  Response to replace the requested version with, usually null.
	 * @param WP_REST_Server  $server  Server instance.
	 * @param WP_REST_Request $request Request used to generate the response.
	 * @return mixed The original $result, or a WP_Error to short-circuit the request.
	 */
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
				$ip        = IS_IP_List::client_ip();

				// General per-IP throttling across every REST route, ahead
				// of the more specific checks below -- an unthrottled
				// attacker previously had no ceiling at all on this filter
				// (only the one custom endpoint in IS_Rest_Posts had a
				// limiter). Whitelisted IPs bypass it, same as login rate
				// limiting.
				if ( ! empty( $settings['rate_limit'] ) && '' !== $ip && ! IS_IP_List::is_whitelisted( $ip ) ) {
					if ( ! IS_Rate_Limiter::hit( 'rest_api', $ip, (int) $settings['rate_limit'], self::RATE_LIMIT_WINDOW ) ) {
						IS_Detections::fire(
							'rest_rate_limited',
							array(
								'ip'    => $ip,
								'route' => $route,
							)
						);
						return new WP_Error( 'is_rest_rate_limited', __( 'Too many REST API requests. Please slow down.', 'integrity-sentinel' ), array( 'status' => 429 ) );
					}
				}

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

				// Enumeration-velocity detection: a scanner walking
				// sequential numeric IDs on a core collection shows up as a
				// burst of single-object lookups from one IP. Logged by
				// default; blocking is opt-in since a very active
				// legitimate integration could plausibly trip the
				// threshold too.
				if ( ! empty( $settings['enumeration_detection'] ) && ! $logged_in && '' !== $ip && ! IS_IP_List::is_whitelisted( $ip ) ) {
					if ( self::numeric_id_route_match( $route ) ) {
						$within_threshold = IS_Rate_Limiter::hit( 'rest_enum', $ip, (int) $settings['enumeration_threshold'], self::RATE_LIMIT_WINDOW );
						if ( ! $within_threshold ) {
							IS_Detections::fire(
								'rest_enumeration_suspected',
								array(
									'ip'    => $ip,
									'route' => $route,
								)
							);
							if ( ! empty( $settings['block_on_enumeration'] ) ) {
								return new WP_Error( 'is_rest_enumeration_blocked', __( 'This IP has been temporarily blocked for suspicious REST API access patterns.', 'integrity-sentinel' ), array( 'status' => 429 ) );
							}
						}
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
				if ( preg_match( '/^\d+$/', wp_unslash( $_GET['author'] ) ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Recommended -- validated by the regex itself
					wp_die( esc_html__( 'Not Found', 'integrity-sentinel' ), '', array( 'response' => 404 ) );
				}
			}
		);
	}
}

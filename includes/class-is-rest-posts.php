<?php
/**
 * REST endpoint for creating posts via Application Passwords, scoped by
 * capability and rate-limited per user.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A dedicated, narrow REST endpoint for creating blog posts --
 * integrity-sentinel/v1/posts (POST) -- authenticated via WordPress
 * core's own Application Passwords (no bespoke secret store), scoped by
 * ordinary WP capabilities (edit_posts to create at all, publish_posts
 * to actually publish rather than land in pending review), and
 * rate-limited per user so a leaked application password can't be used
 * to spam-post without limit.
 *
 * This is the "straightforward integration" surface for an external
 * publishing/agentic tool: create an Application Password for a
 * dedicated user (ideally Author/Editor, not Administrator) in
 * Users -> Profile, then POST here with HTTP Basic auth.
 */
class IS_Rest_Posts {

	/**
	 * Singleton instance.
	 *
	 * @var IS_Rest_Posts|null
	 */
	private static $instance = null;

	const RATE_LIMIT_WINDOW = HOUR_IN_SECONDS;

	/**
	 * Gets (and lazily creates) the singleton instance, wiring up hooks
	 * the first time it is created.
	 *
	 * @return IS_Rest_Posts
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	/**
	 * Default settings for this module.
	 *
	 * @return array
	 */
	public static function default_settings() {
		return array(
			'enabled'    => 1,
			'rate_limit' => 30,
		);
	}

	/**
	 * Current settings, merged with the defaults.
	 *
	 * @return array
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_rest_posts_settings', array() ), self::default_settings() );
	}

	/**
	 * Registers the REST route.
	 */
	private function hooks() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: resolves the requested post status against what the
	 * authenticated user is actually allowed to do -- a request for
	 * 'publish' or 'private' from a user without publish_posts is
	 * downgraded to 'pending' (submitted for review) rather than
	 * rejected outright, so the integration still succeeds.
	 *
	 * @param string $requested   Post status requested by the caller.
	 * @param bool   $can_publish Whether the authenticated user has publish_posts.
	 * @return string Resolved post status.
	 */
	public static function sanitize_status( $requested, $can_publish ) {
		$requested = is_string( $requested ) ? strtolower( trim( $requested ) ) : '';
		if ( ! in_array( $requested, array( 'draft', 'pending', 'publish', 'private' ), true ) ) {
			$requested = 'draft';
		}
		if ( in_array( $requested, array( 'publish', 'private' ), true ) && ! $can_publish ) {
			return 'pending';
		}
		return $requested;
	}

	/**
	 * Pure: fixed-window rate limiter. $record is shaped like
	 * {window_started_at, count}; a window that has expired is treated
	 * as zero regardless of its stored count.
	 *
	 * @param array $record         Rate-limit record ({window_started_at, count}).
	 * @param int   $now            Current timestamp.
	 * @param int   $window_seconds Length of the rate-limit window, in seconds.
	 * @return int Number of requests counted in the current window.
	 */
	public static function current_window_count( array $record, $now, $window_seconds ) {
		if ( empty( $record['window_started_at'] ) || $record['window_started_at'] <= ( $now - $window_seconds ) ) {
			return 0;
		}
		return (int) ( $record['count'] ?? 0 );
	}

	/**
	 * Pure: whether the current window's request count has reached the limit.
	 *
	 * @param array $record         Rate-limit record ({window_started_at, count}).
	 * @param int   $now            Current timestamp.
	 * @param int   $limit          Maximum requests allowed per window.
	 * @param int   $window_seconds Length of the rate-limit window, in seconds.
	 * @return bool
	 */
	public static function is_rate_limited( array $record, $now, $limit, $window_seconds ) {
		return self::current_window_count( $record, $now, $window_seconds ) >= $limit;
	}

	/**
	 * Pure: returns an updated rate-limit record reflecting one more
	 * request, starting a fresh window if the previous one has expired.
	 *
	 * @param array $record         Rate-limit record ({window_started_at, count}).
	 * @param int   $now            Current timestamp.
	 * @param int   $window_seconds Length of the rate-limit window, in seconds.
	 * @return array Updated rate-limit record.
	 */
	public static function record_request( array $record, $now, $window_seconds ) {
		$fresh = empty( $record['window_started_at'] ) || $record['window_started_at'] <= ( $now - $window_seconds );
		return array(
			'window_started_at' => $fresh ? $now : $record['window_started_at'],
			'count'             => $fresh ? 1 : ( (int) ( $record['count'] ?? 0 ) + 1 ),
		);
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * Transient key used to store a user's rate-limit record.
	 *
	 * @param int $user_id User ID.
	 * @return string
	 */
	private static function rate_limit_key( $user_id ) {
		return 'is_rest_posts_rl_' . (int) $user_id;
	}

	/**
	 * Registers the integrity-sentinel/v1/posts REST route, if the module is enabled.
	 */
	public function register_routes() {
		if ( empty( self::settings()['enabled'] ) ) {
			return;
		}
		register_rest_route(
			'integrity-sentinel/v1',
			'/posts',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_create' ),
				'permission_callback' => array( $this, 'check_permission' ),
				'args'                => array(
					'title'      => array(
						'required' => true,
						'type'     => 'string',
					),
					'content'    => array(
						'required' => true,
						'type'     => 'string',
					),
					'status'     => array(
						'required' => false,
						'type'     => 'string',
						'default'  => 'draft',
					),
					'excerpt'    => array(
						'required' => false,
						'type'     => 'string',
					),
					'categories' => array(
						'required' => false,
						'type'     => 'array',
					),
					'tags'       => array(
						'required' => false,
						'type'     => 'array',
					),
				),
			)
		);
	}

	/**
	 * REST permission callback: requires an authenticated user with
	 * edit_posts, and applies this endpoint's per-user rate limit.
	 *
	 * @return true|WP_Error
	 */
	public function check_permission() {
		if ( ! is_user_logged_in() ) {
			return new WP_Error( 'is_rest_posts_unauthorized', __( 'Authentication required. Use a WordPress Application Password.', 'integrity-sentinel' ), array( 'status' => 401 ) );
		}
		if ( ! current_user_can( 'edit_posts' ) ) {
			return new WP_Error( 'is_rest_posts_forbidden', __( 'Your account does not have permission to create posts.', 'integrity-sentinel' ), array( 'status' => 403 ) );
		}

		$settings = self::settings();
		$record   = get_transient( self::rate_limit_key( get_current_user_id() ) );
		$record   = is_array( $record ) ? $record : array();
		if ( self::is_rate_limited( $record, time(), max( 1, (int) $settings['rate_limit'] ), self::RATE_LIMIT_WINDOW ) ) {
			return new WP_Error( 'is_rest_posts_rate_limited', __( 'Rate limit exceeded for this endpoint. Try again later.', 'integrity-sentinel' ), array( 'status' => 429 ) );
		}

		return true;
	}

	/**
	 * REST callback: creates a post from the request parameters,
	 * recording the request against the rate limit first.
	 *
	 * @param WP_REST_Request $request Incoming REST request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_create( WP_REST_Request $request ) {
		return IS_Guard::run(
			'rest_posts',
			function () use ( $request ) {
				$user_id = get_current_user_id();

				$record = get_transient( self::rate_limit_key( $user_id ) );
				$record = is_array( $record ) ? $record : array();
				$record = self::record_request( $record, time(), self::RATE_LIMIT_WINDOW );
				set_transient( self::rate_limit_key( $user_id ), $record, self::RATE_LIMIT_WINDOW );

				$title   = sanitize_text_field( (string) $request->get_param( 'title' ) );
				$content = wp_kses_post( (string) $request->get_param( 'content' ) );
				$excerpt = sanitize_textarea_field( (string) $request->get_param( 'excerpt' ) );
				$status  = self::sanitize_status( $request->get_param( 'status' ), current_user_can( 'publish_posts' ) );

				if ( '' === trim( $title ) || '' === trim( wp_strip_all_tags( $content ) ) ) {
					return new WP_Error( 'is_rest_posts_invalid', __( 'Both title and content are required.', 'integrity-sentinel' ), array( 'status' => 400 ) );
				}

				$postarr = array(
					'post_title'   => $title,
					'post_content' => $content,
					'post_excerpt' => $excerpt,
					'post_status'  => $status,
					'post_author'  => $user_id,
					'post_type'    => 'post',
				);

				$categories = $request->get_param( 'categories' );
				if ( is_array( $categories ) ) {
					$postarr['post_category'] = array_map( 'absint', $categories );
				}

				$post_id = wp_insert_post( $postarr, true );
				if ( is_wp_error( $post_id ) ) {
					return $post_id;
				}

				$tags = $request->get_param( 'tags' );
				if ( is_array( $tags ) ) {
					wp_set_post_tags( $post_id, array_map( 'sanitize_text_field', $tags ), false );
				}

				IS_Audit_Log::record(
					'rest_post_created',
					array(
						'post_id' => $post_id,
						'status'  => $status,
						'user_id' => $user_id,
					)
				);

				return new WP_REST_Response(
					array(
						'id'        => $post_id,
						'status'    => get_post_status( $post_id ),
						'edit_link' => get_edit_post_link( $post_id, 'raw' ),
						'permalink' => get_permalink( $post_id ),
					),
					201
				);
			},
			new WP_Error( 'is_rest_posts_error', __( 'Unexpected error creating the post.', 'integrity-sentinel' ), array( 'status' => 500 ) )
		);
	}
}

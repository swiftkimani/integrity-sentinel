<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two related login-hardening jobs:
 *
 *  1. Login URL rename: hides wp-login.php behind a custom slug, off by
 *     default (an empty slug leaves stock WordPress behaviour untouched).
 *     WordPress core builds every wp-login.php link through site_url()/
 *     network_site_url() (wp_login_url(), wp_logout_url(),
 *     wp_lostpassword_url(), the login form's own POST target, the
 *     password-protected-post form, ...), so filtering those two covers
 *     nearly everything for free -- only stale external links (old
 *     emails, hardcoded URLs) can still hit the literal wp-login.php,
 *     which is why a short allowlist of harmless direct actions exists
 *     below rather than a hard block on everything.
 *
 *  2. Login rate limiting: a per-IP failure counter (the same
 *     threshold/window/cooldown circuit-breaker shape as IS_Guard,
 *     applied to login attempts instead of module faults) that locks an
 *     IP out of authentication for a cooldown period after repeated
 *     failures. Whitelisted IPs (IS_IP_List) always bypass this.
 *
 * Both run through IS_Guard, and both are further covered by
 * IS_SAFE_MODE: a site owner who gets tangled up in either one can
 * define IS_SAFE_MODE in wp-config.php to fully restore stock
 * wp-login.php behaviour, no database access required.
 */
class IS_Login {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	private function hooks() {
		add_action( 'plugins_loaded', array( $this, 'maybe_intercept_login_url' ), 1 );
		add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 2 );
		add_filter( 'network_site_url', array( $this, 'filter_site_url' ), 10, 2 );

		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
		add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 0 );
		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 1 );
	}

	// ===================================================================
	// Login URL rename
	// ===================================================================

	public static function default_rename_settings() {
		return array( 'login_slug' => '' );
	}

	public static function rename_settings() {
		return wp_parse_args( get_option( 'is_login_rename_settings', array() ), self::default_rename_settings() );
	}

	/**
	 * Pure: normalizes a raw admin-entered slug down to safe characters
	 * and rejects anything that collides with a literal WordPress core
	 * path (which would create a conflict or an infinite loop).
	 */
	public static function sanitize_login_slug( $raw ) {
		$slug = strtolower( trim( (string) $raw ) );
		$slug = trim( $slug, '/' );
		$slug = preg_replace( '/[^a-z0-9\-_]/', '', $slug );

		if ( null === $slug || '' === $slug ) {
			return '';
		}

		// Character-stripped forms too (e.g. "wp-login.php" -> "wp-loginphp"
		// once dots are removed above) -- the check below runs after
		// stripping, so both spellings must be listed.
		$reserved = array(
			'wp-admin',
			'wp-login',
			'wp-login.php',
			'wp-loginphp',
			'wp-content',
			'wp-includes',
			'wp-json',
			'wp-cron.php',
			'wp-cronphp',
			'wp-signup.php',
			'wp-signupphp',
			'wp-activate.php',
			'wp-activatephp',
			'xmlrpc.php',
			'xmlrpcphp',
		);
		return in_array( $slug, $reserved, true ) ? '' : $slug;
	}

	/** Pure: strips the query string, decodes, and lowercases a request path. */
	public static function normalize_path( $uri ) {
		$uri = (string) $uri;
		$q   = strpos( $uri, '?' );
		if ( false !== $q ) {
			$uri = substr( $uri, 0, $q );
		}
		$uri = rawurldecode( $uri );
		$uri = rtrim( $uri, '/' );
		return strtolower( $uri );
	}

	public static function is_wp_login_request( $normalized_path ) {
		return (bool) preg_match( '#/wp-login\.php$#', $normalized_path );
	}

	/** Pure: does the request's last path segment match the configured slug exactly? */
	public static function path_matches_slug( $normalized_path, $slug ) {
		if ( '' === $slug || '' === $normalized_path ) {
			return false;
		}
		$segments = explode( '/', $normalized_path );
		return end( $segments ) === $slug;
	}

	/**
	 * A short allowlist of direct wp-login.php actions that are safe to
	 * let through even when hidden: each is either protected by its own
	 * key/nonce or is harmless to expose, and blocking them only breaks
	 * legitimate users following a stale external link -- it buys no
	 * extra security, since brute-force scanners target the credential
	 * form, not these.
	 */
	public static function should_allow_direct_wp_login( array $get ) {
		$action = isset( $get['action'] ) ? (string) $get['action'] : '';
		return in_array( $action, array( 'postpass', 'logout', 'confirmaction', 'confirm_admin_email' ), true );
	}

	/** Pure: rewrites a wp-login.php URL to use the custom slug instead. */
	public static function rewrite_login_url( $url, $slug ) {
		if ( '' === $slug || false === stripos( $url, 'wp-login.php' ) ) {
			return $url;
		}
		return str_ireplace( 'wp-login.php', $slug, $url );
	}

	public function filter_site_url( $url, $path ) {
		return IS_Guard::run(
			'login_rename',
			function () use ( $url ) {
				return self::rewrite_login_url( $url, self::rename_settings()['login_slug'] );
			},
			$url
		);
	}

	public function maybe_intercept_login_url() {
		IS_Guard::run(
			'login_rename',
			function () {
				$slug = self::rename_settings()['login_slug'];
				if ( '' === $slug ) {
					return;
				}

				$path = self::normalize_path( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- normalize_path() only strips/lowercases, no unsafe use

				if ( self::is_wp_login_request( $path ) ) {
					if ( self::should_allow_direct_wp_login( $_GET ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- read-only action-name check against a small allowlist
						return;
					}
					wp_die( esc_html__( 'Not Found', 'integrity-sentinel' ), '', array( 'response' => 404 ) );
				} elseif ( self::path_matches_slug( $path, $slug ) ) {
					require ABSPATH . 'wp-login.php';
					exit;
				}
			}
		);
	}

	// ===================================================================
	// Login rate limiting
	// ===================================================================

	public static function default_throttle_settings() {
		return array(
			'enabled'         => 1,
			'max_attempts'    => 5,
			'window_minutes'  => 15,
			'lockout_minutes' => 15,
		);
	}

	public static function throttle_settings() {
		return wp_parse_args( get_option( 'is_login_throttle_settings', array() ), self::default_throttle_settings() );
	}

	public static function default_attempt_record() {
		return array(
			'failures'     => array(),
			'locked_until' => null,
		);
	}

	public static function is_locked_out( array $record, $now ) {
		return ! empty( $record['locked_until'] ) && $record['locked_until'] > $now;
	}

	/**
	 * Pure state transition for one more failed attempt -- structurally
	 * identical to IS_Guard::failure_state()'s circuit breaker, applied
	 * to login attempts instead of module faults. No WordPress calls.
	 *
	 * @return array{record: array, just_locked: bool}
	 */
	public static function record_failure( array $record, $now, $threshold, $window_seconds, $lockout_seconds ) {
		$was_locked = self::is_locked_out( $record, $now );

		$failures   = array_values(
			array_filter(
				isset( $record['failures'] ) ? (array) $record['failures'] : array(),
				function ( $t ) use ( $now, $window_seconds ) {
					return $t > ( $now - $window_seconds );
				}
			)
		);
		$failures[] = $now;

		$locked_until = isset( $record['locked_until'] ) ? $record['locked_until'] : null;
		$just_locked  = false;

		if ( count( $failures ) >= $threshold ) {
			$locked_until = $now + $lockout_seconds;
			$just_locked  = ! $was_locked;
			$failures     = array();
		}

		return array(
			'record'      => array(
				'failures'     => $failures,
				'locked_until' => $locked_until,
			),
			'just_locked' => $just_locked,
		);
	}

	private static function transient_key( $ip ) {
		return 'is_login_attempts_' . md5( $ip );
	}

	private static function attempt_record( $ip ) {
		$stored = get_transient( self::transient_key( $ip ) );
		return is_array( $stored ) ? wp_parse_args( $stored, self::default_attempt_record() ) : self::default_attempt_record();
	}

	private static function persist_attempt_record( $ip, array $record, $ttl_seconds ) {
		set_transient( self::transient_key( $ip ), $record, max( MINUTE_IN_SECONDS, $ttl_seconds ) );
	}

	public function on_login_failed( $username ) {
		IS_Guard::run(
			'login_rate_limit',
			function () {
				$settings = self::throttle_settings();
				if ( empty( $settings['enabled'] ) || IS_IP_List::is_whitelisted() ) {
					return;
				}

				$ip = IS_IP_List::client_ip();
				if ( '' === $ip ) {
					return;
				}

				$window_seconds  = (int) $settings['window_minutes'] * MINUTE_IN_SECONDS;
				$lockout_seconds = (int) $settings['lockout_minutes'] * MINUTE_IN_SECONDS;

				$result = self::record_failure(
					self::attempt_record( $ip ),
					time(),
					(int) $settings['max_attempts'],
					$window_seconds,
					$lockout_seconds
				);
				self::persist_attempt_record( $ip, $result['record'], max( $window_seconds, $lockout_seconds ) );

				IS_Audit_Log::record( 'login_failed', array( 'ip' => $ip ) );

				if ( $result['just_locked'] ) {
					IS_Audit_Log::record(
						'login_ip_locked_out',
						array(
							'ip'      => $ip,
							'minutes' => $settings['lockout_minutes'],
						)
					);
					IS_Notifications::instance()->send_event(
						'login_lockout',
						__( 'Repeated failed logins — an IP has been temporarily locked out', 'integrity-sentinel' ),
						array(
							sprintf(
								/* translators: 1: IP address, 2: number of failed attempts, 3: lockout duration in minutes */
								__( 'IP %1$s failed to log in %2$d times and has been locked out of authentication for %3$d minutes.', 'integrity-sentinel' ),
								$ip,
								$settings['max_attempts'],
								$settings['lockout_minutes']
							),
							__( 'If this is you, wait for the lockout to expire or ask an administrator to add your IP to the Access Control whitelist.', 'integrity-sentinel' ),
						)
					);
				}
			}
		);
	}

	public function on_login_success() {
		IS_Guard::run(
			'login_rate_limit',
			function () {
				$ip = IS_IP_List::client_ip();
				if ( '' !== $ip ) {
					delete_transient( self::transient_key( $ip ) );
				}
			}
		);
	}

	public function check_lockout( $user ) {
		return IS_Guard::run(
			'login_rate_limit',
			function () use ( $user ) {
				$settings = self::throttle_settings();
				if ( empty( $settings['enabled'] ) || IS_IP_List::is_whitelisted() ) {
					return $user;
				}

				$ip = IS_IP_List::client_ip();
				if ( '' === $ip ) {
					return $user;
				}

				if ( self::is_locked_out( self::attempt_record( $ip ), time() ) ) {
					return new WP_Error( 'is_login_locked_out', __( 'Too many failed login attempts from your IP address. Please try again later.', 'integrity-sentinel' ) );
				}
				return $user;
			},
			$user
		);
	}
}

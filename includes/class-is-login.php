<?php
/**
 * Login URL hiding (custom slug/subdomain) and per-IP login rate limiting.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two related login-hardening jobs:
 *
 *  1. Login URL rename: hides wp-login.php and wp-admin behind a custom
 *     slug and/or a dedicated subdomain, both off by default (stock
 *     WordPress behaviour is untouched until at least one is set -- see
 *     maybe_intercept_login_url() for how the two combine). WordPress
 *     core builds every wp-login.php link through site_url()/
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
	 * Wires the login-url-rename and login-rate-limit hooks.
	 */
	private function hooks() {
		// 'init', not 'plugins_loaded': this class is instantiated from
		// is_init(), itself a 'plugins_loaded' callback -- a callback
		// registered for 'plugins_loaded' from inside another
		// 'plugins_loaded' callback is registered too late to ever run,
		// since that hook fires exactly once per request. 'init' fires
		// immediately after and hasn't happened yet at this point.
		add_action( 'init', array( $this, 'maybe_intercept_login_url' ), 1 );
		add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 2 );
		add_filter( 'network_site_url', array( $this, 'filter_site_url' ), 10, 2 );

		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
		add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 0 );
		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 1 );
	}

	// ===================================================================
	// Login URL rename
	// ===================================================================

	/**
	 * Default rename settings, used to fill in anything missing from the stored option.
	 */
	public static function default_rename_settings() {
		return array(
			'login_slug' => '',
			'login_host' => '',
		);
	}

	/**
	 * Returns the stored login-rename settings merged over the defaults.
	 */
	public static function rename_settings() {
		return wp_parse_args( get_option( 'is_login_rename_settings', array() ), self::default_rename_settings() );
	}

	/**
	 * Pure: normalizes a raw admin-entered slug down to safe characters
	 * and rejects anything that collides with a literal WordPress core
	 * path (which would create a conflict or an infinite loop).
	 *
	 * @param string $raw Raw, admin-entered slug.
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

	/**
	 * Pure: strips the query string, decodes, and lowercases a request path.
	 *
	 * @param string $uri Raw request URI.
	 */
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

	/**
	 * Pure: does this request target the literal wp-login.php file --
	 * either exactly, or with extra PATH_INFO appended after it (e.g.
	 * "/wp-login.php/x")? The trailing form still executes the real
	 * wp-login.php on servers that pass PATH_INFO through to PHP (a
	 * common Apache/mod_php default), so an exact-suffix-only check
	 * would leave that variant unblocked -- a real bypass of the "old
	 * default route" 404, not just a cosmetic gap.
	 *
	 * @param string $normalized_path Path as returned by normalize_path().
	 */
	public static function is_wp_login_request( $normalized_path ) {
		return (bool) preg_match( '#/wp-login\.php(?:/.*)?$#', $normalized_path );
	}

	/**
	 * Pure: does this request target the wp-admin directory itself (any
	 * file under it, or the bare directory)? Matches subdirectory
	 * installs too ("/blog/wp-admin/..."), not just a site root.
	 *
	 * @param string $normalized_path Path as returned by normalize_path().
	 */
	public static function is_wp_admin_request( $normalized_path ) {
		return (bool) preg_match( '#(?:^|/)wp-admin(?:/.*)?$#', $normalized_path );
	}

	/**
	 * A short allowlist of wp-admin endpoints that must stay reachable
	 * even for logged-out visitors once the login page is hidden:
	 * admin-ajax.php and admin-post.php are the standard front-end
	 * hooks countless plugins/themes rely on for logged-out AJAX and
	 * form submissions, and blocking them would break unrelated site
	 * functionality for zero security benefit -- neither one exposes an
	 * authentication form.
	 *
	 * @param string $normalized_path Path as returned by normalize_path().
	 */
	public static function should_allow_direct_wp_admin( $normalized_path ) {
		return (bool) preg_match( '#/wp-admin/admin-(?:ajax|post)\.php$#', $normalized_path );
	}

	/**
	 * Pure: normalizes a raw admin-entered hostname (which may have been
	 * pasted as a full URL) down to a bare, comparable host. Rejects
	 * anything that isn't a plausible hostname.
	 *
	 * @param string $raw Raw, admin-entered host (may be a full URL).
	 */
	public static function sanitize_login_host( $raw ) {
		$host = strtolower( trim( (string) $raw ) );
		$host = preg_replace( '#^[a-z][a-z0-9+.\-]*://#', '', $host );
		$host = preg_replace( '#/.*$#', '', $host );
		$host = preg_replace( '#:\d+$#', '', $host );

		if ( '' === $host || false === strpos( $host, '.' ) || ! preg_match( '/^[a-z0-9.\-]+$/', $host ) ) {
			return '';
		}
		return $host;
	}

	/**
	 * Pure: does the request's Host header match the configured login host?
	 *
	 * @param string $host_header     Raw Host header from the request.
	 * @param string $configured_host Configured login host to compare against.
	 */
	public static function is_configured_login_host( $host_header, $configured_host ) {
		if ( '' === $configured_host ) {
			return false;
		}
		$host = strtolower( trim( (string) $host_header ) );
		$host = preg_replace( '#:\d+$#', '', $host );
		return $host === $configured_host;
	}

	/**
	 * Pure: does the request's last path segment match the configured slug exactly?
	 *
	 * @param string $normalized_path Path as returned by normalize_path().
	 * @param string $slug            Configured login slug to compare against.
	 */
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
	 * form, not these. 'rp'/'resetpass' (the password-reset landing
	 * page and its submit step) matter specifically for host-only mode
	 * (no slug set): the reset email always links to the site's fixed
	 * siteurl host, never to the login subdomain, so without this the
	 * reset flow would 404 for anyone not already on that subdomain.
	 * Both are gated by a single-use, time-limited key, same as
	 * 'postpass' above -- not the credential form itself.
	 *
	 * @param array $get Superglobal-shaped array of GET parameters (e.g. $_GET).
	 */
	public static function should_allow_direct_wp_login( array $get ) {
		$action = isset( $get['action'] ) ? (string) $get['action'] : '';
		return in_array( $action, array( 'postpass', 'logout', 'confirmaction', 'confirm_admin_email', 'rp', 'resetpass' ), true );
	}

	/**
	 * Pure: rewrites a wp-login.php URL to use the custom slug instead.
	 *
	 * @param string $url  URL to rewrite.
	 * @param string $slug Configured login slug.
	 */
	public static function rewrite_login_url( $url, $slug ) {
		if ( '' === $slug || false === stripos( $url, 'wp-login.php' ) ) {
			return $url;
		}
		return str_ireplace( 'wp-login.php', $slug, $url );
	}

	/**
	 * Filter callback for the 'site_url'/'network_site_url' filters:
	 * rewrites wp-login.php links to use the configured slug, if any.
	 *
	 * @param string $url  URL being filtered.
	 * @param string $path Requested path component (unused; kept to match the filter signature).
	 */
	public function filter_site_url( $url, $path ) {
		return IS_Guard::run(
			'login_rename',
			function () use ( $url ) {
				return self::rewrite_login_url( $url, self::rename_settings()['login_slug'] );
			},
			$url
		);
	}

	/**
	 * Sends a real 404 status with a small, ordinary-looking error page
	 * -- deliberately generic wording (no mention of login/admin/hidden)
	 * so it reads exactly like any other "page not found" on the site,
	 * not a security block, and a themed page instead of wp_die()'s bare
	 * unstyled default. Includes a home link plus a no-JS-required
	 * meta-refresh so a visitor who lands here always has a way back,
	 * rather than a dead end.
	 */
	private static function render_not_found() {
		status_header( 404 );
		nocache_headers();

		$home = home_url( '/' );
		$name = get_bloginfo( 'name' );
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="<?php bloginfo( 'charset' ); ?>">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="refresh" content="8;url=<?php echo esc_url( $home ); ?>">
<title><?php esc_html_e( 'Page not found', 'integrity-sentinel' ); ?> — <?php echo esc_html( $name ); ?></title>
<style>
:root{color-scheme:light dark;}
*{box-sizing:border-box;}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f8fafc;color:#0f172a;}
.is-404-card{max-width:420px;text-align:center;}
.is-404-code{font-size:14px;font-weight:700;letter-spacing:.1em;color:#94a3b8;margin:0 0 14px;}
h1{font-size:26px;font-weight:800;margin:0 0 10px;letter-spacing:-0.01em;}
p{font-size:15px;line-height:1.6;color:#475569;margin:0 0 28px;}
a.is-404-button{display:inline-block;padding:12px 26px;border-radius:999px;background:#0f172a;color:#fff;text-decoration:none;font-weight:600;font-size:14px;}
a.is-404-button:hover{opacity:.88;}
.is-404-hint{margin-top:18px;font-size:12px;color:#94a3b8;}
@media (prefers-color-scheme: dark) {
	body{background:#0f172a;color:#f1f5f9;}
	.is-404-code{color:#64748b;}
	p{color:#94a3b8;}
	a.is-404-button{background:#f1f5f9;color:#0f172a;}
	.is-404-hint{color:#64748b;}
}
</style>
</head>
<body>
<div class="is-404-card">
	<p class="is-404-code">404</p>
	<h1><?php esc_html_e( "This page doesn't exist", 'integrity-sentinel' ); ?></h1>
	<p><?php esc_html_e( "The page you're looking for may have been moved or never existed.", 'integrity-sentinel' ); ?></p>
	<a class="is-404-button" href="<?php echo esc_url( $home ); ?>">
		<?php
		printf(
			/* translators: %s: site name */
			esc_html__( 'Take me to %s', 'integrity-sentinel' ),
			esc_html( $name )
		);
		?>
	</a>
	<p class="is-404-hint"><?php esc_html_e( 'Redirecting you there in a few seconds…', 'integrity-sentinel' ); ?></p>
</div>
</body>
</html>
		<?php
		exit;
	}

	/**
	 * Slug and host are independent switches -- either alone is a
	 * complete hiding mechanism, and both together compose cleanly:
	 *
	 *  - Slug only: the classic path rename. site_url()/network_site_url()
	 *    rewrite every wp-login.php link WordPress core generates
	 *    (password reset, logout, ...) to use the slug instead, on
	 *    whatever host the request arrives on -- so it needs no
	 *    per-host special-casing at all.
	 *  - Host only: no path rewrite happens (there's no slug to rewrite
	 *    to), so the configured host is instead treated as a fully
	 *    trusted alternate front door -- wp-login.php works there
	 *    completely unblocked, any action, exactly as stock WordPress
	 *    behaves. The one thing a host rewrite can't fix is that
	 *    site_url() resolves from the fixed `siteurl` option, not the
	 *    current request's Host header, so a password-reset email
	 *    always links to the main domain regardless of which host the
	 *    request was sent from -- which is why 'rp'/'resetpass' are in
	 *    the safe-action allowlist (see should_allow_direct_wp_login()).
	 *  - Both: the slug rewrite already covers every host, and the
	 *    host's own root becomes an extra memorable, path-free entry
	 *    alongside it.
	 *
	 * In every mode, the old default routes (wp-login.php and
	 * wp-admin on any host OTHER than a configured trusted one) 404
	 * for anyone not already logged in, rather than redirecting --
	 * see the wp-admin branch below for why a redirect isn't enough.
	 */
	public function maybe_intercept_login_url() {
		IS_Guard::run(
			'login_rename',
			function () {
				$settings = self::rename_settings();
				$slug     = $settings['login_slug'];
				$host_cfg = $settings['login_host'];
				if ( '' === $slug && '' === $host_cfg ) {
					return;
				}

				$path          = self::normalize_path( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- normalize_path() only strips/lowercases, no unsafe use
				$host          = isset( $_SERVER['HTTP_HOST'] ) ? wp_unslash( $_SERVER['HTTP_HOST'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only comparison against a stored hostname, no unsafe use
				$on_login_host = self::is_configured_login_host( $host, $host_cfg );

				// The configured subdomain's bare root always shows the
				// login form -- the whole point of the host feature is not
				// needing to remember/type a slug there.
				if ( '' === $path && $on_login_host ) {
					require ABSPATH . 'wp-login.php';
					exit;
				}

				if ( self::is_wp_login_request( $path ) ) {
					// On the trusted host, wp-login.php is the real front
					// door, not the "old default route" -- let it run
					// completely normally (any action, no allowlist).
					if ( $on_login_host || self::should_allow_direct_wp_login( $_GET ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- read-only action-name check against a small allowlist
						return;
					}
					self::render_not_found();
				} elseif ( '' !== $slug && self::path_matches_slug( $path, $slug ) ) {
					require ABSPATH . 'wp-login.php';
					exit;
				} elseif ( self::is_wp_admin_request( $path ) && ! self::should_allow_direct_wp_admin( $path ) && ! is_user_logged_in() ) {
					// The old default admin route must 404, not quietly
					// redirect an anonymous visitor to the renamed login
					// page -- a redirect still confirms "this site has a
					// hidden login" and hands a scanner a starting point.
					// Logged-in users are always let through unaffected,
					// on any host, once COOKIE_DOMAIN (if needed) makes
					// their session valid across hosts.
					self::render_not_found();
				}
			}
		);
	}

	// ===================================================================
	// Login rate limiting
	// ===================================================================

	/**
	 * Default throttle settings, used to fill in anything missing from the stored option.
	 */
	public static function default_throttle_settings() {
		return array(
			'enabled'                       => 1,
			'max_attempts'                  => 5,
			'window_minutes'                => 15,
			'lockout_minutes'               => 15,
			'credential_stuffing_threshold' => 8,
		);
	}

	/**
	 * Returns the stored login-throttle settings merged over the defaults.
	 */
	public static function throttle_settings() {
		return wp_parse_args( get_option( 'is_login_throttle_settings', array() ), self::default_throttle_settings() );
	}

	/**
	 * Pure: the default shape of a per-IP failed-attempt record.
	 */
	public static function default_attempt_record() {
		return array(
			'failures'     => array(),
			'locked_until' => null,
		);
	}

	/**
	 * Pure: is this record currently within its lockout period?
	 *
	 * @param array $record Attempt record, shaped like default_attempt_record().
	 * @param int   $now    Current timestamp.
	 */
	public static function is_locked_out( array $record, $now ) {
		return ! empty( $record['locked_until'] ) && $record['locked_until'] > $now;
	}

	/**
	 * Pure state transition for one more failed attempt -- structurally
	 * identical to IS_Guard::failure_state()'s circuit breaker, applied
	 * to login attempts instead of module faults. No WordPress calls.
	 *
	 * @param array $record          Attempt record, shaped like default_attempt_record().
	 * @param int   $now             Current timestamp.
	 * @param int   $threshold       Number of failures within the window before locking out.
	 * @param int   $window_seconds  Rolling window length in seconds.
	 * @param int   $lockout_seconds Lockout duration in seconds once triggered.
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

	/**
	 * Pure: the default shape of a per-IP distinct-username tracker --
	 * a rolling set (unique, order-preserving) of usernames tried from
	 * one IP. Time-windowing is handled by the transient's own TTL
	 * rather than per-entry timestamps, since the set only ever needs to
	 * answer "how many distinct usernames in the current window", not
	 * "which ones and when".
	 */
	public static function default_username_record() {
		return array( 'usernames' => array() );
	}

	/**
	 * Pure: adds $username to the record's rolling set of distinct usernames, if new.
	 *
	 * @param array  $record   Username-tracking record, shaped like default_username_record().
	 * @param string $username Username that was attempted.
	 */
	public static function record_username_attempt( array $record, $username ) {
		$usernames = isset( $record['usernames'] ) ? (array) $record['usernames'] : array();
		$username  = trim( (string) $username );
		if ( '' !== $username && ! in_array( $username, $usernames, true ) ) {
			$usernames[] = $username;
		}
		return array( 'usernames' => $usernames );
	}

	/**
	 * Pure: credential stuffing shows up as many DISTINCT usernames
	 * tried from one IP, unlike a simple brute force against one
	 * account (which the ordinary failure-count lockout above already
	 * handles) -- this is the complementary signal.
	 *
	 * @param array $record    Username-tracking record, shaped like default_username_record().
	 * @param int   $threshold Number of distinct usernames before flagging credential stuffing.
	 */
	public static function is_credential_stuffing( array $record, $threshold ) {
		$usernames = isset( $record['usernames'] ) ? (array) $record['usernames'] : array();
		return count( $usernames ) >= max( 2, (int) $threshold );
	}

	/**
	 * Builds the transient key for an IP's failed-attempt record.
	 *
	 * @param string $ip Client IP address.
	 */
	private static function transient_key( $ip ) {
		return 'is_login_attempts_' . md5( $ip );
	}

	/**
	 * Builds the transient key for an IP's distinct-username tracker.
	 *
	 * @param string $ip Client IP address.
	 */
	private static function username_transient_key( $ip ) {
		return 'is_login_usernames_' . md5( $ip );
	}

	/**
	 * Reads an IP's failed-attempt record from its transient, defaulting
	 * to an empty record if none is stored.
	 *
	 * @param string $ip Client IP address.
	 */
	private static function attempt_record( $ip ) {
		$stored = get_transient( self::transient_key( $ip ) );
		return is_array( $stored ) ? wp_parse_args( $stored, self::default_attempt_record() ) : self::default_attempt_record();
	}

	/**
	 * Stores an IP's failed-attempt record back into its transient.
	 *
	 * @param string $ip          Client IP address.
	 * @param array  $record      Attempt record to persist.
	 * @param int    $ttl_seconds Transient lifetime in seconds.
	 */
	private static function persist_attempt_record( $ip, array $record, $ttl_seconds ) {
		set_transient( self::transient_key( $ip ), $record, max( MINUTE_IN_SECONDS, $ttl_seconds ) );
	}

	/**
	 * Action callback for 'wp_login_failed': records the failure, escalates
	 * to a lockout and/or credential-stuffing alert when thresholds are hit.
	 *
	 * @param string $username Username that was attempted.
	 */
	public function on_login_failed( $username ) {
		IS_Guard::run(
			'login_rate_limit',
			function () use ( $username ) {
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

				// Credential stuffing: many DISTINCT usernames from one IP,
				// a different shape than the single-account brute force
				// the counter above already locks out. Tracked separately
				// so it fires (and escalates the lockout) even for an
				// attacker deliberately staying under the per-account
				// failure threshold by trying each username only once or
				// twice before moving on.
				$username_key    = self::username_transient_key( $ip );
				$username_record = get_transient( $username_key );
				$username_record = is_array( $username_record ) ? $username_record : self::default_username_record();
				$username_record = self::record_username_attempt( $username_record, $username );
				set_transient( $username_key, $username_record, $window_seconds );

				if ( self::is_credential_stuffing( $username_record, $settings['credential_stuffing_threshold'] ) ) {
					$stuffing_record                 = self::attempt_record( $ip );
					$stuffing_record['locked_until'] = time() + $lockout_seconds;
					self::persist_attempt_record( $ip, $stuffing_record, $lockout_seconds );
					delete_transient( $username_key );

					IS_Detections::fire(
						'credential_stuffing_detected',
						array(
							'ip'        => $ip,
							'usernames' => count( $username_record['usernames'] ),
							'minutes'   => $settings['lockout_minutes'],
						)
					);
				}
			}
		);
	}

	/**
	 * Action callback for 'wp_login': clears the client IP's failed-attempt
	 * record on a successful login.
	 */
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

	/**
	 * Filter callback for 'authenticate': rejects the login attempt with a
	 * WP_Error if the client IP is currently locked out.
	 *
	 * @param WP_User|WP_Error|null $user Value passed through the authenticate filter chain.
	 */
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

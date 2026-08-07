<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Session security, built entirely on WordPress core's own session-token
 * API (WP_Session_Tokens) rather than any custom session storage -- the
 * same mechanism behind profile.php's built-in "Log Out Everywhere Else"
 * button. Two things this adds beyond what core already ships:
 *
 *  1. Visibility: core's button is a single blind action with no view
 *     into what it's actually revoking. This lists every active session
 *     (IP, a short device/browser label, login time) so an admin can see
 *     WHERE their account is signed in before doing anything about it,
 *     and revoke individual sessions rather than only "all of them".
 *  2. Oversight: core has no UI at all for one admin to manage ANOTHER
 *     user's sessions. A manage_options user can force-logout any
 *     account's sessions entirely -- the actual incident-response move
 *     when an account looks compromised, today only reachable by editing
 *     the database directly.
 *
 * Also fires a one-time, non-blocking alert (email/webhook + audit log)
 * the first time an account logs in from an IP it hasn't used before --
 * a signal, not a lockout; travel and new devices are normal and
 * shouldn't cost anyone access, just get noticed.
 */
class IS_Sessions {

	private static $instance = null;

	const KNOWN_IPS_META_KEY  = '_is_known_login_ips';
	const LAST_LOGIN_META_KEY = '_is_last_login';
	const MAX_KNOWN_IPS       = 20;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	public static function default_settings() {
		return array(
			'alert_on_new_ip'                  => 1,
			'impossible_travel_detection'      => 1,
			'impossible_travel_window_minutes' => 60,
		);
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_session_settings', array() ), self::default_settings() );
	}

	private function hooks() {
		add_action( 'wp_login', array( $this, 'maybe_alert_new_ip' ), 10, 2 );
		add_action( 'admin_post_is_revoke_session', array( $this, 'handle_revoke_session' ) );
		add_action( 'admin_post_is_revoke_other_sessions', array( $this, 'handle_revoke_other_sessions' ) );
		add_action( 'admin_post_is_force_logout_user', array( $this, 'handle_force_logout_user' ) );
		add_filter( 'user_row_actions', array( $this, 'add_force_logout_row_action' ), 10, 2 );
	}

	// ===================================================================
	// Pure logic
	// ===================================================================

	/**
	 * Pure: is $ip new for this account? Never true when $known_ips is
	 * empty -- that's an account's very first-ever recorded login (or
	 * one that predates this feature), where everything would trivially
	 * look "new" and the alert would just be noise.
	 */
	public static function is_new_ip( $ip, array $known_ips ) {
		if ( '' === $ip || empty( $known_ips ) ) {
			return false;
		}
		return ! in_array( $ip, $known_ips, true );
	}

	/** Pure: appends $ip to $known_ips, de-duplicated, capped to the $max most recent. */
	public static function record_known_ip( array $known_ips, $ip, $max = self::MAX_KNOWN_IPS ) {
		if ( '' === $ip ) {
			return array_values( $known_ips );
		}
		$known_ips   = array_values( array_diff( $known_ips, array( $ip ) ) );
		$known_ips[] = $ip;
		if ( count( $known_ips ) > $max ) {
			$known_ips = array_slice( $known_ips, -1 * $max );
		}
		return $known_ips;
	}

	/**
	 * Pure: the /16 subnet (first two IPv4 octets) of an address, or
	 * null for anything that isn't a plain IPv4 address -- this
	 * heuristic deliberately doesn't attempt an IPv6 equivalent (prefix
	 * boundaries there don't map cleanly to "roughly the same network"
	 * the way a /16 does for IPv4).
	 */
	public static function ipv4_slash16( $ip ) {
		if ( ! preg_match( '/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/', (string) $ip, $m ) ) {
			return null;
		}
		return $m[1] . '.' . $m[2];
	}

	/**
	 * Pure: does this login look like impossible travel -- a different
	 * /16 subnet than the account's immediately preceding login, within
	 * an implausibly short time of it? A geo-IP database would give a
	 * true distance/speed calculation; this trades that precision for
	 * zero bundled data and no external lookups, on the theory that
	 * "same account, wildly different network, within the hour" is
	 * already a strong enough signal on its own. Never fires without a
	 * genuine previous login on record, or across two logins outside the
	 * window, or when either address isn't plain IPv4.
	 *
	 * @param array{ip?:string,time?:int} $previous
	 */
	public static function is_impossible_travel( array $previous, $ip, $now, $window_seconds ) {
		if ( empty( $previous['ip'] ) || empty( $previous['time'] ) ) {
			return false;
		}
		if ( ( $now - (int) $previous['time'] ) > max( 1, (int) $window_seconds ) ) {
			return false;
		}
		$prev_subnet = self::ipv4_slash16( $previous['ip'] );
		$new_subnet  = self::ipv4_slash16( $ip );
		if ( null === $prev_subnet || null === $new_subnet ) {
			return false;
		}
		return $prev_subnet !== $new_subnet;
	}

	/**
	 * Pure: a short, human-readable device/browser label from a user
	 * agent string -- good enough to tell "Chrome on Mac" apart from
	 * "Safari on iPhone" in a session list; not a full UA parser.
	 */
	public static function describe_user_agent( $ua ) {
		$ua = (string) $ua;
		if ( '' === $ua ) {
			return __( 'Unknown device', 'integrity-sentinel' );
		}

		$browser = __( 'Browser', 'integrity-sentinel' );
		if ( false !== stripos( $ua, 'Edg/' ) ) {
			$browser = 'Edge';
		} elseif ( false !== stripos( $ua, 'OPR/' ) || false !== stripos( $ua, 'Opera' ) ) {
			$browser = 'Opera';
		} elseif ( false !== stripos( $ua, 'Firefox' ) ) {
			$browser = 'Firefox';
		} elseif ( false !== stripos( $ua, 'Chrome' ) ) {
			$browser = 'Chrome';
		} elseif ( false !== stripos( $ua, 'Safari' ) ) {
			$browser = 'Safari';
		}

		$os = '';
		if ( false !== stripos( $ua, 'iPhone' ) || false !== stripos( $ua, 'iPad' ) ) {
			$os = 'iOS';
		} elseif ( false !== stripos( $ua, 'Android' ) ) {
			$os = 'Android';
		} elseif ( false !== stripos( $ua, 'Mac OS X' ) ) {
			$os = 'macOS';
		} elseif ( false !== stripos( $ua, 'Windows' ) ) {
			$os = 'Windows';
		} elseif ( false !== stripos( $ua, 'Linux' ) ) {
			$os = 'Linux';
		}

		return '' !== $os ? "{$browser} on {$os}" : $browser;
	}

	// ===================================================================
	// New-IP alert
	// ===================================================================

	public function maybe_alert_new_ip( $user_login, $user ) {
		IS_Guard::run(
			'session_security',
			function () use ( $user ) {
				$settings = self::settings();
				$ip       = IS_IP_List::client_ip();
				if ( '' === $ip ) {
					return;
				}

				$known = (array) get_user_meta( $user->ID, self::KNOWN_IPS_META_KEY, true );

				if ( ! empty( $settings['alert_on_new_ip'] ) && self::is_new_ip( $ip, $known ) ) {
					IS_Audit_Log::record(
						'login_from_new_ip',
						array(
							'user_id'    => $user->ID,
							'user_login' => $user->user_login,
							'ip'         => $ip,
						)
					);
					IS_Notifications::instance()->send_event(
						'login_from_new_ip',
						__( 'Admin login from a new IP address', 'integrity-sentinel' ),
						array(
							sprintf(
								/* translators: 1: username, 2: IP address */
								__( 'The account "%1$s" just logged in from IP %2$s, which hasn\'t been seen for this account before.', 'integrity-sentinel' ),
								$user->user_login,
								$ip
							),
							__( 'If this was you (a new device, or traveling), no action needed. If not, change this account\'s password immediately and review its active sessions under Integrity Sentinel → Login Security.', 'integrity-sentinel' ),
						)
					);
				}

				$now      = time();
				$previous = (array) get_user_meta( $user->ID, self::LAST_LOGIN_META_KEY, true );
				if ( ! empty( $settings['impossible_travel_detection'] ) ) {
					$window_seconds = (int) $settings['impossible_travel_window_minutes'] * MINUTE_IN_SECONDS;
					if ( self::is_impossible_travel( $previous, $ip, $now, $window_seconds ) ) {
						IS_Detections::fire(
							'impossible_travel_suspected',
							array(
								'user_id'     => $user->ID,
								'user_login'  => $user->user_login,
								'previous_ip' => $previous['ip'],
								'new_ip'      => $ip,
								'seconds'     => $now - (int) $previous['time'],
							)
						);
					}
				}

				update_user_meta(
					$user->ID,
					self::LAST_LOGIN_META_KEY,
					array(
						'ip'   => $ip,
						'time' => $now,
					)
				);
				update_user_meta( $user->ID, self::KNOWN_IPS_META_KEY, self::record_known_ip( $known, $ip ) );
			}
		);
	}

	// ===================================================================
	// Session listing + revocation (self)
	// ===================================================================

	/** @return array<string,array> token => session data (expiration, ip, ua, login), each with an added 'is_current' bool. */
	public static function sessions_for( $user_id ) {
		$sessions = WP_Session_Tokens::get_instance( $user_id )->get_all();
		$current  = ( get_current_user_id() === (int) $user_id ) ? wp_get_session_token() : '';
		foreach ( $sessions as $token => &$session ) {
			$session['is_current'] = ( $token === $current );
		}
		unset( $session );
		return $sessions;
	}

	public function handle_revoke_session() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_revoke_session' );
		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		if ( '' !== $token ) {
			WP_Session_Tokens::get_instance( get_current_user_id() )->destroy( $token );
			IS_Audit_Log::record( 'session_revoked', array( 'target' => 'self' ) );
		}
		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url( 'admin.php?page=integrity-sentinel-login' ) );
		exit;
	}

	public function handle_revoke_other_sessions() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_revoke_other_sessions' );
		wp_destroy_other_sessions();
		IS_Audit_Log::record( 'session_revoked_others', array( 'target' => 'self' ) );
		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url( 'admin.php?page=integrity-sentinel-login' ) );
		exit;
	}

	// ===================================================================
	// Force-logout another user (incident response)
	// ===================================================================

	public function handle_force_logout_user() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_force_logout_user' );
		$user_id = isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : 0;
		$user    = $user_id ? get_userdata( $user_id ) : false;
		if ( $user ) {
			WP_Session_Tokens::get_instance( $user_id )->destroy_all();
			IS_Audit_Log::record(
				'session_force_logout',
				array(
					'target_user_id'    => $user_id,
					'target_user_login' => $user->user_login,
				)
			);
		}
		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url( 'users.php' ) );
		exit;
	}

	/** Adds a "Log out all sessions" row action on the Users list for other accounts with an active session. */
	public function add_force_logout_row_action( array $actions, $user_object ) {
		return IS_Guard::run(
			'session_security',
			function () use ( $actions, $user_object ) {
				if ( ! current_user_can( 'manage_options' ) || get_current_user_id() === (int) $user_object->ID ) {
					return $actions;
				}
				if ( empty( WP_Session_Tokens::get_instance( $user_object->ID )->get_all() ) ) {
					return $actions;
				}
				$url                        = wp_nonce_url(
					add_query_arg(
						array(
							'action'  => 'is_force_logout_user',
							'user_id' => $user_object->ID,
						),
						admin_url( 'admin-post.php' )
					),
					'is_force_logout_user'
				);
				$actions['is_force_logout'] = sprintf(
					'<a href="%s" onclick="return confirm(%s);">%s</a>',
					esc_url( $url ),
					"'" . esc_js( __( 'Log this user out of every active session immediately?', 'integrity-sentinel' ) ) . "'",
					esc_html__( 'Log out all sessions', 'integrity-sentinel' )
				);
				return $actions;
			},
			$actions
		);
	}
}

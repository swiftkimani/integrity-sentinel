<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Active defense, not passive detection: a small set of fake sensitive
 * paths (a decoy .env, a decoy backup archive, ...) that no legitimate
 * visitor or logged-in admin has any reason to ever request, plus one
 * decoy "canary token" value meant to be planted somewhere an attacker
 * exfiltrating secrets might find it. Touching either one is about as
 * close to unambiguous proof of malicious probing as this plugin can
 * get, so both respond the same way: an immediate temporary IP ban
 * (IS_IP_List::temp_ban()) plus a critical-severity detection.
 *
 * Both traps fail closed toward doing nothing rather than false-
 * positiving on real traffic: honeypot paths never match anything a
 * real page/asset could be at, the canary check is a constant-time
 * exact-token comparison, and a logged-in admin poking around out of
 * curiosity is always exempted.
 */
class IS_Deception {

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
			'enabled'      => 1,
			'ban_minutes'  => 60,
			'canary_token' => '',
		);
	}

	/** Lazily generates the canary token on first use, same "self-heals a missing default" shape as other modules' settings(). */
	public static function settings() {
		$settings = wp_parse_args( get_option( 'is_deception_settings', array() ), self::default_settings() );
		if ( '' === $settings['canary_token'] ) {
			$settings['canary_token'] = self::generate_canary_token();
			update_option( 'is_deception_settings', $settings, false );
		}
		return $settings;
	}

	private function hooks() {
		add_action( 'template_redirect', array( $this, 'maybe_trigger_honeypot' ), 1 );
		add_action( 'rest_api_init', array( $this, 'register_canary_route' ) );
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * A handful of paths a real site never legitimately serves, chosen
	 * to mimic exactly what an attacker's own reconnaissance tooling
	 * probes for -- leaked config files and backup archives are near
	 * the top of every automated WordPress-scanner's checklist.
	 *
	 * @return string[]
	 */
	public static function honeypot_paths() {
		return array(
			'/.env',
			'/.env.production',
			'/wp-content/uploads/backup.zip',
			'/wp-content/uploads/database.sql',
			'/wp-content/db-backup.sql',
			'/xmlrpc-old.php',
			'/wp-admin/setup-config.old.php',
		);
	}

	public static function is_honeypot_path( $normalized_path ) {
		return in_array( $normalized_path, self::honeypot_paths(), true );
	}

	public static function generate_canary_token() {
		return wp_generate_password( 40, false, false );
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	public function maybe_trigger_honeypot() {
		IS_Guard::run(
			'deception',
			function () {
				$settings = self::settings();
				if ( empty( $settings['enabled'] ) || is_user_logged_in() ) {
					return;
				}

				$path = IS_Login::normalize_path( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- normalize_path() only strips/lowercases, no unsafe use
				if ( ! self::is_honeypot_path( $path ) ) {
					return;
				}

				self::respond_to_trap( $settings, 'honeypot_triggered', array( 'path' => $path ) );
			}
		);
	}

	public function register_canary_route() {
		register_rest_route(
			'integrity-sentinel/v1',
			'/canary',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'handle_canary_check' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'token' => array(
						'required' => true,
						'type'     => 'string',
					),
				),
			)
		);
	}

	public function handle_canary_check( WP_REST_Request $request ) {
		return IS_Guard::run(
			'deception',
			function () use ( $request ) {
				$settings = self::settings();
				$token    = (string) $request->get_param( 'token' );

				if ( ! empty( $settings['enabled'] ) && '' !== $token && hash_equals( $settings['canary_token'], $token ) ) {
					self::respond_to_trap( $settings, 'canary_token_used', array() );
				}

				// Same 404 whether the token matched or not -- a real
				// mismatch and "you got caught" must be indistinguishable
				// to whoever's probing this endpoint.
				return new WP_REST_Response( array(), 404 );
			},
			new WP_REST_Response( array(), 404 )
		);
	}

	/** Shared response to either trap firing: temp-ban (unless whitelisted), fire the detection, and (for the honeypot path only) render a plain 404. */
	private static function respond_to_trap( array $settings, $rule_id, array $extra_detail ) {
		$ip = IS_IP_List::client_ip();
		if ( '' !== $ip && ! IS_IP_List::is_whitelisted( $ip ) ) {
			IS_IP_List::temp_ban( $ip, $rule_id, (int) $settings['ban_minutes'] * MINUTE_IN_SECONDS );
		}
		IS_Detections::fire( $rule_id, array_merge( array( 'ip' => $ip ), $extra_detail ) );

		if ( 'honeypot_triggered' === $rule_id ) {
			status_header( 404 );
			nocache_headers();
			wp_die( '', '', array( 'response' => 404 ) );
		}
	}

	public static function regenerate_canary_token() {
		$settings                 = self::settings();
		$settings['canary_token'] = self::generate_canary_token();
		update_option( 'is_deception_settings', $settings, false );
		return $settings['canary_token'];
	}

	/** The full bait URL to plant wherever an attacker exfiltrating secrets might find it. */
	public static function canary_url() {
		return add_query_arg( 'token', self::settings()['canary_token'], rest_url( 'integrity-sentinel/v1/canary' ) );
	}
}

<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Enforces a minimum password strength server-side. WordPress core's own
 * zxcvbn-based meter (visible on every password field) is advisory only
 * -- it colors a bar and shows a label, but a user can submit "password1"
 * anyway and core accepts it. This actually blocks weak ones, on both
 * places WordPress core validates a new password:
 *
 *  - `validate_password_reset` -- the "forgot your password" email-link
 *    flow (wp-login.php?action=resetpass).
 *  - `user_profile_update_errors` -- profile.php/user-edit.php, which
 *    covers both a user changing their own password and an admin
 *    setting one for someone else (including new-user creation, which
 *    routes through the same core function). At this hook, WordPress
 *    core's own convention is that $user->user_pass holds the raw,
 *    not-yet-hashed submitted password -- the same mechanism plugins
 *    like "Force Strong Passwords" rely on.
 *
 * Off by default: a site with existing users and no minimum today would
 * otherwise start rejecting password changes the moment this activates,
 * which is exactly the kind of surprise this plugin avoids shipping on
 * by default elsewhere (login rename, XML-RPC, full REST lockdown, ...).
 */
class IS_Password_Policy {

	private static $instance = null;

	/**
	 * A short, well-known-weak-password blocklist -- not exhaustive (this
	 * isn't a substitute for a real breached-password database), but
	 * catches the handful of passwords that show up first in every
	 * credential-stuffing wordlist and that length/character-class rules
	 * alone wouldn't reject (e.g. "Password1!" satisfies every rule below
	 * and is still one of the most-guessed passwords there is).
	 */
	const COMMON_PASSWORDS = array(
		'password',
		'password1',
		'password1!',
		'Password1',
		'Password1!',
		'12345678',
		'123456789',
		'1234567890',
		'qwertyuiop',
		'qwerty123',
		'letmein',
		'welcome',
		'welcome1',
		'admin123',
		'iloveyou',
		'password123',
		'abc123456',
		'changeme',
		'changeme1',
	);

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	public static function default_settings() {
		return array(
			'enabled'            => 0,
			'min_length'         => 12,
			'require_mixed_case' => 1,
			'require_number'     => 1,
			'require_symbol'     => 0,
		);
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_password_policy_settings', array() ), self::default_settings() );
	}

	private function hooks() {
		add_action( 'validate_password_reset', array( $this, 'check_password_reset' ), 10, 2 );
		add_action( 'user_profile_update_errors', array( $this, 'check_profile_update' ), 10, 3 );
	}

	// ===================================================================
	// Pure logic
	// ===================================================================

	/**
	 * Pure: every rule violation for $password given $settings, as
	 * ready-to-display messages. Empty array = passes every enabled rule.
	 */
	public static function password_issues( $password, array $settings ) {
		$password = (string) $password;
		$issues   = array();

		$min_length = max( 1, (int) ( $settings['min_length'] ?? 12 ) );
		if ( strlen( $password ) < $min_length ) {
			$issues[] = sprintf(
				/* translators: %d: minimum character count */
				__( 'Must be at least %d characters long.', 'integrity-sentinel' ),
				$min_length
			);
		}

		if ( ! empty( $settings['require_mixed_case'] ) && ( ! preg_match( '/[a-z]/', $password ) || ! preg_match( '/[A-Z]/', $password ) ) ) {
			$issues[] = __( 'Must include both uppercase and lowercase letters.', 'integrity-sentinel' );
		}

		if ( ! empty( $settings['require_number'] ) && ! preg_match( '/[0-9]/', $password ) ) {
			$issues[] = __( 'Must include at least one number.', 'integrity-sentinel' );
		}

		if ( ! empty( $settings['require_symbol'] ) && ! preg_match( '/[^a-zA-Z0-9]/', $password ) ) {
			$issues[] = __( 'Must include at least one symbol (e.g. !@#$%).', 'integrity-sentinel' );
		}

		if ( in_array( strtolower( $password ), array_map( 'strtolower', self::COMMON_PASSWORDS ), true ) ) {
			$issues[] = __( 'This is one of the most commonly used passwords and is guessed within seconds by automated attacks.', 'integrity-sentinel' );
		}

		return $issues;
	}

	// ===================================================================
	// WordPress glue
	// ===================================================================

	public function check_password_reset( $errors, $user ) {
		IS_Guard::run(
			'password_policy',
			function () use ( $errors ) {
				if ( empty( self::settings()['enabled'] ) ) {
					return;
				}
				$password = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only strength check; the reset form's own signed key is the actual authorization
				if ( '' === $password ) {
					return;
				}
				foreach ( self::password_issues( $password, self::settings() ) as $issue ) {
					$errors->add( 'is_weak_password', $issue );
				}
			}
		);
	}

	public function check_profile_update( $errors, $update, $user ) {
		IS_Guard::run(
			'password_policy',
			function () use ( $errors, $user ) {
				if ( empty( self::settings()['enabled'] ) || empty( $user->user_pass ) ) {
					return;
				}
				foreach ( self::password_issues( $user->user_pass, self::settings() ) as $issue ) {
					$errors->add( 'is_weak_password', $issue );
				}
			}
		);
	}
}

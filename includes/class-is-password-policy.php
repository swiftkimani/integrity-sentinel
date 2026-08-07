<?php
/**
 * Enforces a minimum password strength server-side, on both of WordPress
 * core's password-set hooks.
 *
 * @package Integrity_Sentinel
 */

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

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
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
	 * Default settings, used to fill in anything missing from the stored option.
	 */
	public static function default_settings() {
		return array(
			'enabled'            => 0,
			'min_length'         => 12,
			'require_mixed_case' => 1,
			'require_number'     => 1,
			'require_symbol'     => 0,
		);
	}

	/**
	 * Stored settings, merged over default_settings().
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_password_policy_settings', array() ), self::default_settings() );
	}

	/**
	 * Registers the WordPress hooks that enforce this policy.
	 */
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
	 *
	 * @param string $password The candidate password to check.
	 * @param array  $settings Settings shaped like default_settings().
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

	/**
	 * Hooked to `validate_password_reset`: adds a WP_Error for every rule
	 * violation in the submitted reset-form password.
	 *
	 * @param WP_Error $errors Error collector to append to.
	 * @param WP_User  $user   User the reset is for (unused; the raw password
	 *                         only lives in $_POST at this hook).
	 */
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

	/**
	 * Hooked to `user_profile_update_errors`: adds a WP_Error for every
	 * rule violation when a password is being set on an existing user
	 * (self-service change or an admin setting/creating one).
	 *
	 * @param WP_Error $errors Error collector to append to.
	 * @param bool     $update Whether this is an existing-user update (unused).
	 * @param WP_User  $user   User object; at this hook $user->user_pass holds
	 *                         the raw, not-yet-hashed submitted password.
	 */
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

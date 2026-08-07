<?php
/**
 * TOTP-based two-factor authentication, with per-user opt-in and optional
 * per-role enforcement, login-time verification, and single-use recovery codes.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * TOTP-based two-factor authentication built on IS_TOTP. Per-user,
 * opt-in by default; a site can additionally enforce it for specific
 * roles, but enforcement never blocks login itself -- an enforced user
 * who hasn't set up 2FA yet is nudged to their profile to set it up
 * rather than locked out, which is what makes turning enforcement on
 * safe to do without warning every affected user first.
 *
 * Setup requires proving the authenticator app actually works (entering
 * one valid code) before 2FA is actually enabled, so a mistyped/
 * unsynced secret can never lock a user out of their own account.
 * Recovery codes are stored as SHA-256 hashes, never in plaintext, and
 * each is single-use.
 *
 * The whole login-interception flow runs through IS_Guard and is
 * covered by IS_SAFE_MODE, same as the login-rename/rate-limit features
 * in IS_Login.
 */
class IS_2FA {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	const PENDING_TTL         = 10 * MINUTE_IN_SECONDS;
	const MAX_CODE_ATTEMPTS   = 5;
	const RECOVERY_CODE_COUNT = 8;

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
		return array( 'enforced_roles' => array() );
	}

	/**
	 * Stored settings, merged over default_settings().
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_2fa_settings', array() ), self::default_settings() );
	}

	/**
	 * Registers the WordPress hooks that drive setup, login-time
	 * verification, profile-screen UI, and role-based enforcement.
	 */
	private function hooks() {
		add_filter( 'authenticate', array( $this, 'maybe_intercept_login' ), 40 );
		add_action( 'login_form_is_2fa', array( $this, 'handle_verify_screen' ) );
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'admin_post_is_2fa_setup_start', array( $this, 'handle_setup_start' ) );
		add_action( 'admin_post_is_2fa_setup_confirm', array( $this, 'handle_setup_confirm' ) );
		add_action( 'admin_post_is_2fa_disable', array( $this, 'handle_disable' ) );
		add_action( 'admin_post_is_2fa_regenerate_recovery', array( $this, 'handle_regenerate_recovery' ) );
		add_action( 'admin_init', array( $this, 'maybe_enforce_setup' ) );
	}

	// ===================================================================
	// Pure logic
	// ===================================================================

	/**
	 * Pure: hashes a recovery code (after normalizing it) for storage/comparison.
	 *
	 * @param string $code Recovery code, in whatever formatting the user typed.
	 * @return string SHA-256 hash of the normalized code.
	 */
	public static function hash_recovery_code( $code ) {
		return hash( 'sha256', self::normalize_recovery_code( $code ) );
	}

	/**
	 * Pure: strips everything but alphanumerics and uppercases, so "ab12-cd34" and "AB12CD34" match.
	 *
	 * @param string $code Recovery code, in whatever formatting the user typed.
	 * @return string Normalized code.
	 */
	public static function normalize_recovery_code( $code ) {
		return strtoupper( preg_replace( '/[^A-Za-z0-9]/', '', (string) $code ) );
	}

	/**
	 * Pure: finds a matching recovery-code hash for the submitted code
	 * and returns the remaining hash list with it removed (single-use).
	 * Constant-time comparison per candidate.
	 *
	 * @param string[] $hashed_codes   Stored recovery-code hashes to check against.
	 * @param string   $submitted_code Recovery code submitted by the user, unhashed.
	 * @return array{matched: bool, remaining: string[]}
	 */
	public static function consume_recovery_code( array $hashed_codes, $submitted_code ) {
		$submitted_hash = self::hash_recovery_code( $submitted_code );
		foreach ( $hashed_codes as $i => $hash ) {
			if ( hash_equals( $hash, $submitted_hash ) ) {
				$remaining = $hashed_codes;
				unset( $remaining[ $i ] );
				return array(
					'matched'   => true,
					'remaining' => array_values( $remaining ),
				);
			}
		}
		return array(
			'matched'   => false,
			'remaining' => $hashed_codes,
		);
	}

	/**
	 * Pure: whether any of the user's roles are in the enforced-roles list.
	 *
	 * @param string[] $user_roles     Roles assigned to the user.
	 * @param string[] $enforced_roles Roles for which 2FA is enforced.
	 * @return bool
	 */
	public static function role_requires_2fa( array $user_roles, array $enforced_roles ) {
		return (bool) array_intersect( $user_roles, $enforced_roles );
	}

	// ===================================================================
	// WP-dependent glue: per-user state
	// ===================================================================

	/**
	 * Whether 2FA is enabled (fully set up and confirmed) for the given user.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_enabled( $user_id ) {
		return '1' === get_user_meta( $user_id, '_is_2fa_enabled', true );
	}

	/**
	 * The user's stored TOTP secret, or an empty string if none is set.
	 *
	 * @param int $user_id User ID.
	 * @return string
	 */
	public static function secret( $user_id ) {
		return (string) get_user_meta( $user_id, '_is_2fa_secret', true );
	}

	/**
	 * The user's stored recovery-code hashes.
	 *
	 * @param int $user_id User ID.
	 * @return string[]
	 */
	public static function recovery_hashes( $user_id ) {
		$stored = get_user_meta( $user_id, '_is_2fa_recovery_codes', true );
		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * Generates a fresh batch of recovery codes, stores their hashes
	 * (replacing any existing ones), and returns the plaintext codes.
	 *
	 * @param int $user_id User ID.
	 * @return string[] Plaintext codes -- shown to the user exactly once.
	 */
	public static function generate_recovery_codes( $user_id ) {
		$plain  = array();
		$hashed = array();
		for ( $i = 0; $i < self::RECOVERY_CODE_COUNT; $i++ ) {
			$code     = strtoupper( bin2hex( random_bytes( 5 ) ) ); // 10 hex chars, e.g. "A1B2C3D4E5"
			$plain[]  = substr( $code, 0, 5 ) . '-' . substr( $code, 5 );
			$hashed[] = self::hash_recovery_code( $code );
		}
		update_user_meta( $user_id, '_is_2fa_recovery_codes', $hashed );
		return $plain;
	}

	// ===================================================================
	// Setup flow (admin-post, from the user's own profile screen)
	// ===================================================================

	/**
	 * Confirms the current user is acting on their own account and that the
	 * request carries a valid nonce, dying with an error otherwise.
	 *
	 * @param int $target_user_id User ID the action is being performed on.
	 */
	private function guard_own_profile_action( $target_user_id ) {
		if ( get_current_user_id() !== (int) $target_user_id || ! current_user_can( 'read' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_2fa_action' );
	}

	/** Generates a new secret and stashes it in a short-lived transient pending confirmation. */
	public function handle_setup_start() {
		$user_id = get_current_user_id();
		$this->guard_own_profile_action( $user_id );

		$secret = IS_TOTP::generate_secret();
		set_transient( 'is_2fa_setup_' . $user_id, $secret, 15 * MINUTE_IN_SECONDS );

		IS_Audit_Log::record( '2fa_setup_started', array( 'user_id' => $user_id ) );
		wp_safe_redirect( add_query_arg( 'is_2fa_setup', '1', get_edit_profile_url( $user_id ) ) . '#is-2fa' );
		exit;
	}

	/** Requires one valid code against the pending secret before actually enabling 2FA. */
	public function handle_setup_confirm() {
		$user_id = get_current_user_id();
		$this->guard_own_profile_action( $user_id );

		$secret = get_transient( 'is_2fa_setup_' . $user_id );
		$code   = isset( $_POST['is_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['is_2fa_code'] ) ) : '';

		$redirect = get_edit_profile_url( $user_id ) . '#is-2fa';

		if ( ! $secret || ! IS_TOTP::verify( $secret, $code, time() ) ) {
			wp_safe_redirect( add_query_arg( 'is_2fa_error', '1', $redirect ) );
			exit;
		}

		update_user_meta( $user_id, '_is_2fa_secret', $secret );
		update_user_meta( $user_id, '_is_2fa_enabled', '1' );
		delete_transient( 'is_2fa_setup_' . $user_id );

		$codes = self::generate_recovery_codes( $user_id );
		set_transient( 'is_2fa_recovery_display_' . $user_id, $codes, MINUTE_IN_SECONDS ); // shown exactly once, right after this redirect.

		IS_Audit_Log::record( '2fa_enabled', array( 'user_id' => $user_id ) );
		IS_Notifications::instance()->send_event(
			'2fa_enabled',
			__( 'Two-factor authentication was enabled on an account', 'integrity-sentinel' ),
			array(
				sprintf(
					/* translators: %s: user login */
					__( 'Two-factor authentication was just enabled for the account "%s". If this was not you, an attacker with access to that account cannot be locked out by this alone -- review the account immediately.', 'integrity-sentinel' ),
					get_userdata( $user_id )->user_login
				),
			)
		);

		wp_safe_redirect( add_query_arg( 'is_2fa_enabled', '1', $redirect ) );
		exit;
	}

	/**
	 * Disables 2FA for the current user: clears the enabled flag, secret,
	 * and recovery codes, and notifies of the change.
	 */
	public function handle_disable() {
		$user_id = get_current_user_id();
		$this->guard_own_profile_action( $user_id );

		delete_user_meta( $user_id, '_is_2fa_enabled' );
		delete_user_meta( $user_id, '_is_2fa_secret' );
		delete_user_meta( $user_id, '_is_2fa_recovery_codes' );

		IS_Audit_Log::record( '2fa_disabled', array( 'user_id' => $user_id ) );
		IS_Notifications::instance()->send_event(
			'2fa_disabled',
			__( 'Two-factor authentication was disabled on an account', 'integrity-sentinel' ),
			array(
				sprintf(
					/* translators: %s: user login */
					__( 'Two-factor authentication was just disabled for the account "%s". If this was not you, treat it as a possible account compromise.', 'integrity-sentinel' ),
					get_userdata( $user_id )->user_login
				),
			)
		);

		wp_safe_redirect( get_edit_profile_url( $user_id ) . '#is-2fa' );
		exit;
	}

	/**
	 * Regenerates the current user's recovery codes, invalidating the old
	 * ones, provided 2FA is already enabled for them.
	 */
	public function handle_regenerate_recovery() {
		$user_id = get_current_user_id();
		$this->guard_own_profile_action( $user_id );

		if ( ! self::is_enabled( $user_id ) ) {
			wp_safe_redirect( get_edit_profile_url( $user_id ) . '#is-2fa' );
			exit;
		}

		$codes = self::generate_recovery_codes( $user_id );
		set_transient( 'is_2fa_recovery_display_' . $user_id, $codes, MINUTE_IN_SECONDS );
		IS_Audit_Log::record( '2fa_recovery_codes_regenerated', array( 'user_id' => $user_id ) );

		wp_safe_redirect( add_query_arg( 'is_2fa_recovery', '1', get_edit_profile_url( $user_id ) ) . '#is-2fa' );
		exit;
	}

	// ===================================================================
	// Profile screen UI
	// ===================================================================

	/**
	 * Renders the 2FA section on the user's own profile screen: current
	 * status, setup/confirm/disable/regenerate controls, and (once) any
	 * freshly generated recovery codes.
	 *
	 * @param WP_User $user Profile-screen user being rendered.
	 */
	public function render_profile_section( $user ) {
		if ( get_current_user_id() !== (int) $user->ID ) {
			return; // setup is self-service only -- an admin can't set up 2FA on someone else's behalf.
		}
		$enabled       = self::is_enabled( $user->ID );
		$pending       = get_transient( 'is_2fa_setup_' . $user->ID );
		$show_error    = isset( $_GET['is_2fa_error'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag from our own redirect
		$show_recovery = get_transient( 'is_2fa_recovery_display_' . $user->ID );
		if ( $show_recovery ) {
			delete_transient( 'is_2fa_recovery_display_' . $user->ID ); // shown exactly once.
		}
		?>
		<h2 id="is-2fa"><?php esc_html_e( 'Two-Factor Authentication', 'integrity-sentinel' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Status', 'integrity-sentinel' ); ?></th>
				<td>
					<?php if ( $enabled ) : ?>
						<span class="is-badge is-badge-low"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></span>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:8px;">
							<?php wp_nonce_field( 'is_2fa_action' ); ?>
							<input type="hidden" name="action" value="is_2fa_disable">
							<?php submit_button( __( 'Disable two-factor authentication', 'integrity-sentinel' ), 'secondary', 'submit', false ); ?>
						</form>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:8px;">
							<?php wp_nonce_field( 'is_2fa_action' ); ?>
							<input type="hidden" name="action" value="is_2fa_regenerate_recovery">
							<?php submit_button( __( 'Regenerate recovery codes', 'integrity-sentinel' ), 'secondary', 'submit', false ); ?>
						</form>
						<?php if ( $show_recovery ) : ?>
							<div class="notice notice-warning inline">
								<p><strong><?php esc_html_e( 'Save these recovery codes now -- they will not be shown again. Each works once, if you ever lose access to your authenticator app.', 'integrity-sentinel' ); ?></strong></p>
								<pre><?php echo esc_html( implode( "\n", $show_recovery ) ); ?></pre>
							</div>
						<?php endif; ?>
					<?php elseif ( $pending ) : ?>
						<span class="is-badge is-badge-medium"><?php esc_html_e( 'Setup started — confirm below to finish', 'integrity-sentinel' ); ?></span>
						<?php if ( $show_error ) : ?>
							<div class="notice notice-error inline"><p><?php esc_html_e( 'That code was not valid. Scan/enter the key below into your authenticator app and try the current code again.', 'integrity-sentinel' ); ?></p></div>
						<?php endif; ?>
						<p>
							<?php esc_html_e( 'Scan this with your authenticator app (Google Authenticator, Authy, 1Password, ...), or enter the key manually:', 'integrity-sentinel' ); ?><br>
							<code><?php echo esc_html( chunk_split( $pending, 4, ' ' ) ); ?></code>
						</p>
						<p class="description">
							<a href="<?php echo esc_url( IS_TOTP::provisioning_uri( $pending, $user->user_login, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ) ); ?>"><?php esc_html_e( 'Open in authenticator app (on a phone, if this key was shown on the same device)', 'integrity-sentinel' ); ?></a>
						</p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<?php wp_nonce_field( 'is_2fa_action' ); ?>
							<input type="hidden" name="action" value="is_2fa_setup_confirm">
							<label for="is_2fa_code"><?php esc_html_e( 'Enter the current 6-digit code to confirm:', 'integrity-sentinel' ); ?></label>
							<input type="text" inputmode="numeric" autocomplete="one-time-code" id="is_2fa_code" name="is_2fa_code" class="small-text" maxlength="6">
							<?php submit_button( __( 'Confirm and enable', 'integrity-sentinel' ), 'primary', 'submit', false ); ?>
						</form>
					<?php else : ?>
						<span class="is-badge is-badge-high"><?php esc_html_e( 'Not enabled', 'integrity-sentinel' ); ?></span>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<?php wp_nonce_field( 'is_2fa_action' ); ?>
							<input type="hidden" name="action" value="is_2fa_setup_start">
							<?php submit_button( __( 'Set up two-factor authentication', 'integrity-sentinel' ), 'primary', 'submit', false ); ?>
						</form>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Enforcement never blocks login: a user in an enforced role who
	 * hasn't set up 2FA yet is nudged to their profile to do so, rather
	 * than locked out of wp-admin outright or (worse) unable to log in
	 * at all -- which is what makes it safe to turn on without emailing
	 * every affected user first.
	 */
	public function maybe_enforce_setup() {
		IS_Guard::run(
			'2fa_enforcement',
			function () {
				// admin-post.php and admin-ajax.php both fire admin_init before
				// dispatching their own action -- including this plugin's own
				// setup-flow handlers, which must never be redirected away from
				// mid-flow. profile.php is where the redirect below sends
				// people, so it must be reachable too, or this would loop.
				$pagenow = $GLOBALS['pagenow'] ?? '';
				if ( wp_doing_ajax() || in_array( $pagenow, array( 'admin-ajax.php', 'admin-post.php', 'profile.php' ), true ) ) {
					return;
				}

				$user = wp_get_current_user();
				if ( ! $user || ! $user->ID || self::is_enabled( $user->ID ) ) {
					return;
				}
				if ( ! self::role_requires_2fa( (array) $user->roles, self::settings()['enforced_roles'] ) ) {
					return;
				}

				wp_safe_redirect( add_query_arg( 'is_2fa_required', '1', admin_url( 'profile.php' ) ) . '#is-2fa' );
				exit;
			}
		);
	}

	// ===================================================================
	// Login-time verification
	// ===================================================================

	/**
	 * Transient key used to store pending-login state for a verification token.
	 *
	 * @param string $token Random per-attempt token issued in maybe_intercept_login().
	 * @return string
	 */
	private static function pending_key( $token ) {
		return 'is_2fa_pending_' . $token;
	}

	/**
	 * Hooked to 'authenticate': if the authenticated user has 2FA enabled,
	 * stashes the pending login (user, "remember me", attempt count) behind
	 * a random token and redirects to the code-verification screen instead
	 * of letting the login complete.
	 *
	 * @param WP_User|WP_Error|null $user User (or error) from an earlier authenticate callback.
	 * @return WP_User|WP_Error|null Unchanged $user when no interception is needed.
	 */
	public function maybe_intercept_login( $user ) {
		return IS_Guard::run(
			'2fa_login',
			function () use ( $user ) {
				if ( ! ( $user instanceof WP_User ) || ! self::is_enabled( $user->ID ) ) {
					return $user;
				}

				$token = wp_generate_password( 32, false, false );
				set_transient(
					self::pending_key( $token ),
					array(
						'user_id'  => $user->ID,
						'remember' => ! empty( $_POST['rememberme'] ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- mirrors wp-login.php's own unauthenticated handling of this field
						'attempts' => 0,
					),
					self::PENDING_TTL
				);

				$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- passed straight to wp_safe_redirect() below, which validates it

				wp_safe_redirect(
					add_query_arg(
						array(
							'action'      => 'is_2fa',
							'token'       => $token,
							'redirect_to' => rawurlencode( $redirect_to ),
						),
						wp_login_url()
					)
				);
				exit;
			},
			$user
		);
	}

	/**
	 * Hooked to 'login_form_is_2fa': renders the code-entry form on GET,
	 * and on POST validates the submitted token, checks the TOTP code (or
	 * a recovery code as a fallback), enforces the attempt limit, and on
	 * success completes the login and redirects the user onward.
	 */
	public function handle_verify_screen() {
		IS_Guard::run(
			'2fa_login',
			function () {
				$token   = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the token itself is the credential being verified
				$pending = $token ? get_transient( self::pending_key( $token ) ) : false;

				if ( ! is_array( $pending ) ) {
					wp_die(
						sprintf(
							/* translators: %s: login page URL */
							wp_kses( __( 'This verification link has expired. <a href="%s">Log in again</a>.', 'integrity-sentinel' ), array( 'a' => array( 'href' => array() ) ) ),
							esc_url( wp_login_url() )
						)
					);
				}

				if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
					$this->render_verify_form( $token, isset( $_GET['redirect_to'] ) ? wp_unslash( $_GET['redirect_to'] ) : '', false ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- display-only, echoed via esc_url() in render_verify_form()
					exit;
				}

				check_admin_referer( 'is_2fa_verify' );

				if ( (int) $pending['attempts'] >= self::MAX_CODE_ATTEMPTS ) {
					delete_transient( self::pending_key( $token ) );
					wp_die( esc_html__( 'Too many incorrect attempts. Please log in again.', 'integrity-sentinel' ) );
				}

				$user_id  = (int) $pending['user_id'];
				$code     = isset( $_POST['is_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['is_2fa_code'] ) ) : '';
				$verified = IS_TOTP::verify( self::secret( $user_id ), $code, time() );

				if ( ! $verified && '' !== $code ) {
					$result = self::consume_recovery_code( self::recovery_hashes( $user_id ), $code );
					if ( $result['matched'] ) {
						update_user_meta( $user_id, '_is_2fa_recovery_codes', $result['remaining'] );
						IS_Audit_Log::record(
							'2fa_recovery_code_used',
							array(
								'user_id'   => $user_id,
								'remaining' => count( $result['remaining'] ),
							)
						);
						$verified = true;
					}
				}

				if ( ! $verified ) {
					$pending['attempts'] = (int) $pending['attempts'] + 1;
					set_transient( self::pending_key( $token ), $pending, self::PENDING_TTL );
					IS_Audit_Log::record( '2fa_code_rejected', array( 'user_id' => $user_id ) );
					$this->render_verify_form( $token, isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : '', true ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- display-only, echoed via esc_url() in render_verify_form()
					exit;
				}

				delete_transient( self::pending_key( $token ) );

				$user = get_userdata( $user_id );
				wp_set_auth_cookie( $user_id, ! empty( $pending['remember'] ) );
				wp_set_current_user( $user_id );
				do_action( 'wp_login', $user->user_login, $user );

				IS_Audit_Log::record( '2fa_login_verified', array( 'user_id' => $user_id ) );

				$redirect_to = isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : admin_url(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- passed straight to wp_safe_redirect(), which validates it
				wp_safe_redirect( $redirect_to );
				exit;
			}
		);
	}

	/**
	 * Renders the standalone (wp-login.php-hosted) 2FA code-verification
	 * form for the given pending-login token.
	 *
	 * @param string $token       Pending-login token, echoed back as a hidden field via the form action.
	 * @param string $redirect_to Where to send the user after a successful verification.
	 * @param bool   $show_error  Whether to display the "invalid code" error notice.
	 */
	private function render_verify_form( $token, $redirect_to, $show_error ) {
		login_header( __( 'Verification', 'integrity-sentinel' ), '', $show_error ? new WP_Error( 'is_2fa_invalid', __( 'Invalid code. Please try again.', 'integrity-sentinel' ) ) : '' );
		?>
		<form name="is_2fa_form" method="post" action="
		<?php
		echo esc_url(
			add_query_arg(
				array(
					'action' => 'is_2fa',
					'token'  => $token,
				),
				wp_login_url()
			)
		);
		?>
														">
			<?php wp_nonce_field( 'is_2fa_verify' ); ?>
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>">
			<p>
				<label for="is_2fa_code"><?php esc_html_e( 'Authentication code', 'integrity-sentinel' ); ?></label>
				<input type="text" name="is_2fa_code" id="is_2fa_code" class="input" inputmode="numeric" autocomplete="one-time-code" autofocus>
			</p>
			<p class="description"><?php esc_html_e( 'Enter the current code from your authenticator app, or one of your recovery codes.', 'integrity-sentinel' ); ?></p>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'integrity-sentinel' ); ?>">
			</p>
		</form>
		<p id="backtoblog"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '← Back to login', 'integrity-sentinel' ); ?></a></p>
		<?php
		login_footer();
	}
}

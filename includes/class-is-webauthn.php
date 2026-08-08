<?php
/**
 * FIDO2/WebAuthn passwordless 2FA -- a second method alongside IS_2FA's
 * TOTP, built on the vendored web-auth/webauthn-lib.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This entire class is glue around web-auth/webauthn-lib: the actual
 * cryptographic verification (challenge/origin/signature/counter
 * checks) is the library's CeremonyStepManagerFactory, never hand-
 * rolled here. is_available() (PHP 8.2+ and the library actually
 * loaded) gates every entry point -- see the conditional
 * `require_once vendor/autoload.php` in integrity-sentinel.php. A user
 * can have TOTP and/or WebAuthn credentials; IS_2FA's login-challenge
 * screen offers whichever the user has set up, and both complete a
 * verified login through the same IS_2FA::complete_pending_login().
 *
 * Credentials are stored as user meta (_is_webauthn_credentials), one
 * entry per registered authenticator (a user can register more than
 * one, e.g. a phone and a hardware key), each wrapping the library's
 * own CredentialRecord (serialized via its Symfony-serializer-based
 * WebauthnSerializerFactory, never hand-encoded) with a admin-chosen
 * label and a created_at timestamp for display.
 */
class IS_WebAuthn {

	const USER_META_CREDENTIALS = '_is_webauthn_credentials';
	const REG_CHALLENGE_TTL     = 5 * MINUTE_IN_SECONDS;

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
	 * Whether WebAuthn support is actually usable on this install: PHP
	 * 8.2+ and the vendored library successfully loaded. Every entry
	 * point (hooks, AJAX handlers, UI rendering) is gated behind this --
	 * on PHP 7.4-8.1 this is false and WebAuthn simply doesn't appear
	 * anywhere; TOTP remains fully functional either way.
	 */
	public static function is_available() {
		return defined( 'IS_WEBAUTHN_LOADED' ) && IS_WEBAUTHN_LOADED;
	}

	/**
	 * Registers the AJAX/admin-post handlers for credential registration
	 * and removal, and the (unauthenticated) login-time verification
	 * endpoints. Only ever called when is_available() is true (see
	 * integrity-sentinel.php's is_init()).
	 */
	private function hooks() {
		add_action( 'wp_ajax_is_webauthn_register_start', array( $this, 'ajax_register_start' ) );
		add_action( 'wp_ajax_is_webauthn_register_finish', array( $this, 'ajax_register_finish' ) );
		add_action( 'admin_post_is_webauthn_remove_credential', array( $this, 'handle_remove_credential' ) );
		// nopriv: the user is mid-2FA-challenge, not yet fully logged in as far as WordPress is concerned.
		add_action( 'wp_ajax_nopriv_is_webauthn_login_options', array( $this, 'ajax_login_options' ) );
		add_action( 'wp_ajax_nopriv_is_webauthn_login_verify', array( $this, 'ajax_login_verify' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'maybe_enqueue_login_script' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'maybe_enqueue_profile_script' ) );
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: a short, human-readable label for a stored credential entry
	 * for display, falling back to a generic label if none was chosen.
	 *
	 * @param array $entry Stored credential entry (see credentials()).
	 * @param int   $index Position in the credentials list, for the fallback label.
	 */
	public static function credential_label( array $entry, $index ) {
		$label = isset( $entry['label'] ) ? trim( (string) $entry['label'] ) : '';
		if ( '' !== $label ) {
			return $label;
		}
		return sprintf(
			/* translators: %d: 1-based position in the user's list of registered security keys */
			__( 'Security key #%d', 'integrity-sentinel' ),
			(int) $index + 1
		);
	}

	// -----------------------------------------------------------------
	// WP-dependent glue: per-user credential storage
	// -----------------------------------------------------------------

	/**
	 * A user's stored WebAuthn credential entries.
	 *
	 * @param int $user_id User ID.
	 * @return array<array{label:string,created_at:int,record:array}>
	 */
	public static function credentials( $user_id ) {
		$stored = get_user_meta( $user_id, self::USER_META_CREDENTIALS, true );
		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * Whether the user has at least one WebAuthn credential registered.
	 *
	 * @param int $user_id User ID.
	 */
	public static function has_credentials( $user_id ) {
		return ! empty( self::credentials( $user_id ) );
	}

	/**
	 * Persistent, non-identifying WebAuthn user handle for $user_id,
	 * generated once and reused -- per spec recommendation, not the
	 * username/email directly.
	 *
	 * @param int $user_id User ID.
	 * @return string Raw bytes.
	 */
	private function user_handle( $user_id ) {
		$stored = get_user_meta( $user_id, '_is_webauthn_user_handle', true );
		if ( is_string( $stored ) && '' !== $stored ) {
			return $stored;
		}
		$handle = random_bytes( 32 );
		update_user_meta( $user_id, '_is_webauthn_user_handle', $handle );
		return $handle;
	}

	// -----------------------------------------------------------------
	// WP-dependent glue: library plumbing
	// -----------------------------------------------------------------

	/**
	 * The relying-party ID: the site's own host, matching what the
	 * browser will report as the origin's host during a ceremony.
	 */
	private function rp_id() {
		return (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * The relying-party entity (site identity) shown to the authenticator/browser.
	 */
	private function rp_entity() {
		return new \Webauthn\PublicKeyCredentialRpEntity(
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			$this->rp_id()
		);
	}

	/**
	 * The full origin (scheme + host [+ port]) requests must come from --
	 * self-check only, always derived from home_url(), never configurable.
	 */
	private function origin() {
		return home_url();
	}

	/**
	 * A Symfony Serializer configured with every WebAuthn DTO's
	 * normalizer/denormalizer -- never hand-rolled JSON encoding of
	 * these objects.
	 */
	private function serializer() {
		static $serializer = null;
		if ( null === $serializer ) {
			$attestation_manager = new \Webauthn\AttestationStatement\AttestationStatementSupportManager(
				array( new \Webauthn\AttestationStatement\NoneAttestationStatementSupport() )
			);
			$serializer          = ( new \Webauthn\Denormalizer\WebauthnSerializerFactory( $attestation_manager ) )->create();
		}
		return $serializer;
	}

	/**
	 * The library's own ceremony-step factory, configured with this
	 * site's allowed origin -- this is what actually performs every
	 * security-critical check (origin, challenge, signature, counter,
	 * user presence/verification). Never hand-rolled.
	 */
	private function ceremony_step_factory() {
		$factory = new \Webauthn\CeremonyStep\CeremonyStepManagerFactory();
		$factory->setAllowedOrigins( array( $this->origin() ) );
		return $factory;
	}

	/**
	 * Every algorithm this site accepts for a new credential -- ES256
	 * and RS256 cover essentially every authenticator in real-world use
	 * (platform authenticators, security keys).
	 *
	 * @return \Webauthn\PublicKeyCredentialParameters[]
	 */
	private function pub_key_cred_params() {
		return array(
			new \Webauthn\PublicKeyCredentialParameters( 'public-key', \Cose\Algorithm\Signature\ECDSA\ES256::ID ),
			new \Webauthn\PublicKeyCredentialParameters( 'public-key', \Cose\Algorithm\Signature\RSA\RS256::ID ),
		);
	}

	// -----------------------------------------------------------------
	// Registration (profile page, logged-in user, self-service only)
	// -----------------------------------------------------------------

	/**
	 * Renders the "Security keys" section on the user's own profile
	 * screen: registered credentials with a remove button, and a
	 * "Register a new security key" button that drives the JS ceremony.
	 *
	 * @param WP_User $user Profile-screen user being rendered.
	 */
	public function render_profile_section( $user ) {
		if ( get_current_user_id() !== (int) $user->ID ) {
			return; // self-service only, same as IS_2FA's own TOTP section.
		}
		$credentials = self::credentials( $user->ID );
		?>
		<h2 id="is-webauthn"><?php esc_html_e( 'Security Keys (WebAuthn / Passkeys)', 'integrity-sentinel' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Registered keys', 'integrity-sentinel' ); ?></th>
				<td>
					<?php if ( empty( $credentials ) ) : ?>
						<p><?php esc_html_e( 'No security keys registered.', 'integrity-sentinel' ); ?></p>
					<?php else : ?>
						<ul>
							<?php foreach ( $credentials as $index => $entry ) : ?>
								<li>
									<?php echo esc_html( self::credential_label( $entry, $index ) ); ?>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
										<?php wp_nonce_field( 'is_webauthn_action' ); ?>
										<input type="hidden" name="action" value="is_webauthn_remove_credential">
										<input type="hidden" name="credential_index" value="<?php echo esc_attr( $index ); ?>">
										<?php submit_button( __( 'Remove', 'integrity-sentinel' ), 'link-delete', 'submit', false ); ?>
									</form>
								</li>
							<?php endforeach; ?>
						</ul>
					<?php endif; ?>
					<p>
						<button type="button" class="button" id="is-webauthn-register" data-nonce="<?php echo esc_attr( wp_create_nonce( 'is_ajax_nonce' ) ); ?>"><?php esc_html_e( 'Register a new security key', 'integrity-sentinel' ); ?></button>
						<span id="is-webauthn-register-status" role="status"></span>
					</p>
					<p class="description"><?php esc_html_e( 'A hardware security key, or your device\'s built-in authenticator (Touch ID, Windows Hello, etc.). Works alongside an authenticator app -- you can have both set up.', 'integrity-sentinel' ); ?></p>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Rejects the request unless the current user is logged in (`read`
	 * capability -- registering a security key is self-service for any
	 * account, not admin-only) and the request carries a valid plugin
	 * nonce. Deliberately not IS_Ajax::guard(), which requires
	 * manage_options -- registering your own 2FA credential shouldn't
	 * need that.
	 */
	private function guard_own_ajax_action() {
		if ( ! current_user_can( 'read' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'integrity-sentinel' ) ), 403 );
		}
		check_ajax_referer( IS_Ajax::NONCE_ACTION, 'nonce' );
	}

	/**
	 * AJAX: builds registration (creation) options for the current user
	 * and stashes them (serialized) in a transient for ajax_register_finish() to verify against.
	 */
	public function ajax_register_start() {
		$this->guard_own_ajax_action();
		$user_id = get_current_user_id();

		$existing    = array_map(
			function ( $entry ) {
				$record = $entry['record'];
				return new \Webauthn\PublicKeyCredentialDescriptor( 'public-key', base64_decode( $record['publicKeyCredentialId'] ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decoding our own previously base64-encoded credential ID (the library's own storage encoding), not user input
			},
			self::credentials( $user_id )
		);
		$user_entity = new \Webauthn\PublicKeyCredentialUserEntity(
			wp_get_current_user()->user_login,
			$this->user_handle( $user_id ),
			wp_get_current_user()->display_name
		);
		$options     = new \Webauthn\PublicKeyCredentialCreationOptions(
			$this->rp_entity(),
			$user_entity,
			random_bytes( 32 ), // Raw bytes -- the library's own normalizer base64url-encodes this for JSON transport; pre-encoding here would double-encode it.
			$this->pub_key_cred_params(),
			null,
			'none',
			$existing
		);

		$options_json = $this->serializer()->serialize( $options, 'json' );
		set_transient( 'is_webauthn_reg_' . $user_id, $options_json, self::REG_CHALLENGE_TTL );
		wp_send_json_success( array( 'options' => json_decode( $options_json, true ) ) );
	}

	/**
	 * AJAX: verifies the browser's attestation response against the
	 * stashed creation options via the library's own ceremony checks,
	 * and stores the resulting credential.
	 *
	 * @throws \Exception Never escapes this method -- caught internally and converted to a JSON error response.
	 */
	public function ajax_register_finish() {
		$this->guard_own_ajax_action();
		$user_id = get_current_user_id();

		$stored_json = get_transient( 'is_webauthn_reg_' . $user_id );
		if ( ! $stored_json ) {
			wp_send_json_error( array( 'message' => __( 'Registration session expired -- try again.', 'integrity-sentinel' ) ) );
		}
		delete_transient( 'is_webauthn_reg_' . $user_id );

		$label           = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above via IS_Ajax::guard_public()'s nonce check
		$credential_json = isset( $_POST['credential'] ) ? wp_unslash( $_POST['credential'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- verified below via the library's own ceremony checks, not free-form input we trust directly

		try {
			$options    = $this->serializer()->deserialize( $stored_json, \Webauthn\PublicKeyCredentialCreationOptions::class, 'json' );
			$credential = $this->serializer()->deserialize( $credential_json, \Webauthn\PublicKeyCredential::class, 'json' );

			if ( ! $credential->response instanceof \Webauthn\AuthenticatorAttestationResponse ) {
				throw new \Exception( 'Not an attestation response.' );
			}

			$validator = \Webauthn\AuthenticatorAttestationResponseValidator::create( $this->ceremony_step_factory()->creationCeremony() );
			$record    = $validator->check( $credential->response, $options, $this->rp_id() );

			$entries   = self::credentials( $user_id );
			$entries[] = array(
				'label'      => $label,
				'created_at' => time(),
				'record'     => json_decode( $this->serializer()->serialize( $record, 'json' ), true ),
			);
			update_user_meta( $user_id, self::USER_META_CREDENTIALS, $entries );

			IS_Audit_Log::record( 'webauthn_credential_registered', array( 'user_id' => $user_id ) );
			wp_send_json_success();
		} catch ( \Throwable $e ) {
			IS_Audit_Log::record( 'webauthn_registration_failed', array( 'user_id' => $user_id ) );
			wp_send_json_error( array( 'message' => __( 'Could not verify that security key -- try again.', 'integrity-sentinel' ) ) );
		}
	}

	/**
	 * Removes one of the current user's registered credentials, by its
	 * position in their own list (self-service only).
	 */
	public function handle_remove_credential() {
		$user_id = get_current_user_id();
		if ( ! current_user_can( 'read' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_webauthn_action' );

		$index   = isset( $_POST['credential_index'] ) ? (int) $_POST['credential_index'] : -1; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above via check_admin_referer()
		$entries = self::credentials( $user_id );
		if ( isset( $entries[ $index ] ) ) {
			unset( $entries[ $index ] );
			update_user_meta( $user_id, self::USER_META_CREDENTIALS, array_values( $entries ) );
			IS_Audit_Log::record( 'webauthn_credential_removed', array( 'user_id' => $user_id ) );
		}

		wp_safe_redirect( get_edit_profile_url( $user_id ) . '#is-webauthn' );
		exit;
	}

	// -----------------------------------------------------------------
	// Login-time verification (unauthenticated -- mid 2FA-challenge)
	// -----------------------------------------------------------------

	/**
	 * Renders the "Use a security key" button on IS_2FA's login-
	 * challenge screen, when the pending user has WebAuthn credentials.
	 *
	 * @param string $token       Pending-login token from IS_2FA::maybe_intercept_login().
	 * @param string $redirect_to Where to send the user after a successful verification.
	 */
	public function render_login_challenge_button( $token, $redirect_to ) {
		?>
		<p>
			<button type="button" class="button button-large" id="is-webauthn-login" data-token="<?php echo esc_attr( $token ); ?>" data-redirect="<?php echo esc_attr( $redirect_to ); ?>"><?php esc_html_e( 'Use a security key instead', 'integrity-sentinel' ); ?></button>
			<span id="is-webauthn-login-status" role="status"></span>
		</p>
		<?php
	}

	/**
	 * AJAX (nopriv): builds authentication (request) options scoped to
	 * the pending login's user -- only their own registered credentials
	 * are allowed, so the browser can't be tricked into asserting a
	 * different account's credential.
	 */
	public function ajax_login_options() {
		$token   = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the pending-login token itself is the credential being verified, same as IS_2FA::handle_verify_screen()
		$pending = $token ? IS_2FA::get_pending( $token ) : false;
		if ( ! is_array( $pending ) ) {
			wp_send_json_error( array( 'message' => __( 'This verification link has expired.', 'integrity-sentinel' ) ) );
		}

		$user_id = (int) $pending['user_id'];
		$allow   = array_map(
			function ( $entry ) {
				$record = $entry['record'];
				return new \Webauthn\PublicKeyCredentialDescriptor( 'public-key', base64_decode( $record['publicKeyCredentialId'] ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decoding our own previously base64-encoded credential ID (the library's own storage encoding), not user input
			},
			self::credentials( $user_id )
		);
		if ( empty( $allow ) ) {
			wp_send_json_error( array( 'message' => __( 'No security keys are registered for this account.', 'integrity-sentinel' ) ) );
		}

		$options = new \Webauthn\PublicKeyCredentialRequestOptions(
			random_bytes( 32 ), // Raw bytes -- the library's own normalizer base64url-encodes this for JSON transport; pre-encoding here would double-encode it.
			$this->rp_id(),
			$allow
		);

		$options_json = $this->serializer()->serialize( $options, 'json' );
		set_transient( 'is_webauthn_login_' . $token, $options_json, IS_2FA::PENDING_TTL );
		wp_send_json_success( array( 'options' => json_decode( $options_json, true ) ) );
	}

	/**
	 * AJAX (nopriv): verifies the browser's assertion response against
	 * the stashed request options and the pending user's stored
	 * credential, and on success completes the login via
	 * IS_2FA::complete_pending_login() -- the same completion path TOTP uses.
	 *
	 * @throws \Exception Never escapes this method -- caught internally and converted to a JSON error response.
	 */
	public function ajax_login_verify() {
		$token   = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the pending-login token itself is the credential being verified
		$pending = $token ? IS_2FA::get_pending( $token ) : false;
		if ( ! is_array( $pending ) ) {
			wp_send_json_error( array( 'message' => __( 'This verification link has expired.', 'integrity-sentinel' ) ) );
		}

		$stored_json = get_transient( 'is_webauthn_login_' . $token );
		if ( ! $stored_json ) {
			wp_send_json_error( array( 'message' => __( 'Verification session expired -- try again.', 'integrity-sentinel' ) ) );
		}
		delete_transient( 'is_webauthn_login_' . $token );

		$user_id         = (int) $pending['user_id'];
		$credential_json = isset( $_POST['credential'] ) ? wp_unslash( $_POST['credential'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- verified below via the library's own ceremony checks

		try {
			$options    = $this->serializer()->deserialize( $stored_json, \Webauthn\PublicKeyCredentialRequestOptions::class, 'json' );
			$credential = $this->serializer()->deserialize( $credential_json, \Webauthn\PublicKeyCredential::class, 'json' );

			if ( ! $credential->response instanceof \Webauthn\AuthenticatorAssertionResponse ) {
				throw new \Exception( 'Not an assertion response.' );
			}

			$raw_id         = $credential->rawId; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- third-party library's own public property name (Webauthn\Credential::$rawId), not ours to rename
			$entries        = self::credentials( $user_id );
			$matched_record = null;
			foreach ( $entries as $entry ) {
				if ( hash_equals( (string) $entry['record']['publicKeyCredentialId'], (string) base64_encode( $raw_id ) ) ) { // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- comparing against our own stored base64 credential ID, not user input directly
					$matched_record = $entry['record'];
					break;
				}
			}
			if ( null === $matched_record ) {
				throw new \Exception( 'No matching credential for this account.' );
			}
			$credential_record = $this->serializer()->deserialize( wp_json_encode( $matched_record ), \Webauthn\CredentialRecord::class, 'json' );

			$validator = \Webauthn\AuthenticatorAssertionResponseValidator::create( $this->ceremony_step_factory()->requestCeremony() );
			$validator->check( $credential_record, $credential->response, $options, $this->rp_id(), $this->user_handle( $user_id ) );

			IS_2FA::complete_pending_login( $token, $user_id, ! empty( $pending['remember'] ) );
			IS_Audit_Log::record( 'webauthn_login_verified', array( 'user_id' => $user_id ) );

			wp_send_json_success( array( 'redirect_to' => isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : admin_url() ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- the pending-login token (verified above) is the credential being verified; this value is sanitized via esc_url_raw() right here
		} catch ( \Throwable $e ) {
			IS_Audit_Log::record( 'webauthn_login_failed', array( 'user_id' => $user_id ) );
			wp_send_json_error( array( 'message' => __( 'Could not verify that security key.', 'integrity-sentinel' ) ) );
		}
	}

	/**
	 * Enqueues the WebAuthn login-challenge JS only on IS_2FA's own
	 * verification screen (wp-login.php?action=is_2fa), never on the
	 * plain login form.
	 */
	public function maybe_enqueue_login_script() {
		if ( ! isset( $_GET['action'] ) || 'is_2fa' !== $_GET['action'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only page-identity check, not processing input
			return;
		}
		wp_enqueue_script( 'is-webauthn', IS_PLUGIN_URL . 'assets/js/is-webauthn.js', array(), IS_VERSION, true );
		wp_localize_script( 'is-webauthn', 'ISWebAuthn', array( 'ajaxUrl' => admin_url( 'admin-ajax.php' ) ) );
	}

	/**
	 * Enqueues the same WebAuthn JS on the user's own profile screen,
	 * where the "Register a new security key" button lives.
	 *
	 * @param string $hook_suffix Current admin page, as passed by 'admin_enqueue_scripts'.
	 */
	public function maybe_enqueue_profile_script( $hook_suffix ) {
		if ( ! in_array( $hook_suffix, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		wp_enqueue_script( 'is-webauthn', IS_PLUGIN_URL . 'assets/js/is-webauthn.js', array(), IS_VERSION, true );
		wp_localize_script( 'is-webauthn', 'ISWebAuthn', array( 'ajaxUrl' => admin_url( 'admin-ajax.php' ) ) );
	}
}

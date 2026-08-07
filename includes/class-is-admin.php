<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IS_Admin {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	private function hooks() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_head', array( $this, 'hide_native_submenu' ) );
		add_action( 'admin_post_is_apply_uploads_block', array( $this, 'handle_apply_uploads_block' ) );
		add_action( 'admin_post_is_remove_uploads_block', array( $this, 'handle_remove_uploads_block' ) );
		add_action( 'admin_post_is_apply_exec_block', array( $this, 'handle_apply_exec_block' ) );
		add_action( 'admin_post_is_remove_exec_block', array( $this, 'handle_remove_exec_block' ) );
		add_action( 'admin_post_is_apply_hotlink_block', array( $this, 'handle_apply_hotlink_block' ) );
		add_action( 'admin_post_is_remove_hotlink_block', array( $this, 'handle_remove_hotlink_block' ) );
		add_action( 'admin_post_is_apply_asset_cloak', array( $this, 'handle_apply_asset_cloak' ) );
		add_action( 'admin_post_is_remove_asset_cloak', array( $this, 'handle_remove_asset_cloak' ) );
		add_action( 'admin_post_is_reset_module_health', array( $this, 'handle_reset_module_health' ) );
		add_action( 'admin_post_is_quarantine_finding', array( $this, 'handle_quarantine_finding' ) );
		add_action( 'admin_post_is_quarantine_restore', array( $this, 'handle_quarantine_restore' ) );
		add_action( 'admin_post_is_quarantine_delete', array( $this, 'handle_quarantine_delete' ) );
		add_action( 'admin_post_is_check_ip_reputation', array( $this, 'handle_check_ip_reputation' ) );
		add_action( 'admin_post_is_check_hash_reputation', array( $this, 'handle_check_hash_reputation' ) );
		add_action( 'admin_post_is_download_sbom', array( $this, 'handle_download_sbom' ) );
	}

	public function add_menu() {
		add_menu_page(
			__( 'Integrity Sentinel', 'integrity-sentinel' ),
			__( 'Integrity Sentinel', 'integrity-sentinel' ),
			'manage_options',
			'integrity-sentinel',
			array( $this, 'render_dashboard' ),
			'dashicons-shield',
			75
		);
		add_submenu_page( 'integrity-sentinel', __( 'Dashboard', 'integrity-sentinel' ), __( 'Dashboard', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel', array( $this, 'render_dashboard' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Findings', 'integrity-sentinel' ), __( 'Findings', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-findings', array( $this, 'render_findings' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Quarantine', 'integrity-sentinel' ), __( 'Quarantine', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-quarantine', array( $this, 'render_quarantine' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Hardening', 'integrity-sentinel' ), __( 'Hardening', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-hardening', array( $this, 'render_hardening' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Access Control', 'integrity-sentinel' ), __( 'Access Control', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-access', array( $this, 'render_access_control' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Login Security', 'integrity-sentinel' ), __( 'Login Security', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-login', array( $this, 'render_login_security' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Login Design', 'integrity-sentinel' ), __( 'Login Design', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-login-design', array( $this, 'render_login_design' ) );
		add_submenu_page( 'integrity-sentinel', __( 'REST API', 'integrity-sentinel' ), __( 'REST API', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-rest', array( $this, 'render_rest_api' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Audit Log', 'integrity-sentinel' ), __( 'Audit Log', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-audit', array( $this, 'render_audit_log' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Settings', 'integrity-sentinel' ), __( 'Settings', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-settings', array( $this, 'render_settings' ) );

		// Every page above stays fully registered with add_submenu_page()
		// on purpose -- WordPress's own access check (user_can_access_
		// admin_page(), which every admin.php?page=X request runs
		// through) resolves a page's required capability by looking it
		// up in the very $submenu entries add_submenu_page() creates.
		// remove_submenu_page() was tried here first and rejects access
		// to every page it touches ("Sorry, you are not allowed to
		// access this page.") for exactly that reason -- it deletes the
		// $submenu entry those checks depend on, not just the visible
		// row. So instead of removing anything, the native flyout is
		// simply hidden with CSS (hide_native_submenu()) while
		// navigation between pages happens through this plugin's own
		// in-page sidebar (render_shell_open()) -- the result is still
		// one single clean "Integrity Sentinel" entry in the WP admin
		// menu, achieved without breaking WordPress's own bookkeeping.
	}

	/** Hides WP's native submenu flyout for this plugin only; see add_menu() for why. */
	public function hide_native_submenu() {
		$screen = get_current_screen();
		if ( ! $screen || false === strpos( $screen->id, 'integrity-sentinel' ) ) {
			return;
		}
		echo '<style>#adminmenu #toplevel_page_integrity-sentinel > ul.wp-submenu { display: none !important; }</style>';
	}

	/**
	 * The single source of truth for the app-shell sidebar, in display
	 * order. Kept as one array (rather than re-listing labels/slugs
	 * inline at every call site) so the nav, the WP-submenu-hiding loop
	 * above, and any future breadcrumb/search feature all stay in sync
	 * automatically.
	 */
	private function nav_items() {
		return array(
			array(
				'key'   => 'dashboard',
				'label' => __( 'Dashboard', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel',
				'icon'  => 'dashicons-dashboard',
			),
			array(
				'key'   => 'findings',
				'label' => __( 'Findings', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-findings',
				'icon'  => 'dashicons-flag',
			),
			array(
				'key'   => 'quarantine',
				'label' => __( 'Quarantine', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-quarantine',
				'icon'  => 'dashicons-lock',
			),
			array(
				'key'   => 'hardening',
				'label' => __( 'Hardening', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-hardening',
				'icon'  => 'dashicons-shield-alt',
			),
			array(
				'key'   => 'access',
				'label' => __( 'Access Control', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-access',
				'icon'  => 'dashicons-admin-network',
			),
			array(
				'key'   => 'login',
				'label' => __( 'Login Security', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-login',
				'icon'  => 'dashicons-admin-users',
			),
			array(
				'key'   => 'login-design',
				'label' => __( 'Login Design', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-login-design',
				'icon'  => 'dashicons-admin-appearance',
			),
			array(
				'key'   => 'rest',
				'label' => __( 'REST API', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-rest',
				'icon'  => 'dashicons-rest-api',
			),
			array(
				'key'   => 'audit',
				'label' => __( 'Audit Log', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-audit',
				'icon'  => 'dashicons-list-view',
			),
			array(
				'key'   => 'settings',
				'label' => __( 'Settings', 'integrity-sentinel' ),
				'slug'  => 'integrity-sentinel-settings',
				'icon'  => 'dashicons-admin-generic',
			),
		);
	}

	/**
	 * Opens the app shell: a fixed left sidebar (this plugin's own,
	 * replacing reliance on WP's now-hidden submenu flyout) plus the
	 * content pane every render_*() method's markup lives inside.
	 * Always paired with render_shell_close().
	 */
	private function render_shell_open( $active_key ) {
		?>
		<div class="is-shell">
			<nav class="is-shell-nav" aria-label="<?php esc_attr_e( 'Integrity Sentinel sections', 'integrity-sentinel' ); ?>">
				<div class="is-shell-brand">
					<span class="is-shell-logo dashicons dashicons-shield" aria-hidden="true"></span>
					<span class="is-shell-title"><?php esc_html_e( 'Integrity Sentinel', 'integrity-sentinel' ); ?></span>
				</div>
				<ul class="is-shell-nav-list">
					<?php foreach ( $this->nav_items() as $item ) : ?>
						<li>
							<a
								href="<?php echo esc_url( admin_url( 'admin.php?page=' . $item['slug'] ) ); ?>"
								class="is-shell-nav-link<?php echo $active_key === $item['key'] ? ' is-active' : ''; ?>"
								<?php echo $active_key === $item['key'] ? 'aria-current="page"' : ''; ?>
							>
								<span class="dashicons <?php echo esc_attr( $item['icon'] ); ?>" aria-hidden="true"></span>
								<span><?php echo esc_html( $item['label'] ); ?></span>
							</a>
						</li>
					<?php endforeach; ?>
				</ul>
				<div class="is-shell-version">Integrity Sentinel <?php echo esc_html( IS_VERSION ); ?></div>
			</nav>
			<main class="is-shell-content">
		<?php
	}

	private function render_shell_close() {
		?>
			</main>
		</div>
		<?php
	}

	public function enqueue( $hook ) {
		if ( strpos( $hook, 'integrity-sentinel' ) === false ) {
			return;
		}
		wp_enqueue_style( 'is-admin', IS_PLUGIN_URL . 'assets/css/is-admin.css', array(), IS_VERSION );
		wp_enqueue_script( 'is-admin', IS_PLUGIN_URL . 'assets/js/is-admin.js', array(), IS_VERSION, true );

		if ( isset( $_GET['page'] ) && 'integrity-sentinel-login-design' === $_GET['page'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only page-identity check, not processing input
			wp_enqueue_media();
		}
		wp_localize_script(
			'is-admin',
			'ISAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( IS_Ajax::NONCE_ACTION ),
				'i18n'    => array(
					'scanning'       => __( 'Scanning…', 'integrity-sentinel' ),
					'scanComplete'   => __( 'Scan complete.', 'integrity-sentinel' ),
					'scanError'      => __( 'Scan error:', 'integrity-sentinel' ),
					'scanInProgress' => __( 'A scan is already in progress — showing its status.', 'integrity-sentinel' ),
					'notCheckable'   => __( '%d plugin(s) could not be checksum-verified (not hosted on WordPress.org).', 'integrity-sentinel' ),
				),
			)
		);
	}

	public function register_settings() {
		register_setting(
			'is_settings_group',
			'is_scan_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
			)
		);
		register_setting(
			'is_hardening_settings_group',
			'is_hardening_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_hardening_settings' ),
			)
		);
		register_setting(
			'is_ip_list_settings_group',
			'is_ip_list_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_ip_list_settings' ),
			)
		);
		register_setting(
			'is_login_rename_settings_group',
			'is_login_rename_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_login_rename_settings' ),
			)
		);
		register_setting(
			'is_login_throttle_settings_group',
			'is_login_throttle_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_login_throttle_settings' ),
			)
		);
		register_setting(
			'is_login_design_settings_group',
			'is_login_design_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_login_design_settings' ),
			)
		);
		register_setting(
			'is_hotlink_settings_group',
			'is_hotlink_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_hotlink_settings' ),
			)
		);
		register_setting(
			'is_bot_block_settings_group',
			'is_bot_block_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_bot_block_settings' ),
			)
		);
		register_setting(
			'is_rest_api_settings_group',
			'is_rest_api_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_rest_api_settings' ),
			)
		);
		register_setting(
			'is_rest_posts_settings_group',
			'is_rest_posts_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_rest_posts_settings' ),
			)
		);
		register_setting(
			'is_2fa_settings_group',
			'is_2fa_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_2fa_settings' ),
			)
		);
		register_setting(
			'is_session_settings_group',
			'is_session_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_session_settings' ),
			)
		);
		register_setting(
			'is_asset_cloak_settings_group',
			'is_asset_cloak_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_asset_cloak_settings' ),
			)
		);
		register_setting(
			'is_password_policy_settings_group',
			'is_password_policy_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_password_policy_settings' ),
			)
		);
		register_setting(
			'is_vulnerability_scanner_settings_group',
			'is_vulnerability_scanner_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_vulnerability_scanner_settings' ),
			)
		);
		register_setting(
			'is_signatures_settings_group',
			'is_signatures_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_signatures_settings' ),
			)
		);
		register_setting(
			'is_threat_intel_settings_group',
			'is_threat_intel_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_threat_intel_settings' ),
			)
		);
	}

	public function sanitize_vulnerability_scanner_settings( $input ) {
		$old     = IS_Vulnerability_Scanner::settings();
		$api_key = isset( $input['api_key'] ) ? sanitize_text_field( trim( (string) $input['api_key'] ) ) : '';
		$enabled = empty( $input['enabled'] ) ? 0 : 1;

		if ( $enabled && '' === $api_key ) {
			add_settings_error(
				'is_vulnerability_scanner_settings',
				'is_vuln_scanner_key_required',
				__( 'A WPScan API key is required to enable vulnerability scanning — it was left off. Get a free key at wpscan.com/register.', 'integrity-sentinel' )
			);
			$enabled = 0;
		}

		$out = array(
			'enabled' => $enabled,
			'api_key' => $api_key,
		);

		if ( $out !== $old ) {
			// The key itself isn't logged -- only whether the feature's on.
			IS_Audit_Log::record( 'vulnerability_scanner_settings_changed', array( 'enabled' => $out['enabled'] ) );
		}

		return $out;
	}

	public function sanitize_signatures_settings( $input ) {
		$old = IS_Signatures::settings();
		$out = array(
			'enabled' => empty( $input['enabled'] ) ? 0 : 1,
			'hashes'  => sanitize_textarea_field( $input['hashes'] ?? '' ),
		);

		if ( $out !== $old ) {
			IS_Audit_Log::record(
				'signatures_settings_changed',
				array(
					'enabled' => $out['enabled'],
					'count'   => count( IS_Signatures::parse_hash_list( $out['hashes'] ) ),
				)
			);
		}

		return $out;
	}

	public function sanitize_threat_intel_settings( $input ) {
		$old = IS_Threat_Intel::settings();
		$out = array(
			'enabled'        => empty( $input['enabled'] ) ? 0 : 1,
			'abuseipdb_key'  => isset( $input['abuseipdb_key'] ) ? sanitize_text_field( trim( (string) $input['abuseipdb_key'] ) ) : '',
			'virustotal_key' => isset( $input['virustotal_key'] ) ? sanitize_text_field( trim( (string) $input['virustotal_key'] ) ) : '',
		);

		if ( $out['enabled'] !== $old['enabled'] ) {
			// The keys themselves aren't logged -- only whether the feature's on.
			IS_Audit_Log::record( 'threat_intel_settings_changed', array( 'enabled' => $out['enabled'] ) );
		}

		return $out;
	}

	public function sanitize_password_policy_settings( $input ) {
		$old = IS_Password_Policy::settings();
		$out = array(
			'enabled'            => empty( $input['enabled'] ) ? 0 : 1,
			'min_length'         => max( 4, min( 64, (int) ( $input['min_length'] ?? 12 ) ) ),
			'require_mixed_case' => empty( $input['require_mixed_case'] ) ? 0 : 1,
			'require_number'     => empty( $input['require_number'] ) ? 0 : 1,
			'require_symbol'     => empty( $input['require_symbol'] ) ? 0 : 1,
		);

		if ( $out !== $old ) {
			IS_Audit_Log::record( 'password_policy_changed', array( 'settings' => $out ) );
		}

		return $out;
	}

	public function sanitize_session_settings( $input ) {
		$old = IS_Sessions::settings();
		$out = array( 'alert_on_new_ip' => empty( $input['alert_on_new_ip'] ) ? 0 : 1 );

		if ( $out['alert_on_new_ip'] !== $old['alert_on_new_ip'] ) {
			IS_Audit_Log::record( 'session_settings_changed', array( 'alert_on_new_ip' => $out['alert_on_new_ip'] ) );
		}

		return $out;
	}

	public function sanitize_asset_cloak_settings( $input ) {
		$old     = IS_Asset_Cloak::settings();
		$raw     = isset( $input['alias'] ) ? $input['alias'] : '';
		$alias   = IS_Asset_Cloak::sanitize_alias( $raw );
		$enabled = empty( $input['enabled'] ) ? 0 : 1;

		if ( '' !== trim( (string) $raw ) && '' === $alias ) {
			add_settings_error(
				'is_asset_cloak_settings',
				'is_asset_cloak_alias_invalid',
				__( 'That alias could not be used (empty after removing invalid characters, or it collides with a WordPress core path). The previous alias was kept.', 'integrity-sentinel' )
			);
			$alias = $old['alias'];
		}

		if ( $enabled && '' === $alias ) {
			add_settings_error(
				'is_asset_cloak_settings',
				'is_asset_cloak_alias_required',
				__( 'Set an alias before enabling the asset cloak — it was left off.', 'integrity-sentinel' )
			);
			$enabled = 0;
		}

		$out = array(
			'enabled' => $enabled,
			'alias'   => $alias,
		);

		if ( $out !== $old ) {
			IS_Audit_Log::record(
				'asset_cloak_settings_changed',
				array(
					'from' => $old,
					'to'   => $out,
				)
			);
		}

		return $out;
	}

	public function sanitize_2fa_settings( $input ) {
		$old         = IS_2FA::settings();
		$valid_roles = array_keys( wp_roles()->get_names() );
		$requested   = isset( $input['enforced_roles'] ) && is_array( $input['enforced_roles'] ) ? $input['enforced_roles'] : array();
		$out         = array( 'enforced_roles' => array_values( array_intersect( $valid_roles, $requested ) ) );

		if ( $out['enforced_roles'] !== $old['enforced_roles'] ) {
			IS_Audit_Log::record( '2fa_enforcement_changed', array( 'roles' => $out['enforced_roles'] ) );
		}

		return $out;
	}

	public function sanitize_rest_api_settings( $input ) {
		$old = IS_Rest_API::settings();
		$out = array(
			'block_user_enumeration'   => empty( $input['block_user_enumeration'] ) ? 0 : 1,
			'restrict_unauthenticated' => empty( $input['restrict_unauthenticated'] ) ? 0 : 1,
			'allowed_routes'           => sanitize_textarea_field( $input['allowed_routes'] ?? '' ),
			'rate_limit'               => max( 0, min( 10000, (int) ( $input['rate_limit'] ?? 120 ) ) ),
			'enumeration_detection'    => empty( $input['enumeration_detection'] ) ? 0 : 1,
			'enumeration_threshold'    => max( 5, min( 1000, (int) ( $input['enumeration_threshold'] ?? 20 ) ) ),
			'block_on_enumeration'     => empty( $input['block_on_enumeration'] ) ? 0 : 1,
		);

		$changed = array();
		foreach ( $out as $key => $value ) {
			if ( (string) ( $old[ $key ] ?? '' ) !== (string) $value ) {
				$changed[] = $key;
			}
		}
		if ( $changed ) {
			IS_Audit_Log::record( 'rest_api_settings_changed', array( 'keys' => $changed ) );
		}

		return $out;
	}

	public function sanitize_rest_posts_settings( $input ) {
		$old = IS_Rest_Posts::settings();
		$out = array(
			'enabled'    => empty( $input['enabled'] ) ? 0 : 1,
			'rate_limit' => max( 1, min( 1000, (int) ( $input['rate_limit'] ?? 30 ) ) ),
		);

		$changed = array();
		foreach ( $out as $key => $value ) {
			if ( (string) ( $old[ $key ] ?? '' ) !== (string) $value ) {
				$changed[] = $key;
			}
		}
		if ( $changed ) {
			IS_Audit_Log::record( 'rest_posts_settings_changed', array( 'keys' => $changed ) );
		}

		return $out;
	}

	public function sanitize_hotlink_settings( $input ) {
		$old = IS_Hotlink::settings();
		$out = array( 'allowed_domains' => sanitize_textarea_field( $input['allowed_domains'] ?? '' ) );

		if ( (string) $old['allowed_domains'] !== (string) $out['allowed_domains'] ) {
			IS_Audit_Log::record( 'hotlink_settings_changed', array() );
			// Keep an already-active block's rule content in sync with the
			// newly-saved domain list, rather than leaving it stale.
			add_action( 'shutdown', array( 'IS_Hotlink', 'reapply_if_active' ) );
		}

		return $out;
	}

	public function sanitize_bot_block_settings( $input ) {
		$old = IS_Bot_Block::settings();
		$out = array(
			'enabled'      => empty( $input['enabled'] ) ? 0 : 1,
			'blocked_bots' => sanitize_textarea_field( $input['blocked_bots'] ?? '' ),
		);

		$changed = array();
		foreach ( $out as $key => $value ) {
			if ( (string) ( $old[ $key ] ?? '' ) !== (string) $value ) {
				$changed[] = $key;
			}
		}
		if ( $changed ) {
			IS_Audit_Log::record( 'bot_block_settings_changed', array( 'keys' => $changed ) );
		}

		return $out;
	}

	public function sanitize_login_rename_settings( $input ) {
		$old  = IS_Login::rename_settings();
		$raw  = isset( $input['login_slug'] ) ? $input['login_slug'] : '';
		$slug = IS_Login::sanitize_login_slug( $raw );

		if ( '' !== trim( (string) $raw ) && '' === $slug ) {
			add_settings_error(
				'is_login_rename_settings',
				'is_login_slug_invalid',
				__( 'That login slug could not be used (empty after removing invalid characters, or it collides with a WordPress core path). The login rename was left disabled.', 'integrity-sentinel' )
			);
		} elseif ( '' !== $slug && function_exists( 'get_page_by_path' ) && get_page_by_path( $slug ) ) {
			add_settings_error(
				'is_login_rename_settings',
				'is_login_slug_collision',
				sprintf(
					/* translators: %s: the rejected slug */
					__( 'A page or post already uses the slug "%s". Choose a different login slug — the previous setting was kept.', 'integrity-sentinel' ),
					$slug
				)
			);
			$slug = $old['login_slug'];
		}

		$raw_host = isset( $input['login_host'] ) ? $input['login_host'] : '';
		$host     = IS_Login::sanitize_login_host( $raw_host );
		if ( '' !== trim( (string) $raw_host ) && '' === $host ) {
			add_settings_error(
				'is_login_rename_settings',
				'is_login_host_invalid',
				__( 'That admin subdomain did not look like a valid hostname (e.g. admin.example.com) and was left blank.', 'integrity-sentinel' )
			);
		}

		$out = array(
			'login_slug' => $slug,
			'login_host' => $host,
		);

		if ( (string) $old['login_slug'] !== (string) $out['login_slug'] ) {
			IS_Audit_Log::record(
				'login_slug_changed',
				array(
					'from' => $old['login_slug'],
					'to'   => $out['login_slug'],
				)
			);
		}
		if ( (string) $old['login_host'] !== (string) $out['login_host'] ) {
			IS_Audit_Log::record(
				'login_host_changed',
				array(
					'from' => $old['login_host'],
					'to'   => $out['login_host'],
				)
			);
		}

		return $out;
	}

	/**
	 * The actual input -> clean-array transform, with no side effects
	 * (no settings_errors, no audit log) -- shared by the real save path
	 * (sanitize_login_design_settings() below, which adds those side
	 * effects around it) and IS_Ajax::preview_login_design(), which needs
	 * an identically-validated draft for the unsaved-changes preview
	 * without either of those side effects firing for something that was
	 * never actually saved.
	 */
	public function sanitize_login_design_input( $input, $old ) {
		$defaults = IS_Login_Design::default_settings();

		$template = isset( $input['template'] ) && array_key_exists( $input['template'], IS_Login_Design::templates() )
			? $input['template']
			: $defaults['template'];

		$raw_color = isset( $input['primary_color'] ) ? $input['primary_color'] : '';
		$color     = sanitize_hex_color( $raw_color );
		if ( '' !== trim( (string) $raw_color ) && null === $color ) {
			$color = $old['primary_color'];
		} elseif ( null === $color ) {
			$color = $defaults['primary_color'];
		}

		$raw_logo = isset( $input['logo_url'] ) ? trim( (string) $input['logo_url'] ) : '';
		$logo     = '' !== $raw_logo ? esc_url_raw( $raw_logo ) : '';
		if ( '' !== $logo && ! IS_Login_Design::is_http_url( $logo ) ) {
			$logo = '';
		}

		$raw_hero_image = isset( $input['hero_image_url'] ) ? trim( (string) $input['hero_image_url'] ) : '';
		$hero_image     = '' !== $raw_hero_image ? esc_url_raw( $raw_hero_image ) : '';
		if ( '' !== $hero_image && ! IS_Login_Design::is_http_url( $hero_image ) ) {
			$hero_image = '';
		}

		$hero_position = isset( $input['hero_position'] ) && in_array( $input['hero_position'], IS_Login_Design::hero_positions(), true )
			? $input['hero_position']
			: 'left';

		$carousel_indicator = isset( $input['carousel_indicator'] ) && array_key_exists( $input['carousel_indicator'], IS_Login_Design::carousel_indicators() )
			? $input['carousel_indicator']
			: $defaults['carousel_indicator'];

		// One image URL per line (a textarea, not a repeater UI -- simple
		// and robust). Only used by the Carousel template; harmless if
		// present for any other template, since only Carousel ever reads
		// it (IS_Login_Design::carousel_images()).
		$raw_gallery_lines = isset( $input['hero_gallery'] ) ? preg_split( '/[\r\n]+/', (string) $input['hero_gallery'] ) : array();
		$hero_gallery      = array();
		foreach ( $raw_gallery_lines as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$url = esc_url_raw( $line );
			if ( IS_Login_Design::is_http_url( $url ) ) {
				$hero_gallery[] = $url;
			}
		}
		$hero_gallery = array_slice( array_values( array_unique( $hero_gallery ) ), 0, 8 );

		return array(
			'template'           => $template,
			'logo_url'           => $logo,
			'primary_color'      => $color,
			'border_radius'      => IS_Login_Design::clamp_radius( isset( $input['border_radius'] ) ? $input['border_radius'] : $defaults['border_radius'] ),
			'hero_position'      => $hero_position,
			'hero_heading'       => isset( $input['hero_heading'] ) ? sanitize_text_field( $input['hero_heading'] ) : '',
			'hero_subheading'    => isset( $input['hero_subheading'] ) ? sanitize_text_field( $input['hero_subheading'] ) : '',
			'hero_image_url'     => $hero_image,
			'hero_gallery'       => $hero_gallery,
			'carousel_indicator' => $carousel_indicator,
			'hide_branding'      => empty( $input['hide_branding'] ) ? 0 : 1,
			'custom_css'         => IS_Login_Design::sanitize_css_for_style_tag( isset( $input['custom_css'] ) ? (string) $input['custom_css'] : '' ),
			'custom_html'        => isset( $input['custom_html'] ) ? wp_kses_post( $input['custom_html'] ) : '',
		);
	}

	public function sanitize_login_design_settings( $input ) {
		$old = IS_Login_Design::settings();
		$out = $this->sanitize_login_design_input( $input, $old );

		$raw_color = isset( $input['primary_color'] ) ? $input['primary_color'] : '';
		if ( '' !== trim( (string) $raw_color ) && null === sanitize_hex_color( $raw_color ) ) {
			add_settings_error(
				'is_login_design_settings',
				'is_login_design_color_invalid',
				__( 'That accent color was not a valid hex color (e.g. #6366f1) and was left unchanged.', 'integrity-sentinel' )
			);
		}

		if ( $out !== $old ) {
			IS_Audit_Log::record( 'login_design_changed', array() );
		}

		return $out;
	}

	public function sanitize_login_throttle_settings( $input ) {
		$old = IS_Login::throttle_settings();
		$out = array(
			'enabled'                       => empty( $input['enabled'] ) ? 0 : 1,
			'max_attempts'                  => max( 3, min( 20, (int) ( $input['max_attempts'] ?? 5 ) ) ),
			'window_minutes'                => max( 1, min( 1440, (int) ( $input['window_minutes'] ?? 15 ) ) ),
			'lockout_minutes'               => max( 1, min( 1440, (int) ( $input['lockout_minutes'] ?? 15 ) ) ),
			'credential_stuffing_threshold' => max( 2, min( 100, (int) ( $input['credential_stuffing_threshold'] ?? 8 ) ) ),
		);

		$changed = array();
		foreach ( $out as $key => $value ) {
			if ( (string) ( $old[ $key ] ?? '' ) !== (string) $value ) {
				$changed[] = $key;
			}
		}
		if ( $changed ) {
			IS_Audit_Log::record( 'login_throttle_settings_changed', array( 'keys' => $changed ) );
		}

		return $out;
	}

	public function sanitize_ip_list_settings( $input ) {
		$old = IS_IP_List::settings();

		$out = array(
			'whitelist'            => sanitize_textarea_field( $input['whitelist'] ?? '' ),
			'blacklist'            => sanitize_textarea_field( $input['blacklist'] ?? '' ),
			'trusted_proxy_ranges' => sanitize_textarea_field( $input['trusted_proxy_ranges'] ?? '' ),
			'trusted_ip_header'    => in_array( $input['trusted_ip_header'] ?? '', array( '', 'X-Forwarded-For', 'CF-Connecting-IP', 'X-Real-IP' ), true )
				? $input['trusted_ip_header']
				: '',
		);

		// Never let a whitelist edit lock the acting admin out: their own
		// current IP is guaranteed present in the saved whitelist.
		$acting_ip = IS_IP_List::client_ip();
		if ( '' !== $acting_ip && ! IS_IP_List::ip_matches_list( $acting_ip, IS_IP_List::parse_list_text( $out['whitelist'] ) ) ) {
			$out['whitelist'] = trim( $out['whitelist'] . "\n" . $acting_ip . ' # auto-added: the admin who saved this page' );
		}

		$changed = array();
		foreach ( $out as $key => $value ) {
			if ( (string) ( $old[ $key ] ?? '' ) !== (string) $value ) {
				$changed[] = $key;
			}
		}
		if ( $changed ) {
			IS_Audit_Log::record( 'ip_list_settings_changed', array( 'keys' => $changed ) );
		}

		return $out;
	}

	public function sanitize_hardening_settings( $input ) {
		$old = IS_Headers::settings();
		$out = array();
		foreach ( array_keys( IS_Headers::default_settings() ) as $key ) {
			if ( 'content_security_policy' === $key ) {
				// A free-text header value, not a toggle -- stripped of
				// tags and any literal line breaks (a raw newline here
				// would be HTTP header-injection input; header() itself
				// already rejects that, but there's no reason to store an
				// invalid value in the first place).
				$raw         = isset( $input[ $key ] ) ? (string) $input[ $key ] : '';
				$out[ $key ] = trim( (string) preg_replace( '/[\r\n]+/', ' ', sanitize_textarea_field( $raw ) ) );
				continue;
			}
			$out[ $key ] = empty( $input[ $key ] ) ? 0 : 1;
		}

		$changed = array();
		foreach ( $out as $key => $value ) {
			if ( (string) ( $old[ $key ] ?? '' ) !== (string) $value ) {
				$changed[] = $key;
			}
		}
		if ( $changed ) {
			IS_Audit_Log::record( 'hardening_settings_changed', array( 'keys' => $changed ) );
		}

		return $out;
	}

	public function sanitize_settings( $input ) {
		$old = get_option( 'is_scan_settings', array() );

		$out                         = array();
		$out['batch_size']           = max( 5, min( 200, (int) ( $input['batch_size'] ?? 40 ) ) );
		$out['alert_email']          = is_email( $input['alert_email'] ?? '' ) ? sanitize_email( $input['alert_email'] ) : get_option( 'admin_email' );
		$out['alert_on_severity']    = in_array( $input['alert_on_severity'] ?? '', array( 'critical', 'high', 'medium', 'low' ), true ) ? $input['alert_on_severity'] : 'high';
		$out['scan_uploads_for_php'] = empty( $input['scan_uploads_for_php'] ) ? 0 : 1;
		$out['max_file_size_kb']     = max( 64, (int) ( $input['max_file_size_kb'] ?? 2048 ) );
		$out['excluded_paths']       = sanitize_textarea_field( $input['excluded_paths'] ?? '' );
		$out['webhook_url']          = esc_url_raw( $input['webhook_url'] ?? '', array( 'http', 'https' ) );
		$out['deadman_days']         = max( 1, min( 30, (int) ( $input['deadman_days'] ?? 2 ) ) );
		$out['scan_frequency']       = IS_Cron::normalize_frequency( $input['scan_frequency'] ?? 'daily' );

		// Alert-redirection guard: whoever WAS receiving alerts gets told
		// they no longer will. Without this, an attacker with an admin
		// session silently points alerts at themselves and every other
		// defense goes quiet.
		$old_email = $old['alert_email'] ?? '';
		if ( $old_email && is_email( $old_email ) && $old_email !== $out['alert_email'] ) {
			$user = wp_get_current_user();
			wp_mail(
				$old_email,
				'[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] ' . __( 'Integrity Sentinel alert address was changed', 'integrity-sentinel' ),
				sprintf(
					/* translators: 1: new email address, 2: user login, 3: IP address */
					__( "Integrity Sentinel security alerts will no longer be sent to this address.\n\nNew alert address: %1\$s\nChanged by: %2\$s (IP %3\$s)\n\nIf you did not expect this change, investigate immediately.\n", 'integrity-sentinel' ),
					$out['alert_email'],
					$user && $user->ID ? $user->user_login : __( '(unknown)', 'integrity-sentinel' ),
					IS_Audit_Log::request_ip()
				)
			);
			IS_Audit_Log::record(
				'alert_email_changed',
				array(
					'from' => $old_email,
					'to'   => $out['alert_email'],
				)
			);
		}

		$changed = array();
		foreach ( $out as $key => $value ) {
			if ( ! array_key_exists( $key, $old ) || (string) $old[ $key ] !== (string) $value ) {
				$changed[] = $key;
			}
		}
		if ( $changed && $old ) {
			IS_Audit_Log::record( 'settings_changed', array( 'keys' => $changed ) );
		}
		if ( in_array( 'scan_frequency', $changed, true ) ) {
			IS_Cron::reschedule_scan( $out['scan_frequency'] );
		}

		return $out;
	}

	// -----------------------------------------------------------------
	// Hardening actions (plain admin-post forms, no JS dependency)
	// -----------------------------------------------------------------

	public function handle_apply_uploads_block() {
		$this->guard_hardening_action();
		$result = IS_Hardening::apply_uploads_block();
		$this->redirect_hardening( is_wp_error( $result ) ? $result->get_error_message() : '' );
	}

	public function handle_apply_asset_cloak() {
		$this->guard_hardening_action();
		$alias = IS_Asset_Cloak::settings()['alias'];
		if ( '' === $alias ) {
			$this->redirect_hardening( __( 'Save an alias below before applying the .htaccess rule.', 'integrity-sentinel' ) );
		}
		$result = IS_Asset_Cloak::apply_block( $alias );
		$this->redirect_hardening( is_wp_error( $result ) ? $result->get_error_message() : '' );
	}

	public function handle_remove_asset_cloak() {
		$this->guard_hardening_action();
		$result = IS_Asset_Cloak::remove_block();
		$this->redirect_hardening( is_wp_error( $result ) ? $result->get_error_message() : '' );
	}

	public function handle_remove_uploads_block() {
		$this->guard_hardening_action();
		$result = IS_Hardening::remove_uploads_block();
		$this->redirect_hardening( is_wp_error( $result ) ? $result->get_error_message() : '' );
	}

	public function handle_apply_exec_block() {
		$this->guard_hardening_action();
		$target = $this->resolve_exec_block_target();
		$result = $target ? IS_Hardening::apply_block_for( $target['abs_path'] ) : new WP_Error( 'is_unknown_target', __( 'Unknown directory.', 'integrity-sentinel' ) );
		$this->redirect_hardening( is_wp_error( $result ) ? $result->get_error_message() : '' );
	}

	public function handle_remove_exec_block() {
		$this->guard_hardening_action();
		$target = $this->resolve_exec_block_target();
		$result = $target ? IS_Hardening::remove_block_for( $target['abs_path'] ) : new WP_Error( 'is_unknown_target', __( 'Unknown directory.', 'integrity-sentinel' ) );
		$this->redirect_hardening( is_wp_error( $result ) ? $result->get_error_message() : '' );
	}

	/**
	 * Resolves the POSTed target *key* to a server-known absolute path --
	 * the path itself is never accepted from the request, only one of a
	 * fixed set of keys, so this can't be turned into an arbitrary
	 * .htaccess-write primitive.
	 */
	private function resolve_exec_block_target() {
		$key     = isset( $_POST['target'] ) ? sanitize_key( wp_unslash( $_POST['target'] ) ) : '';
		$targets = IS_Hardening::exec_block_targets();
		return isset( $targets[ $key ] ) ? $targets[ $key ] : null;
	}

	public function handle_apply_hotlink_block() {
		$this->guard_hardening_action();
		$result = IS_Hotlink::apply();
		$this->redirect_hardening( is_wp_error( $result ) ? $result->get_error_message() : '' );
	}

	public function handle_remove_hotlink_block() {
		$this->guard_hardening_action();
		$result = IS_Hotlink::remove();
		$this->redirect_hardening( is_wp_error( $result ) ? $result->get_error_message() : '' );
	}

	public function handle_reset_module_health() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_reset_module_health' );

		$module = isset( $_POST['module'] ) ? sanitize_key( wp_unslash( $_POST['module'] ) ) : '';
		if ( $module ) {
			IS_Guard::reset( $module );
			IS_Audit_Log::record( 'module_health_reset', array( 'module' => $module ) );
		}

		wp_safe_redirect( admin_url( 'admin.php?page=integrity-sentinel' ) );
		exit;
	}

	private function guard_quarantine_action() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_quarantine_action' );
	}

	public function handle_quarantine_finding() {
		$this->guard_quarantine_action();

		$finding_id = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
		$finding    = $finding_id ? IS_DB::instance()->get_finding( $finding_id ) : null;
		$url        = admin_url( 'admin.php?page=integrity-sentinel-findings' );

		if ( ! $finding ) {
			wp_safe_redirect( add_query_arg( 'is_error', rawurlencode( __( 'Finding not found.', 'integrity-sentinel' ) ), $url ) );
			exit;
		}

		$result = IS_Quarantine::quarantine_finding( $finding, get_current_user_id() );
		if ( is_wp_error( $result ) ) {
			$url = add_query_arg( 'is_error', rawurlencode( $result->get_error_message() ), $url );
		} else {
			$url = add_query_arg( 'is_quarantined', '1', $url );
		}
		wp_safe_redirect( $url );
		exit;
	}

	public function handle_quarantine_restore() {
		$this->guard_quarantine_action();
		$id     = isset( $_POST['quarantine_id'] ) ? (int) $_POST['quarantine_id'] : 0;
		$result = $id ? IS_Quarantine::restore( $id, get_current_user_id() ) : new WP_Error( 'is_quarantine_invalid', __( 'Invalid request.', 'integrity-sentinel' ) );
		$this->redirect_quarantine( $result );
	}

	public function handle_quarantine_delete() {
		$this->guard_quarantine_action();

		if ( empty( $_POST['is_quarantine_confirm'] ) ) {
			$this->redirect_quarantine( new WP_Error( 'is_quarantine_not_confirmed', __( 'You must check the confirmation box to permanently delete a file.', 'integrity-sentinel' ) ) );
		}

		$id     = isset( $_POST['quarantine_id'] ) ? (int) $_POST['quarantine_id'] : 0;
		$result = $id ? IS_Quarantine::delete_permanently( $id, get_current_user_id() ) : new WP_Error( 'is_quarantine_invalid', __( 'Invalid request.', 'integrity-sentinel' ) );
		$this->redirect_quarantine( $result );
	}

	private function redirect_quarantine( $result ) {
		$url = admin_url( 'admin.php?page=integrity-sentinel-quarantine' );
		if ( is_wp_error( $result ) ) {
			$url = add_query_arg( 'is_error', rawurlencode( $result->get_error_message() ), $url );
		}
		wp_safe_redirect( $url );
		exit;
	}

	private function guard_hardening_action() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_hardening_action' );
	}

	private function redirect_hardening( $error_message = '' ) {
		$url = add_query_arg( array( 'page' => 'integrity-sentinel-hardening' ), admin_url( 'admin.php' ) );
		if ( $error_message ) {
			$url = add_query_arg( 'is_error', rawurlencode( $error_message ), $url );
		}
		wp_safe_redirect( $url );
		exit;
	}

	// -----------------------------------------------------------------
	// Threat intelligence: on-demand reputation checks + SBOM download
	// -----------------------------------------------------------------

	private function guard_threat_intel_action() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'integrity-sentinel' ) );
		}
		check_admin_referer( 'is_threat_intel_action' );
	}

	/**
	 * Runs on the admin's explicit click, from the Audit Log page --
	 * unlike a live login/REST request, a page load taking an extra
	 * second for one external HTTP round-trip is an acceptable, expected
	 * cost here. See IS_Threat_Intel's class doc for why this is never
	 * wired into a live request path instead.
	 */
	public function handle_check_ip_reputation() {
		$this->guard_threat_intel_action();
		$ip  = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$url = admin_url( 'admin.php?page=integrity-sentinel-audit' );

		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_safe_redirect( add_query_arg( 'is_error', rawurlencode( __( 'Invalid IP address.', 'integrity-sentinel' ) ), $url ) );
			exit;
		}

		$result = ( new IS_Threat_Intel() )->lookup_ip( $ip );
		if ( is_wp_error( $result ) ) {
			$url = add_query_arg( 'is_error', rawurlencode( $result->get_error_message() ), $url );
		} else {
			IS_Audit_Log::record( 'threat_intel_ip_checked', array_merge( array( 'ip' => $ip ), $result ) );
			$summary = sprintf(
				/* translators: 1: IP address, 2: AbuseIPDB confidence score 0-100, 3: total report count */
				__( 'AbuseIPDB: %1$s scored %2$d/100 (%3$d reports).', 'integrity-sentinel' ),
				$ip,
				$result['score'],
				$result['total_reports']
			);
			$url = add_query_arg( 'is_ti_result', rawurlencode( $summary ), $url );
		}
		wp_safe_redirect( $url );
		exit;
	}

	public function handle_check_hash_reputation() {
		$this->guard_threat_intel_action();
		$finding_id = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
		$finding    = $finding_id ? IS_DB::instance()->get_finding( $finding_id ) : null;
		$url        = admin_url( 'admin.php?page=integrity-sentinel-findings' );

		if ( ! $finding || empty( $finding['file_hash'] ) ) {
			wp_safe_redirect( add_query_arg( 'is_error', rawurlencode( __( 'This finding has no file hash to check.', 'integrity-sentinel' ) ), $url ) );
			exit;
		}

		$result = ( new IS_Threat_Intel() )->lookup_hash( $finding['file_hash'] );
		if ( is_wp_error( $result ) ) {
			$url = add_query_arg( 'is_error', rawurlencode( $result->get_error_message() ), $url );
		} else {
			IS_Audit_Log::record( 'threat_intel_hash_checked', array_merge( array( 'finding_id' => $finding_id ), $result ) );
			$summary = ! empty( $result['unknown'] )
				? __( 'VirusTotal: this hash is not in their database.', 'integrity-sentinel' )
				: sprintf(
					/* translators: 1: number of engines flagging as malicious, 2: number flagging as suspicious */
					__( 'VirusTotal: %1$d engine(s) flagged this as malicious, %2$d as suspicious.', 'integrity-sentinel' ),
					$result['malicious'],
					$result['suspicious']
				);
			$url = add_query_arg( 'is_ti_result', rawurlencode( $summary ), $url );
		}
		wp_safe_redirect( $url );
		exit;
	}

	/** Streams the current software inventory as a JSON download -- not a redirect, since there's nothing to redirect back to. */
	public function handle_download_sbom() {
		$this->guard_threat_intel_action();
		$document = IS_SBOM::to_document( IS_SBOM::generate() );

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="integrity-sentinel-sbom-' . gmdate( 'Y-m-d' ) . '.json"' );
		echo wp_json_encode( $document, JSON_PRETTY_PRINT );
		exit;
	}

	// -----------------------------------------------------------------
	// Dashboard
	// -----------------------------------------------------------------

	public function render_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$db      = IS_DB::instance();
		$latest  = $db->get_latest_run();
		$counts  = $db->severity_counts( 'new' );
		$running = $db->get_running_run();
		$this->render_shell_open( 'dashboard' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Integrity Sentinel', 'integrity-sentinel' ); ?></h1>
			<p class="description">
				<?php esc_html_e( 'Verifies WordPress core and plugin files against official WordPress.org checksums, and scans every PHP file for common malware/webshell patterns.', 'integrity-sentinel' ); ?>
			</p>

			<div class="is-cards">
				<div class="is-card is-card-critical">
					<span class="is-card-count"><?php echo esc_html( $counts['critical'] ); ?></span>
					<span class="is-card-label"><?php esc_html_e( 'Critical', 'integrity-sentinel' ); ?></span>
				</div>
				<div class="is-card is-card-high">
					<span class="is-card-count"><?php echo esc_html( $counts['high'] ); ?></span>
					<span class="is-card-label"><?php esc_html_e( 'High', 'integrity-sentinel' ); ?></span>
				</div>
				<div class="is-card is-card-medium">
					<span class="is-card-count"><?php echo esc_html( $counts['medium'] ); ?></span>
					<span class="is-card-label"><?php esc_html_e( 'Medium', 'integrity-sentinel' ); ?></span>
				</div>
				<div class="is-card is-card-low">
					<span class="is-card-count"><?php echo esc_html( $counts['low'] ); ?></span>
					<span class="is-card-label"><?php esc_html_e( 'Low', 'integrity-sentinel' ); ?></span>
				</div>
			</div>

			<p>
				<?php if ( $latest ) : ?>
					<?php
					printf(
						/* translators: 1: human time diff, 2: files scanned, 3: files total */
						esc_html__( 'Last scan: %1$s ago — %2$d / %3$d files scanned.', 'integrity-sentinel' ),
						esc_html( human_time_diff( strtotime( $latest['started_at'] ) ) ),
						(int) $latest['files_scanned'],
						(int) $latest['files_total']
					);
					?>
				<?php else : ?>
					<?php esc_html_e( 'No scan has run yet.', 'integrity-sentinel' ); ?>
				<?php endif; ?>
				<?php $next_scan = wp_next_scheduled( IS_CRON_DAILY_SCAN ); ?>
				<?php if ( $next_scan ) : ?>
					<br>
					<?php
					printf(
						/* translators: %s: human-readable time until the next scheduled scan */
						esc_html__( 'Next scheduled scan: in %s.', 'integrity-sentinel' ),
						esc_html( human_time_diff( $next_scan ) )
					);
					?>
				<?php endif; ?>
			</p>

			<button type="button" class="button button-primary" id="is-scan-now-btn" <?php disabled( (bool) $running ); ?>>
				<?php esc_html_e( 'Scan now', 'integrity-sentinel' ); ?>
			</button>

			<div id="is-scan-progress" class="is-progress-wrap" style="<?php echo $running ? '' : 'display:none;'; ?>">
				<div class="is-progress-bar"><div class="is-progress-fill" id="is-progress-fill"></div></div>
				<p id="is-progress-text"></p>
			</div>

			<h2><?php esc_html_e( 'What this scans', 'integrity-sentinel' ); ?></h2>
			<ul class="is-explainer">
				<li><?php esc_html_e( 'WordPress core files against the official WordPress.org checksum API — including unexpected extra files inside wp-admin/ and wp-includes/.', 'integrity-sentinel' ); ?></li>
				<li><?php esc_html_e( 'Installed WordPress.org plugin files against their published checksums — including unexpected extra files inside those plugins\' directories.', 'integrity-sentinel' ); ?></li>
				<li><?php esc_html_e( 'Every PHP file, for common malware/webshell code patterns.', 'integrity-sentinel' ); ?></li>
				<li><?php esc_html_e( 'PHP files hiding inside the uploads directory (which should only ever contain media).', 'integrity-sentinel' ); ?></li>
			</ul>
			<p class="description">
				<?php esc_html_e( 'Themes, mu-plugins, and premium/custom plugins have no published WordPress.org checksums, so they can\'t be checksum-verified — their PHP files are still covered by the malware-pattern scan.', 'integrity-sentinel' ); ?>
			</p>
			<p class="description">
				<?php esc_html_e( 'Started as a file-integrity and pattern scanner and has grown into a full hardening suite: access control, login/2FA protection, a REST firewall, hotlink/bot blocking, and a human-in-the-loop quarantine engine — all summarized below. Every feature is off-by-default when it could break something (XML-RPC, feeds, REST lockdown, login rename), and on-by-default when it can\'t.', 'integrity-sentinel' ); ?>
			</p>

			<?php $this->render_security_status(); ?>
			<?php $this->render_feature_health(); ?>
		</div>
		<?php
		$this->render_shell_close();
	}

	/**
	 * One place to see the state of every hardening feature this plugin
	 * ships, each linking straight to where it's configured -- the
	 * "unified" view the settings are scattered across several
	 * WP-admin-convention submenu pages (Hardening, Access Control,
	 * Login Security, REST API) rather than physically merged into one,
	 * since that's how every other security plugin's settings are
	 * organized and users already know that pattern.
	 *
	 * @return array<array{label:string,ok:bool,text:string,url:string}>
	 */
	private function security_status_items() {
		$headers      = IS_Headers::settings();
		$ip           = IS_IP_List::settings();
		$login_rename = IS_Login::rename_settings();
		$throttle     = IS_Login::throttle_settings();
		$bots         = IS_Bot_Block::settings();
		$rest         = IS_Rest_API::settings();
		$posts        = IS_Rest_Posts::settings();
		$two_factor   = IS_2FA::settings();
		$pending      = IS_DB::instance()->count_quarantine_items( 'quarantined' );

		$whitelist_count = count( IS_IP_List::parse_list_text( $ip['whitelist'] ) );
		$blacklist_count = count( IS_IP_List::parse_list_text( $ip['blacklist'] ) );

		$hardening_url = admin_url( 'admin.php?page=integrity-sentinel-hardening' );
		$access_url    = admin_url( 'admin.php?page=integrity-sentinel-access' );
		$login_url     = admin_url( 'admin.php?page=integrity-sentinel-login' );
		$rest_url      = admin_url( 'admin.php?page=integrity-sentinel-rest' );

		return array(
			array(
				'label' => __( 'Security headers', 'integrity-sentinel' ),
				'ok'    => ! empty( $headers['security_headers'] ) && ! empty( $headers['prevent_clickjacking'] ),
				'text'  => ( ! empty( $headers['security_headers'] ) && ! empty( $headers['prevent_clickjacking'] ) ) ? __( 'Active', 'integrity-sentinel' ) : __( 'Partially off', 'integrity-sentinel' ),
				'url'   => $hardening_url,
			),
			array(
				'label' => __( 'Hide WP version', 'integrity-sentinel' ),
				'ok'    => ! empty( $headers['hide_wp_version'] ),
				'text'  => ! empty( $headers['hide_wp_version'] ) ? __( 'Hidden', 'integrity-sentinel' ) : __( 'Visible', 'integrity-sentinel' ),
				'url'   => $hardening_url,
			),
			array(
				'label' => __( 'XML-RPC', 'integrity-sentinel' ),
				'ok'    => ! empty( $headers['disable_xmlrpc'] ),
				'text'  => ! empty( $headers['disable_xmlrpc'] ) ? __( 'Disabled', 'integrity-sentinel' ) : __( 'Enabled', 'integrity-sentinel' ),
				'url'   => $hardening_url,
			),
			array(
				'label' => __( 'RSS/Atom feeds', 'integrity-sentinel' ),
				'ok'    => ! empty( $headers['disable_feeds'] ),
				'text'  => ! empty( $headers['disable_feeds'] ) ? __( 'Disabled', 'integrity-sentinel' ) : __( 'Enabled', 'integrity-sentinel' ),
				'url'   => $hardening_url,
			),
			array(
				'label' => __( 'Hotlink protection', 'integrity-sentinel' ),
				'ok'    => IS_Hotlink::active(),
				'text'  => IS_Hotlink::active() ? __( 'Protected', 'integrity-sentinel' ) : __( 'Not blocked', 'integrity-sentinel' ),
				'url'   => $hardening_url,
			),
			array(
				'label' => __( 'IP access control', 'integrity-sentinel' ),
				'ok'    => true,
				/* translators: 1: whitelisted count, 2: blacklisted count */
				'text'  => sprintf( __( '%1$d whitelisted, %2$d blacklisted', 'integrity-sentinel' ), $whitelist_count, $blacklist_count ),
				'url'   => $access_url,
			),
			array(
				'label' => __( 'AI bot blocking', 'integrity-sentinel' ),
				'ok'    => ! empty( $bots['enabled'] ),
				'text'  => ! empty( $bots['enabled'] ) ? __( 'Active', 'integrity-sentinel' ) : __( 'Off', 'integrity-sentinel' ),
				'url'   => $access_url,
			),
			array(
				'label' => __( 'Login URL', 'integrity-sentinel' ),
				'ok'    => '' !== $login_rename['login_slug'] || '' !== $login_rename['login_host'],
				'text'  => ( '' !== $login_rename['login_slug'] || '' !== $login_rename['login_host'] ) ? __( 'Hidden', 'integrity-sentinel' ) : __( 'Default', 'integrity-sentinel' ),
				'url'   => $login_url,
			),
			array(
				'label' => __( 'Login rate limiting', 'integrity-sentinel' ),
				'ok'    => ! empty( $throttle['enabled'] ),
				'text'  => ! empty( $throttle['enabled'] ) ? __( 'Active', 'integrity-sentinel' ) : __( 'Off', 'integrity-sentinel' ),
				'url'   => $login_url,
			),
			array(
				'label' => __( 'Two-factor authentication', 'integrity-sentinel' ),
				'ok'    => ! empty( $two_factor['enforced_roles'] ),
				/* translators: %d: number of roles */
				'text'  => ! empty( $two_factor['enforced_roles'] ) ? sprintf( __( 'Required for %d role(s)', 'integrity-sentinel' ), count( $two_factor['enforced_roles'] ) ) : __( 'Optional', 'integrity-sentinel' ),
				'url'   => $login_url,
			),
			array(
				'label' => __( 'REST user enumeration', 'integrity-sentinel' ),
				'ok'    => ! empty( $rest['block_user_enumeration'] ),
				'text'  => ! empty( $rest['block_user_enumeration'] ) ? __( 'Blocked', 'integrity-sentinel' ) : __( 'Allowed', 'integrity-sentinel' ),
				'url'   => $rest_url,
			),
			array(
				'label' => __( 'Blog post endpoint', 'integrity-sentinel' ),
				'ok'    => true,
				'text'  => ! empty( $posts['enabled'] ) ? __( 'Enabled', 'integrity-sentinel' ) : __( 'Disabled', 'integrity-sentinel' ),
				'url'   => $rest_url,
			),
			array(
				'label' => __( 'Quarantine', 'integrity-sentinel' ),
				'ok'    => 0 === $pending,
				/* translators: %d: number of items awaiting review */
				'text'  => $pending > 0 ? sprintf( _n( '%d item awaiting review', '%d items awaiting review', $pending, 'integrity-sentinel' ), $pending ) : __( 'Nothing pending', 'integrity-sentinel' ),
				'url'   => admin_url( 'admin.php?page=integrity-sentinel-quarantine' ),
			),
		);
	}

	private function render_security_status() {
		?>
		<h2><?php esc_html_e( 'Security status', 'integrity-sentinel' ); ?></h2>
		<div class="is-status-grid">
			<?php foreach ( $this->security_status_items() as $item ) : ?>
				<a class="is-status-item <?php echo $item['ok'] ? 'is-status-ok' : 'is-status-warn'; ?>" href="<?php echo esc_url( $item['url'] ); ?>">
					<span class="is-status-dot" aria-hidden="true"></span>
					<span class="is-status-label"><?php echo esc_html( $item['label'] ); ?></span>
					<span class="is-status-value"><?php echo esc_html( $item['text'] ); ?></span>
				</a>
			<?php endforeach; ?>
		</div>
		<?php
	}

	// -----------------------------------------------------------------
	// Feature health
	// -----------------------------------------------------------------

	/**
	 * Every hardening/detection module runs under IS_Guard, which pauses
	 * a module (rather than letting it fatal the site) if it keeps
	 * throwing. This panel surfaces that state so a paused module isn't
	 * silently invisible -- and it always shows the IS_SAFE_MODE kill
	 * switch, since that's the thing a locked-out admin needs to find in
	 * a hurry.
	 */
	private function render_feature_health() {
		$health = IS_Guard::all_health();
		?>
		<h2><?php esc_html_e( 'Feature health', 'integrity-sentinel' ); ?></h2>

		<?php if ( IS_Guard::is_safe_mode() ) : ?>
			<div class="notice notice-warning inline">
				<p>
					<strong><?php esc_html_e( 'Safe mode is active.', 'integrity-sentinel' ); ?></strong>
					<?php esc_html_e( 'IS_SAFE_MODE is defined truthy in wp-config.php, so every hardening module is currently paused. Remove that constant to resume normal protection.', 'integrity-sentinel' ); ?>
				</p>
			</div>
		<?php endif; ?>

		<?php if ( empty( $health ) ) : ?>
			<p class="description"><?php esc_html_e( 'All modules healthy. No hardening module has hit a fault.', 'integrity-sentinel' ); ?></p>
		<?php else : ?>
			<table class="widefat striped" style="max-width:800px;">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Module', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Status', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Last error', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Action', 'integrity-sentinel' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $health as $module => $state ) : ?>
						<?php $disabled = IS_Guard::is_disabled( $state, time() ); ?>
						<tr>
							<td><code><?php echo esc_html( $module ); ?></code></td>
							<td>
								<?php if ( $disabled ) : ?>
									<span class="is-badge is-badge-high"><?php esc_html_e( 'Paused', 'integrity-sentinel' ); ?></span>
								<?php elseif ( 'degraded' === $state['status'] ) : ?>
									<span class="is-badge is-badge-medium"><?php esc_html_e( 'Degraded', 'integrity-sentinel' ); ?></span>
								<?php else : ?>
									<span class="is-badge is-badge-low"><?php esc_html_e( 'OK', 'integrity-sentinel' ); ?></span>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( $state['last_error'] ? $state['last_error'] : '—' ); ?></td>
							<td>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<?php wp_nonce_field( 'is_reset_module_health' ); ?>
									<input type="hidden" name="action" value="is_reset_module_health">
									<input type="hidden" name="module" value="<?php echo esc_attr( $module ); ?>">
									<?php submit_button( __( 'Reset', 'integrity-sentinel' ), 'secondary small', 'submit', false ); ?>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<?php
	}

	// -----------------------------------------------------------------
	// Findings
	// -----------------------------------------------------------------

	public function render_findings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$db = IS_DB::instance();

		$status   = isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : 'new'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter, not a state change
		$severity = isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$paged    = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$per_page = 30;

		$args = array(
			'status'   => 'all' === $status ? '' : $status,
			'severity' => $severity,
			'limit'    => $per_page,
			'offset'   => ( $paged - 1 ) * $per_page,
		);

		$findings    = $db->get_findings( $args );
		$total       = $db->count_findings(
			array(
				'status'   => $args['status'],
				'severity' => $severity,
			)
		);
		$pages       = max( 1, (int) ceil( $total / $per_page ) );
		$error       = isset( $_GET['is_error'] ) ? sanitize_text_field( rawurldecode( wp_unslash( $_GET['is_error'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only message set by our own redirect
		$ti_result   = isset( $_GET['is_ti_result'] ) ? sanitize_text_field( rawurldecode( wp_unslash( $_GET['is_ti_result'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only message set by our own redirect
		$ti_settings = IS_Threat_Intel::settings();
		$ti_ready    = ! empty( $ti_settings['enabled'] ) && '' !== trim( (string) $ti_settings['virustotal_key'] );
		$this->render_shell_open( 'findings' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Findings', 'integrity-sentinel' ); ?></h1>
			<?php if ( $error ) : ?>
				<div class="notice notice-error"><p><?php echo esc_html( $error ); ?></p></div>
			<?php endif; ?>
			<?php if ( $ti_result ) : ?>
				<div class="notice notice-info"><p><?php echo esc_html( $ti_result ); ?></p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['is_quarantined'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag from our own redirect ?>
				<div class="notice notice-success"><p><?php esc_html_e( 'File moved to quarantine. It has not been deleted — review it under Quarantine.', 'integrity-sentinel' ); ?></p></div>
			<?php endif; ?>
			<p class="description"><?php esc_html_e( 'Ignoring a finding stays durable: it won\'t reappear on later scans as long as the file\'s content is unchanged. If the file actually changes afterward, it\'s flagged again as new — an old "ignore" never silently covers different content.', 'integrity-sentinel' ); ?></p>

			<ul class="subsubsub">
				<?php
				$statuses = array(
					'new'          => __( 'New', 'integrity-sentinel' ),
					'acknowledged' => __( 'Acknowledged', 'integrity-sentinel' ),
					'ignored'      => __( 'Ignored', 'integrity-sentinel' ),
					'resolved'     => __( 'Resolved', 'integrity-sentinel' ),
					'all'          => __( 'All', 'integrity-sentinel' ),
				);
				$links    = array();
				foreach ( $statuses as $key => $label ) {
					$url     = add_query_arg(
						array(
							'page'   => 'integrity-sentinel-findings',
							'status' => $key,
						),
						admin_url( 'admin.php' )
					);
					$class   = ( $status === $key ) ? 'current' : '';
					$links[] = sprintf( '<a href="%s" class="%s">%s</a>', esc_url( $url ), esc_attr( $class ), esc_html( $label ) );
				}
				echo wp_kses_post( implode( ' | ', $links ) );
				?>
			</ul>

			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Severity', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'File', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Issue', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'First seen', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Last seen', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'integrity-sentinel' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $findings ) ) : ?>
						<tr><td colspan="6"><?php esc_html_e( 'No findings in this view.', 'integrity-sentinel' ); ?></td></tr>
					<?php endif; ?>
					<?php foreach ( $findings as $f ) : ?>
						<tr data-finding-id="<?php echo esc_attr( $f['id'] ); ?>">
							<td><span class="is-badge is-badge-<?php echo esc_attr( $f['severity'] ); ?>"><?php echo esc_html( ucfirst( $f['severity'] ) ); ?></span></td>
							<td><code><?php echo esc_html( $f['file_path'] ); ?></code></td>
							<td>
								<?php echo esc_html( $f['detail'] ); ?>
								<br>
								<a href="#" class="is-view-finding" data-id="<?php echo esc_attr( $f['id'] ); ?>"><?php esc_html_e( 'View details', 'integrity-sentinel' ); ?></a>
							</td>
							<td><?php echo esc_html( human_time_diff( strtotime( $f['first_seen'] ) ) . ' ' . __( 'ago', 'integrity-sentinel' ) ); ?></td>
							<td><?php echo esc_html( human_time_diff( strtotime( $f['last_seen'] ) ) . ' ' . __( 'ago', 'integrity-sentinel' ) ); ?></td>
							<td>
								<?php if ( in_array( $f['status'], array( 'new', 'acknowledged' ), true ) ) : ?>
									<a href="#" class="is-finding-action" data-id="<?php echo esc_attr( $f['id'] ); ?>" data-status="acknowledged"><?php esc_html_e( 'Acknowledge', 'integrity-sentinel' ); ?></a> |
									<a href="#" class="is-finding-action" data-id="<?php echo esc_attr( $f['id'] ); ?>" data-status="ignored"><?php esc_html_e( 'Ignore', 'integrity-sentinel' ); ?></a> |
									<a href="#" class="is-finding-action" data-id="<?php echo esc_attr( $f['id'] ); ?>" data-status="resolved"><?php esc_html_e( 'Mark resolved', 'integrity-sentinel' ); ?></a>
									<?php if ( IS_Quarantine::is_eligible_issue_type( $f['issue_type'] ) ) : ?>
										|
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;" onsubmit="return confirm('<?php echo esc_js( __( 'Move this file to quarantine? It is suspended, not deleted, and can be restored from the Quarantine screen at any time.', 'integrity-sentinel' ) ); ?>');">
											<?php wp_nonce_field( 'is_quarantine_action' ); ?>
											<input type="hidden" name="action" value="is_quarantine_finding">
											<input type="hidden" name="finding_id" value="<?php echo esc_attr( $f['id'] ); ?>">
											<button type="submit" class="button-link" style="color:#b32d2e;"><?php esc_html_e( 'Quarantine', 'integrity-sentinel' ); ?></button>
										</form>
									<?php endif; ?>
								<?php else : ?>
									<em><?php echo esc_html( ucfirst( $f['status'] ) ); ?></em>
								<?php endif; ?>
								<?php if ( $ti_ready && ! empty( $f['file_hash'] ) ) : ?>
									|
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
										<?php wp_nonce_field( 'is_threat_intel_action' ); ?>
										<input type="hidden" name="action" value="is_check_hash_reputation">
										<input type="hidden" name="finding_id" value="<?php echo esc_attr( $f['id'] ); ?>">
										<button type="submit" class="button-link"><?php esc_html_e( 'Check reputation', 'integrity-sentinel' ); ?></button>
									</form>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $pages > 1 ) : ?>
				<div class="tablenav"><div class="tablenav-pages">
					<?php
					for ( $p = 1; $p <= $pages; $p++ ) {
						$url = add_query_arg(
							array(
								'page'     => 'integrity-sentinel-findings',
								'status'   => $status,
								'severity' => $severity,
								'paged'    => $p,
							),
							admin_url( 'admin.php' )
						);
						printf( '<a class="%s" href="%s">%d</a> ', $p === $paged ? 'current' : '', esc_url( $url ), (int) $p ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					}
					?>
				</div></div>
			<?php endif; ?>

			<div id="is-finding-modal" class="is-modal" style="display:none;">
				<div class="is-modal-content">
					<button type="button" class="is-modal-close" aria-label="<?php esc_attr_e( 'Close', 'integrity-sentinel' ); ?>">&times;</button>
					<div id="is-finding-modal-body"></div>
				</div>
			</div>
		</div>
		<?php
		$this->render_shell_close();
	}

	// -----------------------------------------------------------------
	// Quarantine
	// -----------------------------------------------------------------

	/**
	 * Suspended files awaiting human review: restore to the original
	 * location, or permanently delete (behind an explicit confirmation
	 * checkbox -- this is the one truly irreversible action in the
	 * whole plugin). Nothing here happens automatically or on a
	 * schedule; every quarantine/restore/delete is a human decision.
	 */
	public function render_quarantine() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$db       = IS_DB::instance();
		$status   = isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : 'quarantined'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter, not a state change
		$paged    = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$per_page = 30;
		$error    = isset( $_GET['is_error'] ) ? sanitize_text_field( rawurldecode( wp_unslash( $_GET['is_error'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only message set by our own redirect

		$items = $db->get_quarantine_items( $status, $per_page, ( $paged - 1 ) * $per_page );
		$total = $db->count_quarantine_items( $status );
		$pages = max( 1, (int) ceil( $total / $per_page ) );
		$this->render_shell_open( 'quarantine' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Quarantine', 'integrity-sentinel' ); ?></h1>
			<?php if ( $error ) : ?>
				<div class="notice notice-error"><p><?php echo esc_html( $error ); ?></p></div>
			<?php endif; ?>
			<p class="description">
				<?php esc_html_e( 'A quarantined file is suspended, not deleted: moved into a locked-down directory outside its original location, and left there until you explicitly restore it or permanently delete it. Nothing here happens automatically.', 'integrity-sentinel' ); ?>
			</p>

			<ul class="subsubsub">
				<?php
				$statuses = array(
					'quarantined' => __( 'Awaiting review', 'integrity-sentinel' ),
					'restored'    => __( 'Restored', 'integrity-sentinel' ),
					'deleted'     => __( 'Deleted', 'integrity-sentinel' ),
				);
				$links    = array();
				foreach ( $statuses as $key => $label ) {
					$url     = add_query_arg(
						array(
							'page'   => 'integrity-sentinel-quarantine',
							'status' => $key,
						),
						admin_url( 'admin.php' )
					);
					$class   = ( $status === $key ) ? 'current' : '';
					$links[] = sprintf( '<a href="%s" class="%s">%s</a>', esc_url( $url ), esc_attr( $class ), esc_html( $label ) );
				}
				echo wp_kses_post( implode( ' | ', $links ) );
				?>
			</ul>

			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Original path', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Quarantined', 'integrity-sentinel' ); ?></th>
						<?php if ( 'quarantined' === $status ) : ?>
							<th><?php esc_html_e( 'Actions', 'integrity-sentinel' ); ?></th>
						<?php else : ?>
							<th><?php esc_html_e( 'Reviewed', 'integrity-sentinel' ); ?></th>
						<?php endif; ?>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $items ) ) : ?>
						<tr><td colspan="4"><?php esc_html_e( 'Nothing in this view.', 'integrity-sentinel' ); ?></td></tr>
					<?php endif; ?>
					<?php foreach ( $items as $item ) : ?>
						<tr>
							<td><code><?php echo esc_html( $item['original_path'] ); ?></code></td>
							<td><?php echo esc_html( $item['reason'] ); ?></td>
							<td><?php echo esc_html( human_time_diff( strtotime( $item['quarantined_at'] ) ) . ' ' . __( 'ago', 'integrity-sentinel' ) ); ?></td>
							<?php if ( 'quarantined' === $status ) : ?>
								<td>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
										<?php wp_nonce_field( 'is_quarantine_action' ); ?>
										<input type="hidden" name="action" value="is_quarantine_restore">
										<input type="hidden" name="quarantine_id" value="<?php echo esc_attr( $item['id'] ); ?>">
										<?php submit_button( __( 'Restore', 'integrity-sentinel' ), 'secondary small', 'submit', false ); ?>
									</form>
									<button type="button" class="button button-small is-quarantine-delete-toggle" data-id="<?php echo esc_attr( $item['id'] ); ?>"><?php esc_html_e( 'Delete permanently…', 'integrity-sentinel' ); ?></button>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="is-quarantine-delete-form-<?php echo esc_attr( $item['id'] ); ?>" style="display:none;margin-top:6px;">
										<?php wp_nonce_field( 'is_quarantine_action' ); ?>
										<input type="hidden" name="action" value="is_quarantine_delete">
										<input type="hidden" name="quarantine_id" value="<?php echo esc_attr( $item['id'] ); ?>">
										<label>
											<input type="checkbox" name="is_quarantine_confirm" value="1" required>
											<?php esc_html_e( 'I understand this cannot be undone.', 'integrity-sentinel' ); ?>
										</label>
										<?php submit_button( __( 'Permanently delete', 'integrity-sentinel' ), 'delete small', 'submit', false ); ?>
									</form>
								</td>
							<?php else : ?>
								<td><?php echo $item['reviewed_at'] ? esc_html( human_time_diff( strtotime( $item['reviewed_at'] ) ) . ' ' . __( 'ago', 'integrity-sentinel' ) ) : '—'; ?></td>
							<?php endif; ?>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $pages > 1 ) : ?>
				<div class="tablenav"><div class="tablenav-pages">
					<?php
					for ( $p = 1; $p <= $pages; $p++ ) {
						$url = add_query_arg(
							array(
								'page'   => 'integrity-sentinel-quarantine',
								'status' => $status,
								'paged'  => $p,
							),
							admin_url( 'admin.php' )
						);
						printf( '<a class="%s" href="%s">%d</a> ', $p === $paged ? 'current' : '', esc_url( $url ), (int) $p ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					}
					?>
				</div></div>
			<?php endif; ?>
		</div>
		<?php
		$this->render_shell_close();
	}

	// -----------------------------------------------------------------
	// Hardening
	// -----------------------------------------------------------------

	public function render_hardening() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$active = IS_Hardening::uploads_block_active();
		$error  = isset( $_GET['is_error'] ) ? sanitize_text_field( rawurldecode( wp_unslash( $_GET['is_error'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only message set by our own redirect
		$this->render_shell_open( 'hardening' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Hardening', 'integrity-sentinel' ); ?></h1>

			<?php if ( $error ) : ?>
				<div class="notice notice-error"><p><?php echo esc_html( $error ); ?></p></div>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Block PHP execution in uploads', 'integrity-sentinel' ); ?></h2>
			<p>
				<?php esc_html_e( 'The uploads directory should only ever contain media. Blocking PHP execution there makes a dropped webshell inert even before a scan finds it — detection tells you a backdoor landed; this stops it from running at all.', 'integrity-sentinel' ); ?>
			</p>
			<p>
				<strong><?php esc_html_e( 'Status:', 'integrity-sentinel' ); ?></strong>
				<?php if ( $active ) : ?>
					<span class="is-badge is-badge-low"><?php esc_html_e( 'Protected (Apache rules in place)', 'integrity-sentinel' ); ?></span>
				<?php else : ?>
					<span class="is-badge is-badge-high"><?php esc_html_e( 'Not blocked', 'integrity-sentinel' ); ?></span>
				<?php endif; ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'is_hardening_action' ); ?>
				<?php if ( $active ) : ?>
					<input type="hidden" name="action" value="is_remove_uploads_block">
					<?php submit_button( __( 'Remove the block', 'integrity-sentinel' ), 'secondary', 'submit', false ); ?>
				<?php else : ?>
					<input type="hidden" name="action" value="is_apply_uploads_block">
					<?php submit_button( __( 'Apply the block', 'integrity-sentinel' ), 'primary', 'submit', false ); ?>
				<?php endif; ?>
			</form>

			<p class="description">
				<?php esc_html_e( 'This writes a clearly-marked rule block into the uploads .htaccess (existing rules are preserved, and removal deletes only our block). It protects Apache and LiteSpeed servers. On nginx, .htaccess has no effect — add this to your server config instead:', 'integrity-sentinel' ); ?>
			</p>
			<pre><?php echo esc_html( IS_Hardening::nginx_snippet() ); ?></pre>

			<?php $this->render_other_exec_block_targets(); ?>

			<?php $this->render_hotlink_section(); ?>

			<?php $this->render_http_hardening_section(); ?>

			<?php $this->render_asset_cloak_section(); ?>

			<?php $this->render_vulnerability_scanner_section(); ?>

			<?php $this->render_signatures_section(); ?>

			<?php $this->render_threat_intel_section(); ?>

			<h2><?php esc_html_e( 'Hardening checks', 'integrity-sentinel' ); ?></h2>
			<p>
				<?php esc_html_e( 'Every scan also audits site configuration: the file editor, debug output, auth salts, world-writable paths, exposed .git/.env/debug.log files, backup archives in the webroot, administrator accounts, plugins closed on WordPress.org, and more. Results appear under Findings alongside file-integrity issues.', 'integrity-sentinel' ); ?>
			</p>
		</div>
		<?php
		$this->render_shell_close();
	}

	/**
	 * Other writable, commonly-abused directories (cache/upgrade/temp)
	 * that benefit from the same PHP-execution block as uploads. Only
	 * directories that actually exist on this install are listed.
	 */
	private function render_other_exec_block_targets() {
		$targets = IS_Hardening::exec_block_targets();
		unset( $targets['uploads'] ); // covered by its own dedicated section above
		if ( empty( $targets ) ) {
			return;
		}
		?>
		<h2><?php esc_html_e( 'Block PHP execution in other writable directories', 'integrity-sentinel' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Caches, upgrade staging, and temp directories are writable by WordPress and are common secondary drop locations for a webshell. Same protection as uploads, applied per directory.', 'integrity-sentinel' ); ?></p>
		<table class="widefat striped" style="max-width:700px;">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Directory', 'integrity-sentinel' ); ?></th>
					<th><?php esc_html_e( 'Status', 'integrity-sentinel' ); ?></th>
					<th><?php esc_html_e( 'Action', 'integrity-sentinel' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $targets as $key => $target ) : ?>
					<?php $active = IS_Hardening::block_active_for( $target['abs_path'] ); ?>
					<tr>
						<td><?php echo esc_html( $target['label'] ); ?></td>
						<td>
							<?php if ( $active ) : ?>
								<span class="is-badge is-badge-low"><?php esc_html_e( 'Protected', 'integrity-sentinel' ); ?></span>
							<?php else : ?>
								<span class="is-badge is-badge-high"><?php esc_html_e( 'Not blocked', 'integrity-sentinel' ); ?></span>
							<?php endif; ?>
						</td>
						<td>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
								<?php wp_nonce_field( 'is_hardening_action' ); ?>
								<input type="hidden" name="target" value="<?php echo esc_attr( $key ); ?>">
								<?php if ( $active ) : ?>
									<input type="hidden" name="action" value="is_remove_exec_block">
									<?php submit_button( __( 'Remove', 'integrity-sentinel' ), 'secondary small', 'submit', false ); ?>
								<?php else : ?>
									<input type="hidden" name="action" value="is_apply_exec_block">
									<?php submit_button( __( 'Apply', 'integrity-sentinel' ), 'primary small', 'submit', false ); ?>
								<?php endif; ?>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Hotlink protection for the uploads directory. Same .htaccess
	 * marker-block mechanism as the exec blocks above (static image
	 * requests never go through PHP, so there's no other way to enforce
	 * this) but with its own independent BEGIN/END markers.
	 */
	private function render_hotlink_section() {
		$active    = IS_Hotlink::active();
		$settings  = IS_Hotlink::settings();
		$home_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		?>
		<h2><?php esc_html_e( 'Hotlink protection', 'integrity-sentinel' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Stops other sites from embedding your images directly (bandwidth theft). Direct access, feed readers, and social-share previews (which send no referer) always still work.', 'integrity-sentinel' ); ?></p>

		<form method="post" action="options.php">
			<?php settings_fields( 'is_hotlink_settings_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="is_hotlink_allowed_domains"><?php esc_html_e( 'Allowed domains', 'integrity-sentinel' ); ?></label></th>
					<td>
						<textarea id="is_hotlink_allowed_domains" name="is_hotlink_settings[allowed_domains]" rows="4" class="large-text code"><?php echo esc_textarea( $settings['allowed_domains'] ); ?></textarea>
						<p class="description">
							<?php
							printf(
								/* translators: %s: the site's own domain */
								esc_html__( 'One domain per line, in addition to your own (%s), which is always allowed automatically.', 'integrity-sentinel' ),
								esc_html( $home_host )
							);
							?>
						</p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save allowed domains', 'integrity-sentinel' ) ); ?>
		</form>

		<p>
			<strong><?php esc_html_e( 'Status:', 'integrity-sentinel' ); ?></strong>
			<?php if ( $active ) : ?>
				<span class="is-badge is-badge-low"><?php esc_html_e( 'Protected (Apache rules in place)', 'integrity-sentinel' ); ?></span>
			<?php else : ?>
				<span class="is-badge is-badge-high"><?php esc_html_e( 'Not blocked', 'integrity-sentinel' ); ?></span>
			<?php endif; ?>
		</p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'is_hardening_action' ); ?>
			<?php if ( $active ) : ?>
				<input type="hidden" name="action" value="is_remove_hotlink_block">
				<?php submit_button( __( 'Remove the block', 'integrity-sentinel' ), 'secondary', 'submit', false ); ?>
			<?php else : ?>
				<input type="hidden" name="action" value="is_apply_hotlink_block">
				<?php submit_button( __( 'Apply the block', 'integrity-sentinel' ), 'primary', 'submit', false ); ?>
			<?php endif; ?>
		</form>
		<p class="description"><?php esc_html_e( 'On nginx, .htaccess has no effect — add this to your server config instead:', 'integrity-sentinel' ); ?></p>
		<pre><?php echo esc_html( IS_Hotlink::nginx_snippet( $home_host, IS_Hotlink::parse_domain_list( $settings['allowed_domains'] ) ) ); ?></pre>
		<?php
	}

	/**
	 * HTTP hardening toggles: security headers (incl. clickjacking),
	 * hiding the WordPress version, and disabling XML-RPC/RSS feeds.
	 * The first three are safe to leave on for every site; the last two
	 * can break a real integration (Jetpack, feed subscribers), so
	 * they're clearly marked and off by default.
	 */
	private function render_http_hardening_section() {
		$settings = IS_Headers::settings();
		?>
		<h2><?php esc_html_e( 'HTTP hardening', 'integrity-sentinel' ); ?></h2>
		<form method="post" action="options.php">
			<?php settings_fields( 'is_hardening_settings_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Security headers', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_hardening_settings[security_headers]" value="1" <?php checked( $settings['security_headers'], 1 ); ?>>
							<?php esc_html_e( 'Send X-Content-Type-Options, Referrer-Policy, and a conservative Permissions-Policy on every response (safe for any site).', 'integrity-sentinel' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Clickjacking protection', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_hardening_settings[prevent_clickjacking]" value="1" <?php checked( $settings['prevent_clickjacking'], 1 ); ?>>
							<?php esc_html_e( 'Send X-Frame-Options: SAMEORIGIN and a frame-ancestors CSP so the site can\'t be embedded in another site\'s iframe (safe for any site — your own iframes, e.g. the Customizer preview, stay same-origin).', 'integrity-sentinel' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Hide WordPress version', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_hardening_settings[hide_wp_version]" value="1" <?php checked( $settings['hide_wp_version'], 1 ); ?>>
							<?php esc_html_e( 'Remove the generator meta tag and the ?ver= query string from enqueued scripts/styles (safe for any site — this only slows down casual version fingerprinting, it is not a substitute for staying updated).', 'integrity-sentinel' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Hide WordPress fingerprints', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_hardening_settings[hide_meta_fingerprints]" value="1" <?php checked( $settings['hide_meta_fingerprints'], 1 ); ?>>
							<?php esc_html_e( 'Remove the head links and REST-discovery header that advertise WordPress-specific endpoints on every page (wlwmanifest, shortlink, the api.w.org discovery link/header).', 'integrity-sentinel' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Safe for any site — purely stops advertising these URLs; it does not disable anything, so nothing that already knows the URL is affected.', 'integrity-sentinel' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Disable XML-RPC', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_hardening_settings[disable_xmlrpc]" value="1" <?php checked( $settings['disable_xmlrpc'], 1 ); ?>>
							<?php esc_html_e( 'Disable every XML-RPC method (a long-standing brute-force/amplification vector).', 'integrity-sentinel' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Only enable this if nothing on the site needs XML-RPC — Jetpack and some mobile apps/publishing tools do.', 'integrity-sentinel' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Disable RSS/Atom feeds', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_hardening_settings[disable_feeds]" value="1" <?php checked( $settings['disable_feeds'], 1 ); ?>>
							<?php esc_html_e( 'Return 403 for every feed URL (post, comment, category, author, etc.).', 'integrity-sentinel' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Only enable this if the site has no RSS subscribers or feed-consuming integrations.', 'integrity-sentinel' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="is_csp_policy"><?php esc_html_e( 'Content-Security-Policy', 'integrity-sentinel' ); ?></label></th>
					<td>
						<textarea id="is_csp_policy" name="is_hardening_settings[content_security_policy]" rows="4" class="large-text code" placeholder="<?php echo esc_attr( IS_Headers::suggested_csp() ); ?>"><?php echo esc_textarea( $settings['content_security_policy'] ); ?></textarea>
						<p class="description">
							<?php
							printf(
								/* translators: %s: a ready-to-use suggested policy string */
								esc_html__( 'Empty = off. A reasonable starting point that rarely breaks a typical WordPress theme/plugin mix: %s — copy it in and adjust as needed.', 'integrity-sentinel' ),
								'<code>' . esc_html( IS_Headers::suggested_csp() ) . '</code>'
							);
							?>
						</p>
						<label style="display:block;margin-top:6px;">
							<input type="checkbox" name="is_hardening_settings[csp_report_only]" value="1" <?php checked( $settings['csp_report_only'], 1 ); ?>>
							<?php esc_html_e( 'Report-only — log violations to the browser console without blocking anything. Recommended while testing; a wrong policy in enforcing mode can break scripts/styles sitewide.', 'integrity-sentinel' ); ?>
						</label>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save HTTP hardening settings', 'integrity-sentinel' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Rewrites wp-content/wp-includes asset URLs to a disguised alias --
	 * the riskiest thing this plugin writes to disk (a root .htaccess
	 * rewrite rule). See IS_Asset_Cloak's class docblock before touching
	 * this on a live site.
	 */
	private function render_asset_cloak_section() {
		$settings = IS_Asset_Cloak::settings();
		$active   = IS_Asset_Cloak::block_active();
		?>
		<h2><?php esc_html_e( 'Disguise wp-content/wp-includes paths', 'integrity-sentinel' ); ?></h2>
		<div class="notice notice-warning inline">
			<p>
				<?php esc_html_e( 'The riskiest setting on this page: it rewrites your site\'s root .htaccess file. Getting it wrong can break every stylesheet, script, and uploaded image on the site. Unlike other settings here, IS_SAFE_MODE cannot undo this — it stops the URL rewriting in PHP, but not the .htaccess rule itself. Test on a staging copy first if at all possible, and use the "Remove" button below (not just disabling the checkbox) to fully revert.', 'integrity-sentinel' ); ?>
			</p>
		</div>
		<p class="description">
			<?php esc_html_e( 'Reduces (does not eliminate) the "this is WordPress" fingerprint an anonymous visitor sees when inspecting page source or a browser\'s Sources panel: enqueued styles/scripts, uploaded media, and theme/plugin asset URLs are rewritten from /wp-content/ and /wp-includes/ to your chosen alias. A theme or plugin that hardcodes a literal wp-content path instead of using WordPress\'s own URL functions won\'t be caught by this.', 'integrity-sentinel' ); ?>
		</p>

		<form method="post" action="options.php">
			<?php settings_fields( 'is_asset_cloak_settings_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="is_asset_cloak_alias"><?php esc_html_e( 'Alias', 'integrity-sentinel' ); ?></label></th>
					<td>
						<input type="text" id="is_asset_cloak_alias" name="is_asset_cloak_settings[alias]" value="<?php echo esc_attr( $settings['alias'] ); ?>" class="regular-text" placeholder="app">
						<p class="description"><?php esc_html_e( 'e.g. "app" produces /app-content/ and /app-includes/ in place of /wp-content/ and /wp-includes/.', 'integrity-sentinel' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_asset_cloak_settings[enabled]" value="1" <?php checked( $settings['enabled'], 1 ); ?>>
							<?php esc_html_e( 'Rewrite asset URLs to the alias above.', 'integrity-sentinel' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Rewriting URLs alone does nothing until the .htaccess rule below is also applied — the disguised URLs would otherwise 404.', 'integrity-sentinel' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save alias settings', 'integrity-sentinel' ) ); ?>
		</form>

		<p>
			<strong><?php esc_html_e( '.htaccess rule status:', 'integrity-sentinel' ); ?></strong>
			<?php if ( $active ) : ?>
				<span class="is-badge is-badge-low"><?php esc_html_e( 'Applied', 'integrity-sentinel' ); ?></span>
			<?php else : ?>
				<span class="is-badge is-badge-high"><?php esc_html_e( 'Not applied', 'integrity-sentinel' ); ?></span>
			<?php endif; ?>
		</p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'is_hardening_action' ); ?>
			<?php if ( $active ) : ?>
				<input type="hidden" name="action" value="is_remove_asset_cloak">
				<?php submit_button( __( 'Remove the .htaccess rule', 'integrity-sentinel' ), 'secondary', 'submit', false ); ?>
			<?php else : ?>
				<input type="hidden" name="action" value="is_apply_asset_cloak">
				<?php submit_button( __( 'Apply the .htaccess rule', 'integrity-sentinel' ), 'primary', 'submit', false, array( 'onclick' => "return confirm('" . esc_js( __( 'This rewrites your site\'s root .htaccess file. Continue only if you understand the risk described above.', 'integrity-sentinel' ) ) . "');" ) ); ?>
			<?php endif; ?>
		</form>
		<p class="description">
			<?php esc_html_e( 'Save an alias above first. Applying writes a marked rule block to the TOP of the root .htaccess (ahead of WordPress\'s own rules — required for it to work at all) and preserves everything else already in the file; removing deletes only that block. Apache/LiteSpeed only — nginx needs this added to your server config manually:', 'integrity-sentinel' ); ?>
		</p>
		<pre><?php echo esc_html( IS_Asset_Cloak::nginx_snippet( $settings['alias'] ) ); ?></pre>
		<?php
	}

	/**
	 * Known-vulnerability scanning against the WPScan Vulnerability
	 * Database -- catches the class of risk file-integrity checking
	 * can't: an untampered plugin with a known, published CVE in the
	 * exact installed version.
	 */
	private function render_vulnerability_scanner_section() {
		$settings = IS_Vulnerability_Scanner::settings();
		?>
		<h2><?php esc_html_e( 'Known-vulnerability scanning', 'integrity-sentinel' ); ?></h2>
		<p>
			<?php esc_html_e( 'File-integrity checking confirms nothing has been tampered with — it can\'t tell you a completely untampered plugin has a known, published vulnerability in the exact version installed. This checks installed plugins and the active theme against the WPScan Vulnerability Database on every scan and reports any that match, with severity, a CVE reference where available, and the version that fixes it.', 'integrity-sentinel' ); ?>
		</p>
		<p class="description">
			<?php
			printf(
				/* translators: %s: link to wpscan.com/register */
				wp_kses(
					__( 'Requires a free WPScan API key (25 requests/day) — <a href="%s" target="_blank" rel="noopener noreferrer">register at wpscan.com</a>. Off by default since, unlike the WordPress.org lookups elsewhere in this plugin, it depends on a key only you can provide.', 'integrity-sentinel' ),
					array(
						'a' => array(
							'href'   => array(),
							'target' => array(),
							'rel'    => array(),
						),
					)
				),
				'https://wpscan.com/register'
			);
			?>
		</p>
		<form method="post" action="options.php">
			<?php settings_fields( 'is_vulnerability_scanner_settings_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="is_vuln_api_key"><?php esc_html_e( 'WPScan API key', 'integrity-sentinel' ); ?></label></th>
					<td><input type="text" id="is_vuln_api_key" name="is_vulnerability_scanner_settings[api_key]" value="<?php echo esc_attr( $settings['api_key'] ); ?>" class="regular-text" autocomplete="off"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_vulnerability_scanner_settings[enabled]" value="1" <?php checked( $settings['enabled'], 1 ); ?>>
							<?php esc_html_e( 'Check installed plugins/theme for known vulnerabilities on every scan.', 'integrity-sentinel' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'A large plugin list is covered across a few scans rather than all at once, to stay within the free tier\'s daily quota.', 'integrity-sentinel' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save vulnerability scanning settings', 'integrity-sentinel' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Exact-hash signature matching against an admin-curated known-bad-
	 * hash list -- see IS_Signatures's class doc for why this ships
	 * empty rather than with a bundled hash database.
	 */
	private function render_signatures_section() {
		$settings = IS_Signatures::settings();
		?>
		<h2><?php esc_html_e( 'Known-bad file hashes', 'integrity-sentinel' ); ?></h2>
		<p>
			<?php esc_html_e( 'Checks every scanned file\'s SHA-256 hash against a list you maintain — paste in hashes gathered from an incident write-up, a threat-intel feed, or a VirusTotal/MalwareBazaar report. An exact match is a certain finding, not a guess, so this complements (not replaces) the pattern-based heuristic scan above.', 'integrity-sentinel' ); ?>
		</p>
		<form method="post" action="options.php">
			<?php settings_fields( 'is_signatures_settings_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_signatures_settings[enabled]" value="1" <?php checked( $settings['enabled'], 1 ); ?>>
							<?php esc_html_e( 'Check file hashes against the list below on every scan.', 'integrity-sentinel' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="is_signature_hashes"><?php esc_html_e( 'Known-bad SHA-256 hashes', 'integrity-sentinel' ); ?></label></th>
					<td>
						<textarea id="is_signature_hashes" name="is_signatures_settings[hashes]" rows="6" class="large-text code" placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  # optional label"><?php echo esc_textarea( $settings['hashes'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One SHA-256 hash per line, with an optional "# label" after it. Malformed lines are ignored.', 'integrity-sentinel' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save signature settings', 'integrity-sentinel' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Opt-in reputation lookups (IP/hash) plus the software inventory
	 * (SBOM) download -- see IS_Threat_Intel and IS_SBOM's class docs.
	 * Lookups themselves happen from "Check reputation" links on the
	 * Audit Log and Findings pages, not from here.
	 */
	private function render_threat_intel_section() {
		$settings = IS_Threat_Intel::settings();
		?>
		<h2><?php esc_html_e( 'Threat intelligence & software inventory', 'integrity-sentinel' ); ?></h2>
		<p>
			<?php esc_html_e( 'Configure API keys here, then look up an IP\'s reputation from the Audit Log page or a finding\'s file hash from the Findings page — lookups are on-demand, not automatic, to keep this predictable and within free-tier quotas.', 'integrity-sentinel' ); ?>
		</p>
		<form method="post" action="options.php">
			<?php settings_fields( 'is_threat_intel_settings_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_threat_intel_settings[enabled]" value="1" <?php checked( $settings['enabled'], 1 ); ?>>
							<?php esc_html_e( 'Allow on-demand reputation lookups.', 'integrity-sentinel' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="is_ti_abuseipdb_key"><?php esc_html_e( 'AbuseIPDB API key', 'integrity-sentinel' ); ?></label></th>
					<td>
						<input type="text" id="is_ti_abuseipdb_key" name="is_threat_intel_settings[abuseipdb_key]" value="<?php echo esc_attr( $settings['abuseipdb_key'] ); ?>" class="regular-text" autocomplete="off">
						<p class="description">
							<?php
							printf(
								/* translators: %s: link to abuseipdb.com/register */
								wp_kses(
									__( 'Free tier available — <a href="%s" target="_blank" rel="noopener noreferrer">register at abuseipdb.com</a>.', 'integrity-sentinel' ),
									array(
										'a' => array(
											'href'   => array(),
											'target' => array(),
											'rel'    => array(),
										),
									)
								),
								'https://www.abuseipdb.com/register'
							);
							?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="is_ti_virustotal_key"><?php esc_html_e( 'VirusTotal API key', 'integrity-sentinel' ); ?></label></th>
					<td>
						<input type="text" id="is_ti_virustotal_key" name="is_threat_intel_settings[virustotal_key]" value="<?php echo esc_attr( $settings['virustotal_key'] ); ?>" class="regular-text" autocomplete="off">
						<p class="description">
							<?php
							printf(
								/* translators: %s: link to virustotal.com/gui/join-us */
								wp_kses(
									__( 'Free tier available — <a href="%s" target="_blank" rel="noopener noreferrer">register at virustotal.com</a>.', 'integrity-sentinel' ),
									array(
										'a' => array(
											'href'   => array(),
											'target' => array(),
											'rel'    => array(),
										),
									)
								),
								'https://www.virustotal.com/gui/join-us'
							);
							?>
						</p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save threat intelligence settings', 'integrity-sentinel' ) ); ?>
		</form>

		<h3><?php esc_html_e( 'Software inventory (SBOM)', 'integrity-sentinel' ); ?></h3>
		<p class="description"><?php esc_html_e( 'A CycloneDX-style export of every installed component (core, plugins, active theme) with its current version — regenerated and diffed automatically on every scan; an unexpected change shows up in the Audit Log as "Software inventory changed".', 'integrity-sentinel' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'is_threat_intel_action' ); ?>
			<input type="hidden" name="action" value="is_download_sbom">
			<?php submit_button( __( 'Download SBOM (JSON)', 'integrity-sentinel' ), 'secondary', 'submit', false ); ?>
		</form>
		<?php
	}

	// -----------------------------------------------------------------
	// Access control (IP allow/deny lists)
	// -----------------------------------------------------------------

	public function render_access_control() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings  = IS_IP_List::settings();
		$your_ip   = IS_IP_List::client_ip();
		$bot_block = IS_Bot_Block::settings();
		$this->render_shell_open( 'access' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Access Control', 'integrity-sentinel' ); ?></h1>
			<p class="description">
				<?php
				printf(
					/* translators: %s: the current visitor's detected IP address */
					esc_html__( 'Your current detected IP address is %s. It is always kept in the whitelist automatically when you save this page, so a blacklist mistake here can never lock you out.', 'integrity-sentinel' ),
					'<code>' . esc_html( $your_ip ? $your_ip : __( '(unknown)', 'integrity-sentinel' ) ) . '</code>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the <code> wrapper is a fixed literal, the interpolated value is esc_html()'d
				);
				?>
			</p>

			<form method="post" action="options.php">
				<?php settings_fields( 'is_ip_list_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="is_ip_whitelist"><?php esc_html_e( 'Whitelist', 'integrity-sentinel' ); ?></label></th>
						<td>
							<textarea id="is_ip_whitelist" name="is_ip_list_settings[whitelist]" rows="6" class="large-text code"><?php echo esc_textarea( $settings['whitelist'] ); ?></textarea>
							<p class="description"><?php esc_html_e( 'One IP or CIDR range per line (e.g. 203.0.113.5 or 203.0.113.0/24). Trailing "# note" comments are allowed. Always wins over the blacklist below.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_ip_blacklist"><?php esc_html_e( 'Blacklist', 'integrity-sentinel' ); ?></label></th>
						<td>
							<textarea id="is_ip_blacklist" name="is_ip_list_settings[blacklist]" rows="6" class="large-text code"><?php echo esc_textarea( $settings['blacklist'] ); ?></textarea>
							<p class="description"><?php esc_html_e( 'One IP or CIDR range per line. Matching visitors get a 403 before most of WordPress loads.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Behind a reverse proxy or CDN?', 'integrity-sentinel' ); ?></h2>
				<p class="description">
					<?php esc_html_e( 'By default only the direct connecting IP (REMOTE_ADDR) is used, which is safe but will show your proxy/CDN\'s IP for every visitor if you use one. Only fill this in if you actually run behind a reverse proxy or CDN: the forwarded-IP header is trusted ONLY when the direct connection comes from an IP in the range below, so a visitor connecting directly can never forge their way past your lists with a fake header.', 'integrity-sentinel' ); ?>
				</p>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="is_ip_header"><?php esc_html_e( 'Trusted header', 'integrity-sentinel' ); ?></label></th>
						<td>
							<select id="is_ip_header" name="is_ip_list_settings[trusted_ip_header]">
								<option value="" <?php selected( $settings['trusted_ip_header'], '' ); ?>><?php esc_html_e( 'None — always use the direct connecting IP (recommended unless you use a proxy/CDN)', 'integrity-sentinel' ); ?></option>
								<option value="X-Forwarded-For" <?php selected( $settings['trusted_ip_header'], 'X-Forwarded-For' ); ?>>X-Forwarded-For</option>
								<option value="CF-Connecting-IP" <?php selected( $settings['trusted_ip_header'], 'CF-Connecting-IP' ); ?>>CF-Connecting-IP (Cloudflare)</option>
								<option value="X-Real-IP" <?php selected( $settings['trusted_ip_header'], 'X-Real-IP' ); ?>>X-Real-IP</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_ip_trusted_ranges"><?php esc_html_e( 'Trusted proxy IP range(s)', 'integrity-sentinel' ); ?></label></th>
						<td>
							<textarea id="is_ip_trusted_ranges" name="is_ip_list_settings[trusted_proxy_ranges]" rows="3" class="large-text code"><?php echo esc_textarea( $settings['trusted_proxy_ranges'] ); ?></textarea>
							<p class="description"><?php esc_html_e( 'One IP or CIDR range per line — your proxy/CDN\'s own IP ranges, not your visitors\'.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save access control settings', 'integrity-sentinel' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'AI crawlers & scraper bots', 'integrity-sentinel' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Blocks a curated, editable list of AI-training crawlers and scrapers with a 403, and lists the same names as Disallow entries in robots.txt for the well-behaved ones that honor it. Blocking known bot user agents carries no risk to human visitors.', 'integrity-sentinel' ); ?></p>
			<form method="post" action="options.php">
				<?php settings_fields( 'is_bot_block_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_bot_block_settings[enabled]" value="1" <?php checked( $bot_block['enabled'], 1 ); ?>>
								<?php esc_html_e( 'Block the user agents listed below.', 'integrity-sentinel' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_blocked_bots"><?php esc_html_e( 'Blocked user agents', 'integrity-sentinel' ); ?></label></th>
						<td>
							<textarea id="is_blocked_bots" name="is_bot_block_settings[blocked_bots]" rows="10" class="large-text code"><?php echo esc_textarea( $bot_block['blocked_bots'] ); ?></textarea>
							<p class="description"><?php esc_html_e( 'One user-agent substring per line, matched case-insensitively (e.g. "GPTBot" matches any user agent containing that text).', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save bot blocking settings', 'integrity-sentinel' ) ); ?>
			</form>
		</div>
		<?php
		$this->render_shell_close();
	}

	// -----------------------------------------------------------------
	// Login security (rename + rate limiting)
	// -----------------------------------------------------------------

	public function render_login_security() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		settings_errors( 'is_login_rename_settings' );
		$rename          = IS_Login::rename_settings();
		$throttle        = IS_Login::throttle_settings();
		$two_factor      = IS_2FA::settings();
		$password_policy = IS_Password_Policy::settings();
		$this->render_shell_open( 'login' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Login Security', 'integrity-sentinel' ); ?></h1>

			<h2><?php esc_html_e( 'Hide the login page', 'integrity-sentinel' ); ?></h2>
			<div class="notice notice-warning inline">
				<p>
					<?php esc_html_e( 'This is the riskiest setting in this plugin: getting it wrong can make wp-login.php unreachable. Safety net: define IS_SAFE_MODE as true in wp-config.php at any time to instantly restore normal wp-login.php access, no database access required.', 'integrity-sentinel' ); ?>
				</p>
			</div>
			<form method="post" action="options.php">
				<?php settings_fields( 'is_login_rename_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="is_login_slug"><?php esc_html_e( 'Custom login slug', 'integrity-sentinel' ); ?></label></th>
						<td>
							<code><?php echo esc_html( home_url( '/' ) ); ?></code>
							<input type="text" id="is_login_slug" name="is_login_rename_settings[login_slug]" value="<?php echo esc_attr( $rename['login_slug'] ); ?>" class="regular-text" placeholder="<?php esc_attr_e( 'leave blank to keep wp-login.php', 'integrity-sentinel' ); ?>">
							<p class="description"><?php esc_html_e( 'When set, both wp-login.php and wp-admin 404 for anyone not already logged in, and this becomes the real login URL.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_login_host"><?php esc_html_e( 'Admin subdomain (optional)', 'integrity-sentinel' ); ?></label></th>
						<td>
							<input type="text" id="is_login_host" name="is_login_rename_settings[login_host]" value="<?php echo esc_attr( $rename['login_host'] ); ?>" class="regular-text" placeholder="admin.example.com">
							<p class="description">
								<?php esc_html_e( 'Optional and independent of the slug above — works alone, together with a slug, or not at all. Once DNS/your web server routes this hostname to this same site, visiting its bare address opens the login form directly, and wp-login.php works normally there too (any action) — no slug in the URL needed.', 'integrity-sentinel' ); ?>
							</p>
							<?php if ( '' !== $rename['login_host'] && '' === $rename['login_slug'] ) : ?>
								<p class="description"><?php esc_html_e( 'No slug is set, so a password-reset email link (which always points at this site\'s main address, not the subdomain) still works normally — that one specific action stays reachable everywhere. Nothing else does.', 'integrity-sentinel' ); ?></p>
							<?php endif; ?>
							<?php if ( '' !== $rename['login_host'] ) : ?>
								<div class="notice notice-warning inline" style="margin:10px 0 0;">
									<p>
										<?php
										printf(
											/* translators: %s: define('COOKIE_DOMAIN', ...) snippet */
											esc_html__( 'Important: for a session started on the subdomain to also work on your main domain\'s wp-admin, add %s to wp-config.php (the leading dot covers all subdomains). Without it, logging in on the subdomain may leave you looking logged out on the main site.', 'integrity-sentinel' ),
											'<code>' . esc_html( "define('COOKIE_DOMAIN', '." . preg_replace( '/^[^.]+\./', '', $rename['login_host'] ) . "');" ) . '</code>'
										);
										?>
									</p>
								</div>
							<?php endif; ?>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save login slug', 'integrity-sentinel' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Login rate limiting', 'integrity-sentinel' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Locks an IP out of authentication after repeated failed logins. Whitelisted IPs (Access Control) always bypass this.', 'integrity-sentinel' ); ?></p>
			<form method="post" action="options.php">
				<?php settings_fields( 'is_login_throttle_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_login_throttle_settings[enabled]" value="1" <?php checked( $throttle['enabled'], 1 ); ?>>
								<?php esc_html_e( 'Lock out an IP after too many failed login attempts.', 'integrity-sentinel' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_max_attempts"><?php esc_html_e( 'Failed attempts allowed', 'integrity-sentinel' ); ?></label></th>
						<td><input type="number" min="3" max="20" id="is_max_attempts" name="is_login_throttle_settings[max_attempts]" value="<?php echo esc_attr( $throttle['max_attempts'] ); ?>" class="small-text"></td>
					</tr>
					<tr>
						<th scope="row"><label for="is_window_minutes"><?php esc_html_e( 'Within (minutes)', 'integrity-sentinel' ); ?></label></th>
						<td><input type="number" min="1" max="1440" id="is_window_minutes" name="is_login_throttle_settings[window_minutes]" value="<?php echo esc_attr( $throttle['window_minutes'] ); ?>" class="small-text"></td>
					</tr>
					<tr>
						<th scope="row"><label for="is_lockout_minutes"><?php esc_html_e( 'Lockout duration (minutes)', 'integrity-sentinel' ); ?></label></th>
						<td><input type="number" min="1" max="1440" id="is_lockout_minutes" name="is_login_throttle_settings[lockout_minutes]" value="<?php echo esc_attr( $throttle['lockout_minutes'] ); ?>" class="small-text"></td>
					</tr>
					<tr>
						<th scope="row"><label for="is_credential_stuffing_threshold"><?php esc_html_e( 'Credential stuffing threshold (distinct usernames)', 'integrity-sentinel' ); ?></label></th>
						<td>
							<input type="number" min="2" max="100" id="is_credential_stuffing_threshold" name="is_login_throttle_settings[credential_stuffing_threshold]" value="<?php echo esc_attr( $throttle['credential_stuffing_threshold'] ); ?>" class="small-text">
							<p class="description"><?php esc_html_e( 'If one IP tries this many different usernames within the window above, it\'s treated as credential stuffing (not just a brute force against one account) and locked out immediately.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save rate limiting settings', 'integrity-sentinel' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Password strength policy', 'integrity-sentinel' ); ?></h2>
			<p class="description"><?php esc_html_e( 'WordPress\'s own strength meter is advisory only — it shows a color and a label but still accepts a weak password. This actually blocks one, on both the "forgot password" reset flow and profile/user-edit password changes (including new users created from wp-admin).', 'integrity-sentinel' ); ?></p>
			<form method="post" action="options.php">
				<?php settings_fields( 'is_password_policy_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_password_policy_settings[enabled]" value="1" <?php checked( $password_policy['enabled'], 1 ); ?>>
								<?php esc_html_e( 'Reject a new password that doesn\'t meet the rules below.', 'integrity-sentinel' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_pw_min_length"><?php esc_html_e( 'Minimum length', 'integrity-sentinel' ); ?></label></th>
						<td><input type="number" min="4" max="64" id="is_pw_min_length" name="is_password_policy_settings[min_length]" value="<?php echo esc_attr( $password_policy['min_length'] ); ?>" class="small-text"></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Character requirements', 'integrity-sentinel' ); ?></th>
						<td>
							<label style="display:block;">
								<input type="checkbox" name="is_password_policy_settings[require_mixed_case]" value="1" <?php checked( $password_policy['require_mixed_case'], 1 ); ?>>
								<?php esc_html_e( 'Require both uppercase and lowercase letters.', 'integrity-sentinel' ); ?>
							</label>
							<label style="display:block;">
								<input type="checkbox" name="is_password_policy_settings[require_number]" value="1" <?php checked( $password_policy['require_number'], 1 ); ?>>
								<?php esc_html_e( 'Require at least one number.', 'integrity-sentinel' ); ?>
							</label>
							<label style="display:block;">
								<input type="checkbox" name="is_password_policy_settings[require_symbol]" value="1" <?php checked( $password_policy['require_symbol'], 1 ); ?>>
								<?php esc_html_e( 'Require at least one symbol (e.g. !@#$%).', 'integrity-sentinel' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'A short list of extremely common passwords (password1, welcome1, ...) is always rejected once enabled, regardless of these rules.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save password policy', 'integrity-sentinel' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Two-factor authentication', 'integrity-sentinel' ); ?></h2>
			<p class="description">
				<?php
				printf(
					/* translators: %s: URL to the user's own profile page */
					wp_kses(
						__( 'Every user sets up their own two-factor authentication from <a href="%s">their profile page</a> — it cannot be set up on someone else\'s behalf. The setting below only controls whether it\'s required.', 'integrity-sentinel' ),
						array( 'a' => array( 'href' => array() ) )
					),
					esc_url( admin_url( 'profile.php#is-2fa' ) )
				);
				?>
			</p>
			<form method="post" action="options.php">
				<?php settings_fields( 'is_2fa_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Require for roles', 'integrity-sentinel' ); ?></th>
						<td>
							<?php foreach ( wp_roles()->get_names() as $role_slug => $role_label ) : ?>
								<label style="display:block;">
									<input type="checkbox" name="is_2fa_settings[enforced_roles][]" value="<?php echo esc_attr( $role_slug ); ?>" <?php checked( in_array( $role_slug, $two_factor['enforced_roles'], true ) ); ?>>
									<?php echo esc_html( translate_user_role( $role_label ) ); ?>
								</label>
							<?php endforeach; ?>
							<p class="description"><?php esc_html_e( 'Enforcement never blocks login: a user in a required role who hasn\'t set it up yet is redirected to their profile to set it up, rather than locked out.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save two-factor authentication settings', 'integrity-sentinel' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Your active sessions', 'integrity-sentinel' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Every device currently signed in as you. If you don\'t recognize one, revoke it and change your password.', 'integrity-sentinel' ); ?></p>
			<?php $this->render_sessions_table( get_current_user_id() ); ?>
			<?php if ( count( IS_Sessions::sessions_for( get_current_user_id() ) ) > 1 ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:10px;">
					<input type="hidden" name="action" value="is_revoke_other_sessions">
					<?php wp_nonce_field( 'is_revoke_other_sessions' ); ?>
					<button type="submit" class="button"><?php esc_html_e( 'Log out everywhere else', 'integrity-sentinel' ); ?></button>
				</form>
			<?php endif; ?>

			<form method="post" action="options.php" style="margin-top:20px;">
				<?php settings_fields( 'is_session_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'New-IP alerts', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_session_settings[alert_on_new_ip]" value="1" <?php checked( IS_Sessions::settings()['alert_on_new_ip'], 1 ); ?>>
								<?php esc_html_e( 'Email/webhook alert the first time an account logs in from an IP it hasn\'t used before.', 'integrity-sentinel' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'A signal, not a block — travel and new devices are normal and still get in; you just get notified.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save session settings', 'integrity-sentinel' ) ); ?>
			</form>
		</div>
		<?php
		$this->render_shell_close();
	}

	/** Renders the active-sessions table for one user (used on the Login Security page for the current admin). */
	private function render_sessions_table( $user_id ) {
		$sessions = IS_Sessions::sessions_for( $user_id );
		if ( ! $sessions ) {
			echo '<p class="description">' . esc_html__( 'No active sessions found.', 'integrity-sentinel' ) . '</p>';
			return;
		}
		?>
		<table class="widefat striped" style="max-width:800px;">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Device', 'integrity-sentinel' ); ?></th>
					<th><?php esc_html_e( 'IP address', 'integrity-sentinel' ); ?></th>
					<th><?php esc_html_e( 'Signed in', 'integrity-sentinel' ); ?></th>
					<th><?php esc_html_e( 'Expires', 'integrity-sentinel' ); ?></th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $sessions as $token => $session ) : ?>
					<tr>
						<td>
							<?php echo esc_html( IS_Sessions::describe_user_agent( $session['ua'] ?? '' ) ); ?>
							<?php if ( ! empty( $session['is_current'] ) ) : ?>
								<span class="is-badge is-badge-info"><?php esc_html_e( 'This device', 'integrity-sentinel' ); ?></span>
							<?php endif; ?>
						</td>
						<td><?php echo esc_html( $session['ip'] ?? '—' ); ?></td>
						<td><?php echo esc_html( ! empty( $session['login'] ) ? human_time_diff( $session['login'] ) . ' ' . __( 'ago', 'integrity-sentinel' ) : '—' ); ?></td>
						<td><?php echo esc_html( ! empty( $session['expiration'] ) ? human_time_diff( time(), $session['expiration'] ) : '—' ); ?></td>
						<td>
							<?php if ( empty( $session['is_current'] ) ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<input type="hidden" name="action" value="is_revoke_session">
									<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>">
									<?php wp_nonce_field( 'is_revoke_session' ); ?>
									<button type="submit" class="button-link"><?php esc_html_e( 'Revoke', 'integrity-sentinel' ); ?></button>
								</form>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	// -----------------------------------------------------------------
	// Login Design
	// -----------------------------------------------------------------

	public function render_login_design() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		settings_errors( 'is_login_design_settings' );
		$design    = IS_Login_Design::settings();
		$templates = IS_Login_Design::templates();
		$this->render_shell_open( 'login-design' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Login Design', 'integrity-sentinel' ); ?></h1>
			<p class="description"><?php esc_html_e( 'Replace the stock sign-in screen with one of the built-in templates, tweak it below, or drop in your own CSS/HTML. Nothing here mentions your CMS by name — the goal is a sign-in page that looks like part of your product, not a default install.', 'integrity-sentinel' ); ?></p>

			<div class="is-login-design-layout">
				<form method="post" action="options.php" class="is-login-design-form" id="is-login-design-form">
					<?php settings_fields( 'is_login_design_settings_group' ); ?>

					<h2><?php esc_html_e( 'Template', 'integrity-sentinel' ); ?></h2>
					<div class="is-template-grid" id="is-template-grid">
						<?php foreach ( $templates as $key => $label ) : ?>
							<label class="is-template-card is-tpl-<?php echo esc_attr( $key ); ?><?php echo $design['template'] === $key ? ' is-selected' : ''; ?>">
								<input type="radio" name="is_login_design_settings[template]" value="<?php echo esc_attr( $key ); ?>" data-template="<?php echo esc_attr( $key ); ?>" <?php checked( $design['template'], $key ); ?>>
								<span class="is-template-swatch" aria-hidden="true">
									<span class="is-template-swatch-hero"></span>
									<span class="is-template-swatch-card"></span>
								</span>
								<span class="is-template-label"><?php echo esc_html( $label ); ?></span>
							</label>
						<?php endforeach; ?>
					</div>
					<p class="description"><?php esc_html_e( '"Minimal" is a plain centered card. Every other template adds a decorative image panel down one side — heading, subheading, artwork, and which side it goes on are all yours to set below.', 'integrity-sentinel' ); ?></p>

					<h2><?php esc_html_e( 'Hero panel', 'integrity-sentinel' ); ?></h2>
					<table class="form-table" role="presentation" id="is-hero-fields">
						<tr>
							<th scope="row"><?php esc_html_e( 'Placement', 'integrity-sentinel' ); ?></th>
							<td>
								<label style="margin-right:16px;"><input type="radio" name="is_login_design_settings[hero_position]" value="left" id="is-hero-position-left" <?php checked( $design['hero_position'], 'left' ); ?>> <?php esc_html_e( 'Left', 'integrity-sentinel' ); ?></label>
								<label style="margin-right:16px;"><input type="radio" name="is_login_design_settings[hero_position]" value="right" id="is-hero-position-right" <?php checked( $design['hero_position'], 'right' ); ?>> <?php esc_html_e( 'Right', 'integrity-sentinel' ); ?></label>
								<label><input type="radio" name="is_login_design_settings[hero_position]" value="center" id="is-hero-position-center" <?php checked( $design['hero_position'], 'center' ); ?>> <?php esc_html_e( 'Center', 'integrity-sentinel' ); ?></label>
								<p class="description"><?php esc_html_e( 'Left / Right split the screen — artwork one side, form the other. Center floats the form as a frosted-glass card over a full-screen backdrop (the gradient, your photo, or the live carousel).', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="is-hero-heading"><?php esc_html_e( 'Heading', 'integrity-sentinel' ); ?></label></th>
							<td><input type="text" id="is-hero-heading" name="is_login_design_settings[hero_heading]" value="<?php echo esc_attr( $design['hero_heading'] ); ?>" class="regular-text" placeholder="Welcome back"></td>
						</tr>
						<tr>
							<th scope="row"><label for="is-hero-subheading"><?php esc_html_e( 'Subheading', 'integrity-sentinel' ); ?></label></th>
							<td><input type="text" id="is-hero-subheading" name="is_login_design_settings[hero_subheading]" value="<?php echo esc_attr( $design['hero_subheading'] ); ?>" class="regular-text" placeholder="<?php esc_attr_e( 'e.g. Everything you need, in one place.', 'integrity-sentinel' ); ?>"></td>
						</tr>
						<tr>
							<th scope="row"><label for="is-hero-image-url"><?php esc_html_e( 'Illustration / photo', 'integrity-sentinel' ); ?></label></th>
							<td>
								<div class="is-logo-picker">
									<img id="is-hero-image-preview" src="<?php echo esc_url( $design['hero_image_url'] ); ?>" alt="" style="<?php echo '' === $design['hero_image_url'] ? 'display:none;' : ''; ?>">
									<input type="url" id="is-hero-image-url" name="is_login_design_settings[hero_image_url]" value="<?php echo esc_attr( $design['hero_image_url'] ); ?>" class="regular-text" placeholder="https://example.com/illustration.jpg">
									<button type="button" class="button" id="is-hero-image-pick"><?php esc_html_e( 'Choose from Media Library', 'integrity-sentinel' ); ?></button>
									<button type="button" class="button-link" id="is-hero-image-clear" style="<?php echo '' === $design['hero_image_url'] ? 'display:none;' : ''; ?>"><?php esc_html_e( 'Remove', 'integrity-sentinel' ); ?></button>
								</div>
								<p class="description"><?php esc_html_e( 'Optional. Without one, a soft generated pattern is used instead — pick your own photo or illustration for something more "you".', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
						<tr id="is-carousel-gallery-row" style="<?php echo 'carousel' === $design['template'] ? '' : 'display:none;'; ?>">
							<th scope="row"><label for="is-hero-gallery"><?php esc_html_e( 'Carousel images', 'integrity-sentinel' ); ?></label></th>
							<td>
								<div class="is-gallery-picker" id="is-gallery-picker">
									<div class="is-gallery-thumbs" id="is-gallery-thumbs" aria-live="polite"></div>
									<button type="button" class="button" id="is-gallery-add"><?php esc_html_e( 'Add images from Media Library', 'integrity-sentinel' ); ?></button>
								</div>
								<details class="is-gallery-advanced">
									<summary><?php esc_html_e( 'Edit image URLs manually', 'integrity-sentinel' ); ?></summary>
									<textarea id="is-hero-gallery" name="is_login_design_settings[hero_gallery]" rows="4" class="large-text code" placeholder="https://example.com/photo-1.jpg&#10;https://example.com/photo-2.jpg&#10;https://example.com/photo-3.jpg"><?php echo esc_textarea( implode( "\n", $design['hero_gallery'] ) ); ?></textarea>
								</details>
								<p class="description"><?php esc_html_e( 'Only used by the "Carousel" template — pick up to 8 images from your library (or paste URLs manually above). Two or more images enables navigation; one behaves like a static image; none falls back to a generated pattern.', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
						<tr id="is-carousel-indicator-row" style="<?php echo 'carousel' === $design['template'] ? '' : 'display:none;'; ?>">
							<th scope="row"><label for="is-carousel-indicator"><?php esc_html_e( 'Slide indicators', 'integrity-sentinel' ); ?></label></th>
							<td>
								<select id="is-carousel-indicator" name="is_login_design_settings[carousel_indicator]">
									<?php foreach ( IS_Login_Design::carousel_indicators() as $ind_key => $ind_label ) : ?>
										<option value="<?php echo esc_attr( $ind_key ); ?>" <?php selected( IS_Login_Design::carousel_indicator( $design ), $ind_key ); ?>><?php echo esc_html( $ind_label ); ?></option>
									<?php endforeach; ?>
								</select>
								<p class="description"><?php esc_html_e( 'How the slide navigation looks: slim bars, round dots, a numeric counter, image thumbnails, or arrows only.', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
					</table>

					<h2><?php esc_html_e( 'Customize', 'integrity-sentinel' ); ?></h2>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><?php esc_html_e( 'WordPress branding', 'integrity-sentinel' ); ?></th>
							<td>
								<label>
									<input type="checkbox" id="is-hide-branding" name="is_login_design_settings[hide_branding]" value="1" <?php checked( ! empty( $design['hide_branding'] ) ); ?>>
									<?php esc_html_e( 'Hide it — use my site name/homepage instead of the default WordPress logo, link, and page title.', 'integrity-sentinel' ); ?>
								</label>
								<p class="description"><?php esc_html_e( 'On by default. Turn off to restore the stock WordPress logo and title.', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="is-login-color"><?php esc_html_e( 'Accent color', 'integrity-sentinel' ); ?></label></th>
							<td>
								<input type="color" id="is-login-color" name="is_login_design_settings[primary_color]" value="<?php echo esc_attr( $design['primary_color'] ); ?>">
								<p class="description"><?php esc_html_e( 'Tints the hero artwork and drives the submit button, focus rings, and links across every template.', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="is-login-radius"><?php esc_html_e( 'Corner roundness', 'integrity-sentinel' ); ?></label></th>
							<td>
								<input type="range" id="is-login-radius" name="is_login_design_settings[border_radius]" min="0" max="40" step="1" value="<?php echo esc_attr( $design['border_radius'] ); ?>">
								<output id="is-login-radius-value" for="is-login-radius"><?php echo esc_html( $design['border_radius'] ); ?>px</output>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="is-login-logo-url"><?php esc_html_e( 'Logo', 'integrity-sentinel' ); ?></label></th>
							<td>
								<div class="is-logo-picker">
									<img id="is-login-logo-preview" src="<?php echo esc_url( $design['logo_url'] ); ?>" alt="" style="<?php echo '' === $design['logo_url'] ? 'display:none;' : ''; ?>">
									<input type="url" id="is-login-logo-url" name="is_login_design_settings[logo_url]" value="<?php echo esc_attr( $design['logo_url'] ); ?>" class="regular-text" placeholder="https://example.com/logo.png">
									<button type="button" class="button" id="is-login-logo-pick"><?php esc_html_e( 'Choose from Media Library', 'integrity-sentinel' ); ?></button>
									<button type="button" class="button-link" id="is-login-logo-clear" style="<?php echo '' === $design['logo_url'] ? 'display:none;' : ''; ?>"><?php esc_html_e( 'Remove', 'integrity-sentinel' ); ?></button>
								</div>
								<p class="description"><?php esc_html_e( 'Shown as text (your site name) until you set one, while branding is hidden above.', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="is-login-custom-html"><?php esc_html_e( 'Custom HTML banner', 'integrity-sentinel' ); ?></label></th>
							<td>
								<textarea id="is-login-custom-html" name="is_login_design_settings[custom_html]" rows="3" class="large-text code" placeholder="<?php esc_attr_e( 'e.g. <p>Staff portal — authorized access only.</p>', 'integrity-sentinel' ); ?>"><?php echo esc_textarea( $design['custom_html'] ); ?></textarea>
								<p class="description"><?php esc_html_e( 'A small notice shown above the form. Filtered through the same rules as post content (wp_kses_post) — scripts and unsafe markup are stripped.', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="is-login-custom-css"><?php esc_html_e( 'Custom CSS', 'integrity-sentinel' ); ?></label></th>
							<td>
								<textarea id="is-login-custom-css" name="is_login_design_settings[custom_css]" rows="8" class="large-text code" placeholder=".login form { }"><?php echo esc_textarea( $design['custom_css'] ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Applied last, after everything above, so it can override anything on the page — full freedom if the customizer fields aren\'t enough.', 'integrity-sentinel' ); ?></p>
							</td>
						</tr>
					</table>
					<p class="submit" style="display:flex;gap:10px;align-items:center;">
						<?php submit_button( __( 'Save login design', 'integrity-sentinel' ), 'primary', 'submit', false ); ?>
						<button type="button" class="button" id="is-login-preview-btn"><?php esc_html_e( 'Open real preview ↗', 'integrity-sentinel' ); ?></button>
						<span id="is-login-preview-status" class="description"></span>
					</p>
				</form>

				<div class="is-login-preview-pane">
					<h2><?php esc_html_e( 'Instant preview', 'integrity-sentinel' ); ?></h2>
					<p class="description"><?php esc_html_e( 'Updates as you type — a stand-in, not the real page. Use "Open real preview" above to see it rendered for real, unsaved.', 'integrity-sentinel' ); ?></p>
					<div class="is-login-preview" id="is-login-preview" data-template="<?php echo esc_attr( $design['template'] ); ?>" data-position="<?php echo esc_attr( $design['hero_position'] ); ?>" style="--is-login-color:<?php echo esc_attr( $design['primary_color'] ); ?>;--is-login-radius:<?php echo esc_attr( (int) $design['border_radius'] ); ?>px;">
						<div class="is-login-preview-hero" id="is-login-preview-hero">
							<span class="is-login-preview-blob is-login-preview-blob-1"></span>
							<span class="is-login-preview-blob is-login-preview-blob-2"></span>
							<div class="is-login-preview-hero-copy">
								<strong id="is-login-preview-heading"><?php echo esc_html( $design['hero_heading'] ); ?></strong>
								<span id="is-login-preview-subheading"><?php echo esc_html( $design['hero_subheading'] ); ?></span>
							</div>
						</div>
						<div class="is-login-preview-card">
							<div class="is-login-preview-logo" id="is-login-preview-logo"><?php echo esc_html( get_bloginfo( 'name' ) ? get_bloginfo( 'name' ) : __( 'Your Site', 'integrity-sentinel' ) ); ?></div>
							<div class="is-login-preview-field"></div>
							<div class="is-login-preview-field"></div>
							<div class="is-login-preview-button"><?php esc_html_e( 'Log In', 'integrity-sentinel' ); ?></div>
						</div>
					</div>
				</div>
			</div>
		</div>
		<?php
		$this->render_shell_close();
	}

	// -----------------------------------------------------------------
	// REST API
	// -----------------------------------------------------------------

	public function render_rest_api() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$api      = IS_Rest_API::settings();
		$posts    = IS_Rest_Posts::settings();
		$endpoint = rest_url( 'integrity-sentinel/v1/posts' );
		$this->render_shell_open( 'rest' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'REST API', 'integrity-sentinel' ); ?></h1>

			<h2><?php esc_html_e( 'Restriction', 'integrity-sentinel' ); ?></h2>
			<form method="post" action="options.php">
				<?php settings_fields( 'is_rest_api_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Block user enumeration', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_rest_api_settings[block_user_enumeration]" value="1" <?php checked( $api['block_user_enumeration'], 1 ); ?>>
								<?php esc_html_e( 'Block unauthenticated access to /wp/v2/users and the old ?author=N enumeration redirect (safe for any site).', 'integrity-sentinel' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Restrict unauthenticated REST access', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_rest_api_settings[restrict_unauthenticated]" value="1" <?php checked( $api['restrict_unauthenticated'], 1 ); ?>>
								<?php esc_html_e( 'Require authentication for every REST route except the ones listed below.', 'integrity-sentinel' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'Only enable this if you understand what depends on public REST access — many themes/plugins (search, forms, block-editor previews, WooCommerce\'s store API) use public REST routes and will break without being allowlisted below.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_rest_allowed_routes"><?php esc_html_e( 'Allowed route prefixes', 'integrity-sentinel' ); ?></label></th>
						<td>
							<textarea id="is_rest_allowed_routes" name="is_rest_api_settings[allowed_routes]" rows="4" class="large-text code"><?php echo esc_textarea( $api['allowed_routes'] ); ?></textarea>
							<p class="description"><?php esc_html_e( 'One route prefix per line (e.g. wp/v2/oembed). Only used when restriction above is enabled. This plugin\'s own endpoint below is always allowed — it enforces its own authentication.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>

				<h3><?php esc_html_e( 'Rate limiting & abuse detection', 'integrity-sentinel' ); ?></h3>
				<p class="description"><?php esc_html_e( 'Applies to every REST API route, not just this plugin\'s own endpoints. Whitelisted IPs (Access Control) always bypass these.', 'integrity-sentinel' ); ?></p>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="is_rest_rate_limit"><?php esc_html_e( 'Rate limit (requests per 5 minutes, per IP)', 'integrity-sentinel' ); ?></label></th>
						<td>
							<input type="number" min="0" max="10000" id="is_rest_rate_limit" name="is_rest_api_settings[rate_limit]" value="<?php echo esc_attr( $api['rate_limit'] ); ?>" class="small-text">
							<p class="description"><?php esc_html_e( '0 disables rate limiting entirely.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Enumeration detection', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_rest_api_settings[enumeration_detection]" value="1" <?php checked( $api['enumeration_detection'], 1 ); ?>>
								<?php esc_html_e( 'Log a detection when one IP requests many sequential numeric-ID objects (e.g. /wp/v2/posts/1, /2, /3, …) — a common scanner pattern.', 'integrity-sentinel' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_rest_enumeration_threshold"><?php esc_html_e( 'Enumeration threshold (per 5 minutes, per IP)', 'integrity-sentinel' ); ?></label></th>
						<td><input type="number" min="5" max="1000" id="is_rest_enumeration_threshold" name="is_rest_api_settings[enumeration_threshold]" value="<?php echo esc_attr( $api['enumeration_threshold'] ); ?>" class="small-text"></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Block on enumeration', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_rest_api_settings[block_on_enumeration]" value="1" <?php checked( $api['block_on_enumeration'], 1 ); ?>>
								<?php esc_html_e( 'Also reject requests once the threshold is crossed, instead of only logging. Off by default — a very active legitimate integration could plausibly trip this.', 'integrity-sentinel' ); ?>
							</label>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save REST restriction settings', 'integrity-sentinel' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Blog post publishing endpoint', 'integrity-sentinel' ); ?></h2>
			<p class="description">
				<?php esc_html_e( 'A dedicated endpoint for creating posts from an external tool, authenticated with WordPress\'s own Application Passwords — no separate secret store. Create one for a dedicated user (Author or Editor, not Administrator) under Users → Profile → Application Passwords, then send HTTP Basic auth with that username and application password.', 'integrity-sentinel' ); ?>
			</p>
			<p><strong><?php esc_html_e( 'Endpoint:', 'integrity-sentinel' ); ?></strong> <code>POST <?php echo esc_html( $endpoint ); ?></code></p>
			<p class="description"><?php esc_html_e( 'Body (JSON): title (required), content (required), status (draft/pending/publish/private — publish/private require the publish_posts capability, otherwise it lands as pending), excerpt, categories (array of IDs), tags (array of names).', 'integrity-sentinel' ); ?></p>

			<form method="post" action="options.php">
				<?php settings_fields( 'is_rest_posts_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enabled', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_rest_posts_settings[enabled]" value="1" <?php checked( $posts['enabled'], 1 ); ?>>
								<?php esc_html_e( 'Register this endpoint.', 'integrity-sentinel' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_rest_posts_rate_limit"><?php esc_html_e( 'Rate limit (requests/hour per user)', 'integrity-sentinel' ); ?></label></th>
						<td><input type="number" min="1" max="1000" id="is_rest_posts_rate_limit" name="is_rest_posts_settings[rate_limit]" value="<?php echo esc_attr( $posts['rate_limit'] ); ?>" class="small-text"></td>
					</tr>
				</table>
				<?php submit_button( __( 'Save endpoint settings', 'integrity-sentinel' ) ); ?>
			</form>
		</div>
		<?php
		$this->render_shell_close();
	}

	// -----------------------------------------------------------------
	// Audit log
	// -----------------------------------------------------------------

	public function render_audit_log() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$per_page    = 50;
		$paged       = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only pagination
		$entries     = IS_Audit_Log::entries( $per_page, ( $paged - 1 ) * $per_page );
		$total       = IS_Audit_Log::count();
		$pages       = max( 1, (int) ceil( $total / $per_page ) );
		$error       = isset( $_GET['is_error'] ) ? sanitize_text_field( rawurldecode( wp_unslash( $_GET['is_error'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only message set by our own redirect
		$ti_result   = isset( $_GET['is_ti_result'] ) ? sanitize_text_field( rawurldecode( wp_unslash( $_GET['is_ti_result'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only message set by our own redirect
		$ti_settings = IS_Threat_Intel::settings();
		$ti_ready    = ! empty( $ti_settings['enabled'] ) && '' !== trim( (string) $ti_settings['abuseipdb_key'] );
		$this->render_shell_open( 'audit' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Audit Log', 'integrity-sentinel' ); ?></h1>
			<?php if ( $error ) : ?>
				<div class="notice notice-error"><p><?php echo esc_html( $error ); ?></p></div>
			<?php endif; ?>
			<?php if ( $ti_result ) : ?>
				<div class="notice notice-info"><p><?php echo esc_html( $ti_result ); ?></p></div>
			<?php endif; ?>
			<p class="description">
				<?php esc_html_e( 'Append-only record of every security-relevant action: scans, finding status changes, settings changes, hardening actions, deactivations. Nothing done through WordPress can act on this plugin without leaving a row here.', 'integrity-sentinel' ); ?>
			</p>

			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'When', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'User', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'IP', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Action', 'integrity-sentinel' ); ?></th>
						<th><?php esc_html_e( 'Detail', 'integrity-sentinel' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $entries ) ) : ?>
						<tr><td colspan="5"><?php esc_html_e( 'No entries yet.', 'integrity-sentinel' ); ?></td></tr>
					<?php endif; ?>
					<?php foreach ( $entries as $entry ) : ?>
						<tr>
							<td><?php echo esc_html( $entry['created_at'] ); ?></td>
							<td><?php echo esc_html( $entry['user_login'] ); ?></td>
							<td>
								<?php echo esc_html( $entry['ip'] ); ?>
								<?php if ( $ti_ready && $entry['ip'] ) : ?>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
										<?php wp_nonce_field( 'is_threat_intel_action' ); ?>
										<input type="hidden" name="action" value="is_check_ip_reputation">
										<input type="hidden" name="ip" value="<?php echo esc_attr( $entry['ip'] ); ?>">
										<button type="submit" class="button-link"><?php esc_html_e( 'Check reputation', 'integrity-sentinel' ); ?></button>
									</form>
								<?php endif; ?>
							</td>
							<td><code><?php echo esc_html( $entry['action'] ); ?></code></td>
							<td><code><?php echo esc_html( (string) $entry['detail'] ); ?></code></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $pages > 1 ) : ?>
				<div class="tablenav"><div class="tablenav-pages">
					<?php
					for ( $p = 1; $p <= $pages; $p++ ) {
						$url = add_query_arg(
							array(
								'page'  => 'integrity-sentinel-audit',
								'paged' => $p,
							),
							admin_url( 'admin.php' )
						);
						printf( '<a class="%s" href="%s">%d</a> ', $p === $paged ? 'current' : '', esc_url( $url ), (int) $p ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					}
					?>
				</div></div>
			<?php endif; ?>
		</div>
		<?php
		$this->render_shell_close();
	}

	// -----------------------------------------------------------------
	// Settings
	// -----------------------------------------------------------------

	public function render_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings        = wp_parse_args(
			get_option( 'is_scan_settings', array() ),
			array(
				'batch_size'           => 40,
				'alert_email'          => get_option( 'admin_email' ),
				'alert_on_severity'    => 'high',
				'scan_uploads_for_php' => 1,
				'max_file_size_kb'     => 2048,
				'excluded_paths'       => '',
				'webhook_url'          => '',
				'deadman_days'         => 2,
				'scan_frequency'       => 'daily',
			)
		);
		$avg_ms_per_file = IS_Scanner::average_ms_per_file();
		$this->render_shell_open( 'settings' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Integrity Sentinel Settings', 'integrity-sentinel' ); ?></h1>
			<form method="post" action="options.php">
				<?php settings_fields( 'is_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="is_scan_frequency"><?php esc_html_e( 'Automatic scan frequency', 'integrity-sentinel' ); ?></label></th>
						<td>
							<select id="is_scan_frequency" name="is_scan_settings[scan_frequency]">
								<?php foreach ( IS_Cron::VALID_FREQUENCIES as $frequency ) : ?>
									<option value="<?php echo esc_attr( $frequency ); ?>" <?php selected( $settings['scan_frequency'], $frequency ); ?>><?php echo esc_html( ucfirst( $frequency ) ); ?></option>
								<?php endforeach; ?>
							</select>
							<?php $next = wp_next_scheduled( IS_CRON_DAILY_SCAN ); ?>
							<p class="description">
								<?php
								if ( $next ) {
									printf(
										/* translators: %s: human-readable time until the next scheduled scan */
										esc_html__( 'Next scheduled scan: in %s.', 'integrity-sentinel' ),
										esc_html( human_time_diff( $next ) )
									);
								} else {
									esc_html_e( 'No scan is currently scheduled — save this page to schedule one.', 'integrity-sentinel' );
								}
								?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_batch_size"><?php esc_html_e( 'Files per batch', 'integrity-sentinel' ); ?></label></th>
						<td>
							<input type="number" min="5" max="200" id="is_batch_size" name="is_scan_settings[batch_size]" value="<?php echo esc_attr( $settings['batch_size'] ); ?>" class="small-text">
							<p class="description"><?php esc_html_e( 'How many files to process per AJAX request during a live scan. Lower this if your host times out on the default.', 'integrity-sentinel' ); ?></p>
							<?php if ( null !== $avg_ms_per_file ) : ?>
								<p class="description">
									<?php
									printf(
										/* translators: 1: observed milliseconds per file, 2: estimated seconds for the current batch size */
										esc_html__( 'Observed pace on this site: ~%1$s ms/file — your current batch size takes roughly ~%2$s seconds. If that exceeds your host\'s PHP execution time limit, lower the batch size.', 'integrity-sentinel' ),
										esc_html( number_format_i18n( $avg_ms_per_file, 1 ) ),
										esc_html( number_format_i18n( ( $avg_ms_per_file * (int) $settings['batch_size'] ) / 1000, 1 ) )
									);
									?>
								</p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_alert_email"><?php esc_html_e( 'Alert email', 'integrity-sentinel' ); ?></label></th>
						<td><input type="email" id="is_alert_email" name="is_scan_settings[alert_email]" value="<?php echo esc_attr( $settings['alert_email'] ); ?>" class="regular-text"></td>
					</tr>
					<tr>
						<th scope="row"><label for="is_alert_on_severity"><?php esc_html_e( 'Alert on severity', 'integrity-sentinel' ); ?></label></th>
						<td>
							<select id="is_alert_on_severity" name="is_scan_settings[alert_on_severity]">
								<?php foreach ( array( 'critical', 'high', 'medium', 'low' ) as $sev ) : ?>
									<option value="<?php echo esc_attr( $sev ); ?>" <?php selected( $settings['alert_on_severity'], $sev ); ?>><?php echo esc_html( ucfirst( $sev ) ); ?> <?php esc_html_e( 'and above', 'integrity-sentinel' ); ?></option>
								<?php endforeach; ?>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Scan uploads for PHP', 'integrity-sentinel' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="is_scan_settings[scan_uploads_for_php]" value="1" <?php checked( $settings['scan_uploads_for_php'], 1 ); ?>>
								<?php esc_html_e( 'Flag any .php file found inside the uploads directory (recommended).', 'integrity-sentinel' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_max_file_size_kb"><?php esc_html_e( 'Max file size to pattern-scan (KB)', 'integrity-sentinel' ); ?></label></th>
						<td>
							<input type="number" min="64" id="is_max_file_size_kb" name="is_scan_settings[max_file_size_kb]" value="<?php echo esc_attr( $settings['max_file_size_kb'] ); ?>" class="small-text">
							<p class="description"><?php esc_html_e( 'Files are always hashed for checksum comparison; files larger than this are skipped for the (slower) malware-pattern scan.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_webhook_url"><?php esc_html_e( 'Alert webhook URL', 'integrity-sentinel' ); ?></label></th>
						<td>
							<input type="url" id="is_webhook_url" name="is_scan_settings[webhook_url]" value="<?php echo esc_attr( $settings['webhook_url'] ); ?>" class="regular-text" placeholder="https://">
							<p class="description"><?php esc_html_e( 'Optional. Security events are also POSTed as JSON to this URL — an off-site copy of alerts that an attacker on this server cannot delete. Works with Slack incoming webhooks and most alerting services.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_deadman_days"><?php esc_html_e( 'Alert if no scan completes for (days)', 'integrity-sentinel' ); ?></label></th>
						<td>
							<input type="number" min="1" max="30" id="is_deadman_days" name="is_scan_settings[deadman_days]" value="<?php echo esc_attr( $settings['deadman_days'] ); ?>" class="small-text">
							<p class="description"><?php esc_html_e( 'Dead-man\'s switch: if no scan has completed in this many days, an alert is sent — a scanner that has silently stopped scanning protects nothing.', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="is_excluded_paths"><?php esc_html_e( 'Excluded paths', 'integrity-sentinel' ); ?></label></th>
						<td>
							<textarea id="is_excluded_paths" name="is_scan_settings[excluded_paths]" rows="5" class="large-text code"><?php echo esc_textarea( $settings['excluded_paths'] ); ?></textarea>
							<p class="description"><?php esc_html_e( 'One glob pattern per line, relative to the WordPress root (e.g. wp-content/cache, wp-content/uploads/backup*).', 'integrity-sentinel' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button(); ?>
			</form>
		</div>
		<?php
		$this->render_shell_close();
	}
}

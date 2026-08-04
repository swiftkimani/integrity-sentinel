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
		add_action( 'admin_post_is_reset_module_health', array( $this, 'handle_reset_module_health' ) );
		add_action( 'admin_post_is_quarantine_finding', array( $this, 'handle_quarantine_finding' ) );
		add_action( 'admin_post_is_quarantine_restore', array( $this, 'handle_quarantine_restore' ) );
		add_action( 'admin_post_is_quarantine_delete', array( $this, 'handle_quarantine_delete' ) );
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

		return array(
			'template'        => $template,
			'logo_url'        => $logo,
			'primary_color'   => $color,
			'border_radius'   => IS_Login_Design::clamp_radius( isset( $input['border_radius'] ) ? $input['border_radius'] : $defaults['border_radius'] ),
			'hero_heading'    => isset( $input['hero_heading'] ) ? sanitize_text_field( $input['hero_heading'] ) : '',
			'hero_subheading' => isset( $input['hero_subheading'] ) ? sanitize_text_field( $input['hero_subheading'] ) : '',
			'hero_image_url'  => $hero_image,
			'custom_css'      => IS_Login_Design::sanitize_css_for_style_tag( isset( $input['custom_css'] ) ? (string) $input['custom_css'] : '' ),
			'custom_html'     => isset( $input['custom_html'] ) ? wp_kses_post( $input['custom_html'] ) : '',
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
			'enabled'         => empty( $input['enabled'] ) ? 0 : 1,
			'max_attempts'    => max( 3, min( 20, (int) ( $input['max_attempts'] ?? 5 ) ) ),
			'window_minutes'  => max( 1, min( 1440, (int) ( $input['window_minutes'] ?? 15 ) ) ),
			'lockout_minutes' => max( 1, min( 1440, (int) ( $input['lockout_minutes'] ?? 15 ) ) ),
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

		$findings = $db->get_findings( $args );
		$total    = $db->count_findings(
			array(
				'status'   => $args['status'],
				'severity' => $severity,
			)
		);
		$pages    = max( 1, (int) ceil( $total / $per_page ) );
		$error    = isset( $_GET['is_error'] ) ? sanitize_text_field( rawurldecode( wp_unslash( $_GET['is_error'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only message set by our own redirect
		$this->render_shell_open( 'findings' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Findings', 'integrity-sentinel' ); ?></h1>
			<?php if ( $error ) : ?>
				<div class="notice notice-error"><p><?php echo esc_html( $error ); ?></p></div>
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
			</table>
			<?php submit_button( __( 'Save HTTP hardening settings', 'integrity-sentinel' ) ); ?>
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
		$rename     = IS_Login::rename_settings();
		$throttle   = IS_Login::throttle_settings();
		$two_factor = IS_2FA::settings();
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
				</table>
				<?php submit_button( __( 'Save rate limiting settings', 'integrity-sentinel' ) ); ?>
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
		</div>
		<?php
		$this->render_shell_close();
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
					<p class="description"><?php esc_html_e( '"Minimal" is a plain centered card. The other three add a decorative image panel down one side — heading, subheading and artwork are all yours to set below.', 'integrity-sentinel' ); ?></p>

					<h2><?php esc_html_e( 'Hero panel', 'integrity-sentinel' ); ?></h2>
					<table class="form-table" role="presentation" id="is-hero-fields">
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
					</table>

					<h2><?php esc_html_e( 'Customize', 'integrity-sentinel' ); ?></h2>
					<table class="form-table" role="presentation">
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
								<p class="description"><?php esc_html_e( 'Shown as text (your site name) until you set one — there\'s no default logo mark on this page either way.', 'integrity-sentinel' ); ?></p>
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
					<div class="is-login-preview" id="is-login-preview" data-template="<?php echo esc_attr( $design['template'] ); ?>" style="--is-login-color:<?php echo esc_attr( $design['primary_color'] ); ?>;--is-login-radius:<?php echo esc_attr( (int) $design['border_radius'] ); ?>px;">
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
		$per_page = 50;
		$paged    = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only pagination
		$entries  = IS_Audit_Log::entries( $per_page, ( $paged - 1 ) * $per_page );
		$total    = IS_Audit_Log::count();
		$pages    = max( 1, (int) ceil( $total / $per_page ) );
		$this->render_shell_open( 'audit' );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Audit Log', 'integrity-sentinel' ); ?></h1>
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
							<td><?php echo esc_html( $entry['ip'] ); ?></td>
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

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
		add_action( 'admin_post_is_apply_uploads_block', array( $this, 'handle_apply_uploads_block' ) );
		add_action( 'admin_post_is_remove_uploads_block', array( $this, 'handle_remove_uploads_block' ) );
		add_action( 'admin_post_is_reset_module_health', array( $this, 'handle_reset_module_health' ) );
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
		add_submenu_page( 'integrity-sentinel', __( 'Hardening', 'integrity-sentinel' ), __( 'Hardening', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-hardening', array( $this, 'render_hardening' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Access Control', 'integrity-sentinel' ), __( 'Access Control', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-access', array( $this, 'render_access_control' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Login Security', 'integrity-sentinel' ), __( 'Login Security', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-login', array( $this, 'render_login_security' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Audit Log', 'integrity-sentinel' ), __( 'Audit Log', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-audit', array( $this, 'render_audit_log' ) );
		add_submenu_page( 'integrity-sentinel', __( 'Settings', 'integrity-sentinel' ), __( 'Settings', 'integrity-sentinel' ), 'manage_options', 'integrity-sentinel-settings', array( $this, 'render_settings' ) );
	}

	public function enqueue( $hook ) {
		if ( strpos( $hook, 'integrity-sentinel' ) === false ) {
			return;
		}
		wp_enqueue_style( 'is-admin', IS_PLUGIN_URL . 'assets/css/is-admin.css', array(), IS_VERSION );
		wp_enqueue_script( 'is-admin', IS_PLUGIN_URL . 'assets/js/is-admin.js', array(), IS_VERSION, true );
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

		$out = array( 'login_slug' => $slug );
		if ( (string) $old['login_slug'] !== (string) $out['login_slug'] ) {
			IS_Audit_Log::record( 'login_slug_changed', array( 'from' => $old['login_slug'], 'to' => $out['login_slug'] ) );
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

		$out = array();
		$out['batch_size']           = max( 5, min( 200, (int) ( $input['batch_size'] ?? 40 ) ) );
		$out['alert_email']          = is_email( $input['alert_email'] ?? '' ) ? sanitize_email( $input['alert_email'] ) : get_option( 'admin_email' );
		$out['alert_on_severity']    = in_array( $input['alert_on_severity'] ?? '', array( 'critical', 'high', 'medium', 'low' ), true ) ? $input['alert_on_severity'] : 'high';
		$out['scan_uploads_for_php'] = empty( $input['scan_uploads_for_php'] ) ? 0 : 1;
		$out['max_file_size_kb']     = max( 64, (int) ( $input['max_file_size_kb'] ?? 2048 ) );
		$out['excluded_paths']       = sanitize_textarea_field( $input['excluded_paths'] ?? '' );
		$out['webhook_url']          = esc_url_raw( $input['webhook_url'] ?? '', array( 'http', 'https' ) );
		$out['deadman_days']         = max( 1, min( 30, (int) ( $input['deadman_days'] ?? 2 ) ) );

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
		$db     = IS_DB::instance();
		$latest = $db->get_latest_run();
		$counts = $db->severity_counts( 'new' );
		$running = $db->get_running_run();
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
				<?php esc_html_e( "This is a file-integrity and pattern scanner, not a full security suite: it doesn't include a firewall, login-attack protection, or a global threat-intelligence feed. It's built to answer one question well: \"is there anything on this site that shouldn't be here?\"", 'integrity-sentinel' ); ?>
			</p>

			<?php $this->render_feature_health(); ?>
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
		$total    = $db->count_findings( array( 'status' => $args['status'], 'severity' => $severity ) );
		$pages    = max( 1, (int) ceil( $total / $per_page ) );
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Findings', 'integrity-sentinel' ); ?></h1>

			<ul class="subsubsub">
				<?php
				$statuses = array(
					'new'          => __( 'New', 'integrity-sentinel' ),
					'acknowledged' => __( 'Acknowledged', 'integrity-sentinel' ),
					'ignored'      => __( 'Ignored', 'integrity-sentinel' ),
					'resolved'     => __( 'Resolved', 'integrity-sentinel' ),
					'all'          => __( 'All', 'integrity-sentinel' ),
				);
				$links = array();
				foreach ( $statuses as $key => $label ) {
					$url    = add_query_arg( array( 'page' => 'integrity-sentinel-findings', 'status' => $key ), admin_url( 'admin.php' ) );
					$class  = ( $status === $key ) ? 'current' : '';
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
						$url = add_query_arg( array( 'page' => 'integrity-sentinel-findings', 'status' => $status, 'severity' => $severity, 'paged' => $p ), admin_url( 'admin.php' ) );
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

			<?php $this->render_http_hardening_section(); ?>

			<h2><?php esc_html_e( 'Hardening checks', 'integrity-sentinel' ); ?></h2>
			<p>
				<?php esc_html_e( 'Every scan also audits site configuration: the file editor, debug output, auth salts, world-writable paths, exposed .git/.env/debug.log files, backup archives in the webroot, administrator accounts, plugins closed on WordPress.org, and more. Results appear under Findings alongside file-integrity issues.', 'integrity-sentinel' ); ?>
			</p>
		</div>
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
		</div>
		<?php
	}

	// -----------------------------------------------------------------
	// Login security (rename + rate limiting)
	// -----------------------------------------------------------------

	public function render_login_security() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		settings_errors( 'is_login_rename_settings' );
		$rename   = IS_Login::rename_settings();
		$throttle = IS_Login::throttle_settings();
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
							<p class="description"><?php esc_html_e( 'When set, wp-login.php 404s for everyone and this becomes the real login URL. Leave blank to keep the default wp-login.php behavior unchanged.', 'integrity-sentinel' ); ?></p>
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
		</div>
		<?php
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
						$url = add_query_arg( array( 'page' => 'integrity-sentinel-audit', 'paged' => $p ), admin_url( 'admin.php' ) );
						printf( '<a class="%s" href="%s">%d</a> ', $p === $paged ? 'current' : '', esc_url( $url ), (int) $p ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					}
					?>
				</div></div>
			<?php endif; ?>
		</div>
		<?php
	}

	// -----------------------------------------------------------------
	// Settings
	// -----------------------------------------------------------------

	public function render_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings = wp_parse_args(
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
			)
		);
		?>
		<div class="wrap is-wrap">
			<h1><?php esc_html_e( 'Integrity Sentinel Settings', 'integrity-sentinel' ); ?></h1>
			<form method="post" action="options.php">
				<?php settings_fields( 'is_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="is_batch_size"><?php esc_html_e( 'Files per batch', 'integrity-sentinel' ); ?></label></th>
						<td>
							<input type="number" min="5" max="200" id="is_batch_size" name="is_scan_settings[batch_size]" value="<?php echo esc_attr( $settings['batch_size'] ); ?>" class="small-text">
							<p class="description"><?php esc_html_e( 'How many files to process per AJAX request during a live scan. Lower this if your host times out on the default.', 'integrity-sentinel' ); ?></p>
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
	}
}

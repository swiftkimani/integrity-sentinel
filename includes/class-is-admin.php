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
					'scanning'      => __( 'Scanning…', 'integrity-sentinel' ),
					'scanComplete'  => __( 'Scan complete.', 'integrity-sentinel' ),
					'scanError'     => __( 'Scan error:', 'integrity-sentinel' ),
					'confirmAction' => __( 'Are you sure?', 'integrity-sentinel' ),
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
	}

	public function sanitize_settings( $input ) {
		$out = array();
		$out['batch_size']           = max( 5, min( 200, (int) ( $input['batch_size'] ?? 40 ) ) );
		$out['alert_email']          = is_email( $input['alert_email'] ?? '' ) ? sanitize_email( $input['alert_email'] ) : get_option( 'admin_email' );
		$out['alert_on_severity']    = in_array( $input['alert_on_severity'] ?? '', array( 'critical', 'high', 'medium', 'low' ), true ) ? $input['alert_on_severity'] : 'high';
		$out['scan_uploads_for_php'] = empty( $input['scan_uploads_for_php'] ) ? 0 : 1;
		$out['max_file_size_kb']     = max( 64, (int) ( $input['max_file_size_kb'] ?? 2048 ) );
		$out['excluded_paths']       = sanitize_textarea_field( $input['excluded_paths'] ?? '' );
		return $out;
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
				<li><?php esc_html_e( 'WordPress core files against the official WordPress.org checksum API.', 'integrity-sentinel' ); ?></li>
				<li><?php esc_html_e( 'Installed WordPress.org plugin files against their published checksums.', 'integrity-sentinel' ); ?></li>
				<li><?php esc_html_e( 'Every PHP file, for common malware/webshell code patterns.', 'integrity-sentinel' ); ?></li>
				<li><?php esc_html_e( 'PHP files hiding inside the uploads directory (which should only ever contain media).', 'integrity-sentinel' ); ?></li>
			</ul>
			<p class="description">
				<?php esc_html_e( "This is a file-integrity and pattern scanner, not a full security suite: it doesn't include a firewall, login-attack protection, or a global threat-intelligence feed. It's built to answer one question well: \"is there anything on this site that shouldn't be here?\"", 'integrity-sentinel' ); ?>
			</p>
		</div>
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

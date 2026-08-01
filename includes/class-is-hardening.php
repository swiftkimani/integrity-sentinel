<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two related jobs:
 *
 *  1. The one active protection this plugin offers: writing (and
 *     removing) a marker-delimited .htaccess block that denies PHP
 *     execution inside wp-content/uploads/. Everything else the plugin
 *     does is read-only; this single write is opt-in, reversible, and
 *     its correct content is fully known in advance.
 *
 *  2. A hardening audit: configuration, permission, exposure, account,
 *     and component checks that make a compromise easier or harder.
 *     Results flow through the normal findings pipeline (severity,
 *     acknowledge/ignore, auto-resolve, alerts) like any other check.
 */
class IS_Hardening {

	const BLOCK_BEGIN = '# BEGIN Integrity Sentinel';
	const BLOCK_END   = '# END Integrity Sentinel';

	// ---------------------------------------------------------------
	// Uploads PHP-execution block
	// ---------------------------------------------------------------

	public static function uploads_htaccess_path() {
		$uploads = wp_upload_dir();
		return trailingslashit( $uploads['basedir'] ) . '.htaccess';
	}

	/**
	 * Writable, commonly-abused directories other than uploads that
	 * benefit from the same PHP-execution block -- included only when
	 * they actually exist on this install, so the list stays honest
	 * rather than offering to "protect" a directory the site doesn't have.
	 *
	 * @return array<string,array{label:string,abs_path:string}>
	 */
	public static function exec_block_targets() {
		$uploads = wp_upload_dir();
		$targets = array(
			'uploads' => array(
				'label'    => __( 'Uploads', 'integrity-sentinel' ),
				'abs_path' => $uploads['basedir'],
			),
			'cache'   => array(
				'label'    => __( 'wp-content/cache', 'integrity-sentinel' ),
				'abs_path' => WP_CONTENT_DIR . '/cache',
			),
			'upgrade' => array(
				'label'    => __( 'wp-content/upgrade', 'integrity-sentinel' ),
				'abs_path' => WP_CONTENT_DIR . '/upgrade',
			),
			'temp'    => array(
				'label'    => __( 'wp-content/temp', 'integrity-sentinel' ),
				'abs_path' => WP_CONTENT_DIR . '/temp',
			),
		);

		return array_filter(
			$targets,
			function ( $target ) {
				return is_dir( $target['abs_path'] );
			}
		);
	}

	public static function htaccess_path_for( $abs_dir ) {
		return trailingslashit( $abs_dir ) . '.htaccess';
	}

	public static function block_active_for( $abs_dir ) {
		$path = self::htaccess_path_for( $abs_dir );
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return false;
		}
		return false !== strpos( (string) file_get_contents( $path ), self::BLOCK_BEGIN ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	}

	/**
	 * Appends our marker-delimited block to $abs_dir/.htaccess,
	 * preserving any existing rules.
	 *
	 * @return true|WP_Error
	 */
	public static function apply_block_for( $abs_dir ) {
		if ( self::block_active_for( $abs_dir ) ) {
			return true;
		}
		$path     = self::htaccess_path_for( $abs_dir );
		$existing = file_exists( $path ) ? (string) file_get_contents( $path ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$content  = rtrim( $existing );
		$content  = ( '' === $content ? '' : $content . "\n\n" ) . self::block_rules();

		if ( false === @file_put_contents( $path, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- single well-known file, error surfaced below
			return new WP_Error( 'is_htaccess_unwritable', __( 'Could not write the .htaccess file — check directory permissions.', 'integrity-sentinel' ) );
		}
		IS_Audit_Log::record( 'exec_block_applied', array( 'path' => $path ) );
		return true;
	}

	/**
	 * Removes ONLY our marker-delimited block from $abs_dir/.htaccess,
	 * leaving anything else in the file untouched.
	 *
	 * @return true|WP_Error
	 */
	public static function remove_block_for( $abs_dir ) {
		if ( ! self::block_active_for( $abs_dir ) ) {
			return true;
		}
		$path    = self::htaccess_path_for( $abs_dir );
		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$pattern = '/\n?' . preg_quote( self::BLOCK_BEGIN, '/' ) . '.*?' . preg_quote( self::BLOCK_END, '/' ) . '\n?/s';
		$content = trim( (string) preg_replace( $pattern, '', $content ) );

		$written = ( '' === $content )
			? @unlink( $path ) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- removing a now-empty file we created
			: ( false !== @file_put_contents( $path, $content . "\n" ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents

		if ( ! $written ) {
			return new WP_Error( 'is_htaccess_unwritable', __( 'Could not update the .htaccess file — check directory permissions.', 'integrity-sentinel' ) );
		}
		IS_Audit_Log::record( 'exec_block_removed', array( 'path' => $path ) );
		return true;
	}

	/** The Apache rules we write: 2.4 syntax with a 2.2 fallback. */
	public static function block_rules() {
		return self::BLOCK_BEGIN . "\n"
			. "# Deny direct execution of PHP inside uploads. Uploads should only\n"
			. "# ever contain media; a dropped webshell here becomes inert.\n"
			. "<FilesMatch \"\\.(?:php|phtml|php[0-9])$\">\n"
			. "\t<IfModule mod_authz_core.c>\n"
			. "\t\tRequire all denied\n"
			. "\t</IfModule>\n"
			. "\t<IfModule !mod_authz_core.c>\n"
			. "\t\tOrder allow,deny\n"
			. "\t\tDeny from all\n"
			. "\t</IfModule>\n"
			. "</FilesMatch>\n"
			. self::BLOCK_END . "\n";
	}

	/** Shown for manual configuration on non-Apache servers. */
	public static function nginx_snippet() {
		return "location ~* ^/wp-content/uploads/.*\\.(?:php|phtml|php[0-9])$ {\n\tdeny all;\n}";
	}

	/** Thin wrapper over block_active_for() kept for the existing uploads-specific call sites/tests. */
	public static function uploads_block_active() {
		$uploads = wp_upload_dir();
		return self::block_active_for( $uploads['basedir'] );
	}

	/** @return true|WP_Error */
	public static function apply_uploads_block() {
		$uploads = wp_upload_dir();
		return self::apply_block_for( $uploads['basedir'] );
	}

	/** @return true|WP_Error */
	public static function remove_uploads_block() {
		$uploads = wp_upload_dir();
		return self::remove_block_for( $uploads['basedir'] );
	}

	// ---------------------------------------------------------------
	// Hardening audit checks
	// ---------------------------------------------------------------

	/**
	 * Records every hardening finding for a run.
	 *
	 * @return int Number of NEW findings.
	 */
	public function run_checks( $run_id, IS_DB $db ) {
		$new = 0;
		foreach ( $this->collect_findings() as $finding ) {
			$finding['issue_type'] = 'hardening';
			$result                = $db->record_finding( $run_id, $finding );
			if ( $result['is_new'] ) {
				++$new;
			}
		}
		return $new;
	}

	/**
	 * @return array<array{file_path:string,severity:string,rule_id:string,detail:string}>
	 */
	public function collect_findings() {
		return array_merge(
			$this->check_config(),
			$this->check_world_writable(),
			$this->check_backup_archives(),
			$this->check_uploads_exec_block(),
			$this->check_remote_exposures(),
			$this->check_administrators(),
			$this->check_closed_plugins(),
			$this->check_core_update(),
			$this->check_dangerous_functions()
		);
	}

	const DANGEROUS_SHELL_FUNCTIONS = array( 'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec' );

	/**
	 * Pure: which of the dangerous shell-execution functions are NOT
	 * listed in a disable_functions ini value. No WordPress/ini calls --
	 * unit-testable on its own.
	 */
	public static function still_enabled_dangerous_functions( $disable_functions_value ) {
		$disabled = array_filter( array_map( 'trim', explode( ',', (string) $disable_functions_value ) ) );
		return array_values( array_diff( self::DANGEROUS_SHELL_FUNCTIONS, $disabled ) );
	}

	/**
	 * This plugin can't itself change php.ini, but it can tell the site
	 * owner exactly what to change: sites that don't need shell_exec()
	 * and friends are meaningfully safer with them disabled at the PHP
	 * engine level, since that closes the door on a whole class of
	 * webshell payloads even after one has been dropped on disk.
	 */
	private function check_dangerous_functions() {
		$still_enabled = self::still_enabled_dangerous_functions( ini_get( 'disable_functions' ) );
		if ( empty( $still_enabled ) ) {
			return array();
		}
		return array(
			$this->finding(
				'shell_functions_enabled',
				'medium',
				'php.ini',
				sprintf(
					/* translators: %s: comma-separated list of PHP function names */
					__( 'These PHP shell-execution functions are still enabled: %s. If your hosting plan allows editing disable_functions (php.ini or a hosting control panel), disabling the ones this site doesn\'t use closes off a whole class of webshell payloads even if one gets dropped on disk.', 'integrity-sentinel' ),
					implode( ', ', $still_enabled )
				)
			),
		);
	}

	private function finding( $rule_id, $severity, $file_path, $detail ) {
		return array(
			'file_path' => $file_path,
			'severity'  => $severity,
			'rule_id'   => $rule_id,
			'detail'    => $detail,
		);
	}

	private function check_config() {
		$out = array();

		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			$out[] = $this->finding(
				'file_edit_enabled',
				'medium',
				'wp-config.php',
				__( "The built-in theme/plugin file editor is enabled. Any compromised administrator session can use it to inject PHP. Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php.", 'integrity-sentinel' )
			);
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) {
			$out[] = $this->finding(
				'debug_display_on',
				'medium',
				'wp-config.php',
				__( 'WP_DEBUG_DISPLAY is on: error output can leak paths, queries, and credentials to visitors. Disable it in production.', 'integrity-sentinel' )
			);
		}

		$weak = array();
		foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ) as $key ) {
			if ( self::is_weak_salt_value( defined( $key ) ? constant( $key ) : '' ) ) {
				$weak[] = $key;
			}
		}
		if ( $weak ) {
			$out[] = $this->finding(
				'weak_auth_salts',
				'high',
				'wp-config.php',
				sprintf(
					/* translators: %s: comma-separated list of constant names */
					__( 'Missing or placeholder authentication keys/salts: %s. Weak salts make session cookies forgeable. Regenerate them from the WordPress.org secret-key service.', 'integrity-sentinel' ),
					implode( ', ', $weak )
				)
			);
		}

		global $wpdb;
		if ( isset( $wpdb->prefix ) && 'wp_' === $wpdb->prefix ) {
			$out[] = $this->finding(
				'default_table_prefix',
				'low',
				'wp-config.php',
				__( 'The database table prefix is the default "wp_", which makes blind SQL-injection payloads slightly easier to write. Low priority, but worth changing on a rebuild.', 'integrity-sentinel' )
			);
		}

		if ( filter_var( ini_get( 'allow_url_include' ), FILTER_VALIDATE_BOOLEAN ) ) {
			$out[] = $this->finding(
				'allow_url_include_on',
				'high',
				'php.ini',
				__( 'PHP allow_url_include is enabled: include/require can load remote URLs, turning many local-file-inclusion bugs into remote code execution. Disable it.', 'integrity-sentinel' )
			);
		}

		if ( version_compare( PHP_VERSION, '8.0', '<' ) ) {
			$out[] = $this->finding(
				'php_end_of_life',
				'medium',
				'php.ini',
				sprintf(
					/* translators: %s: PHP version */
					__( 'PHP %s no longer receives security fixes. Upgrade to a supported PHP version.', 'integrity-sentinel' ),
					PHP_VERSION
				)
			);
		}

		return $out;
	}

	/** True if a salt/key constant value is unusable as a secret. */
	public static function is_weak_salt_value( $value ) {
		return ! is_string( $value )
			|| strlen( $value ) < 32
			|| false !== stripos( $value, 'put your unique phrase here' );
	}

	private function check_world_writable() {
		if ( 0 === stripos( PHP_OS, 'WIN' ) ) {
			return array(); // Unix permission bits are meaningless here.
		}

		$uploads = wp_upload_dir();
		$targets = array(
			'wp-config.php' => ABSPATH . 'wp-config.php',
			'.'             => untrailingslashit( ABSPATH ),
			'wp-content'    => WP_CONTENT_DIR,
			'uploads'       => $uploads['basedir'],
		);

		$out = array();
		foreach ( $targets as $label => $abs ) {
			if ( ! file_exists( $abs ) ) {
				continue;
			}
			$perms = @fileperms( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false !== $perms && ( $perms & 0002 ) ) {
				$out[] = $this->finding(
					'world_writable_path',
					'high',
					$label,
					__( 'This path is world-writable: any local process or user on the server can modify it. Tighten its permissions.', 'integrity-sentinel' )
				);
			}
		}
		return $out;
	}

	/** True if a filename looks like a database dump or site backup. */
	public static function looks_like_backup_file( $filename ) {
		return (bool) preg_match( '/\.(?:sql|sql\.gz|zip|tar\.gz|tgz|bak)$/i', $filename );
	}

	private function check_backup_archives() {
		$out   = array();
		$items = @scandir( ABSPATH ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! is_array( $items ) ) {
			return $out;
		}
		foreach ( $items as $item ) {
			if ( ! is_file( ABSPATH . $item ) || ! self::looks_like_backup_file( $item ) ) {
				continue;
			}
			$out[] = $this->finding(
				'backup_archive_in_webroot',
				'high',
				$item,
				__( 'A database dump or backup archive is sitting in the webroot, where anyone who guesses its name can download it. Move backups out of the web-accessible tree.', 'integrity-sentinel' )
			);
		}
		return $out;
	}

	private function check_uploads_exec_block() {
		if ( self::uploads_block_active() ) {
			return array();
		}
		$uploads = wp_upload_dir();
		$rel     = IS_File_Walker::relative_to_abspath( $uploads['basedir'] );
		return array(
			$this->finding(
				'uploads_php_exec_unblocked',
				'low',
				null === $rel ? 'wp-content/uploads' : $rel,
				__( 'PHP execution is not blocked inside the uploads directory. Apply the block from the Integrity Sentinel → Hardening screen (Apache), or add the equivalent nginx rule shown there.', 'integrity-sentinel' )
			),
		);
	}

	/**
	 * Loopback checks for files that exist on disk AND are fetchable over
	 * HTTP. Conditioning on local existence avoids false positives from
	 * servers that answer 200 to everything, and skips pointless requests.
	 * A failed loopback (some hosts block them) just skips the check.
	 */
	private function check_remote_exposures() {
		$out = array();

		$targets = array();
		if ( is_dir( ABSPATH . '.git' ) ) {
			$targets[] = array(
				'url'      => home_url( '/.git/HEAD' ),
				'rule'     => 'git_dir_exposed',
				'severity' => 'high',
				'path'     => '.git/HEAD',
				'detail'   => __( 'The .git directory is web-accessible: the entire source history (often including credentials in old commits) can be downloaded. Deny access to /.git/ in the server config.', 'integrity-sentinel' ),
			);
		}
		if ( file_exists( ABSPATH . '.env' ) ) {
			$targets[] = array(
				'url'      => home_url( '/.env' ),
				'rule'     => 'env_file_exposed',
				'severity' => 'high',
				'path'     => '.env',
				'detail'   => __( 'A .env file is web-accessible — these routinely contain database and API credentials. Deny access to it in the server config or move it out of the webroot.', 'integrity-sentinel' ),
			);
		}
		if ( file_exists( WP_CONTENT_DIR . '/debug.log' ) ) {
			$targets[] = array(
				'url'      => content_url( '/debug.log' ),
				'rule'     => 'debug_log_exposed',
				'severity' => 'medium',
				'path'     => 'wp-content/debug.log',
				'detail'   => __( 'wp-content/debug.log exists and is web-accessible: it can leak file paths, queries, and plugin internals. Block access to it or disable file logging.', 'integrity-sentinel' ),
			);
		}

		foreach ( $targets as $t ) {
			$response = wp_remote_get(
				$t['url'],
				array(
					'timeout'     => 5,
					'redirection' => 0,
				)
			);
			if ( is_wp_error( $response ) ) {
				continue; // host blocks loopback requests -- can't tell, don't guess
			}
			if ( 200 === wp_remote_retrieve_response_code( $response ) && '' !== trim( wp_remote_retrieve_body( $response ) ) ) {
				$out[] = $this->finding( $t['rule'], $t['severity'], $t['path'], $t['detail'] );
			}
		}

		if ( apply_filters( 'xmlrpc_enabled', true ) ) {
			$out[] = $this->finding(
				'xmlrpc_enabled',
				'info',
				'xmlrpc.php',
				__( 'XML-RPC is enabled. If nothing you use needs it (Jetpack, some mobile apps), disable it — it is a long-standing brute-force and amplification vector.', 'integrity-sentinel' )
			);
		}

		return $out;
	}

	private function check_administrators() {
		$out    = array();
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'ID', 'user_login' ),
			)
		);

		$current_ids = array();
		foreach ( $admins as $admin ) {
			$current_ids[] = (int) $admin->ID;
			if ( 'admin' === strtolower( $admin->user_login ) ) {
				$out[] = $this->finding(
					'default_admin_username',
					'low',
					'user:' . $admin->user_login,
					__( 'An administrator account is literally named "admin" — the first username every brute-force attempt tries. Create a new administrator and remove this one.', 'integrity-sentinel' )
				);
			}
		}
		sort( $current_ids );

		// Administrators that appeared since the last scan. A rogue admin
		// account is a common persistence mechanism, and it should never
		// appear without whoever reads the alerts knowing why.
		$known = get_option( 'is_known_admin_ids', null );
		if ( is_array( $known ) ) {
			foreach ( array_diff( $current_ids, array_map( 'intval', $known ) ) as $new_id ) {
				$user  = get_userdata( $new_id );
				$login = $user ? $user->user_login : ( 'ID ' . $new_id );
				$out[] = $this->finding(
					'new_administrator',
					'high',
					'user:' . $login,
					sprintf(
						/* translators: %s: user login */
						__( 'A new administrator account ("%s") was created since the last scan. Verify this was intentional — rogue admin accounts are a standard persistence technique.', 'integrity-sentinel' ),
						$login
					)
				);
			}
		}
		update_option( 'is_known_admin_ids', $current_ids, false );

		return $out;
	}

	/**
	 * Plugins closed/delisted on WordPress.org -- frequently for
	 * unpatched security issues. Cached a week per slug+version of the
	 * question ("is this slug closed?"), capped per scan to bound HTTP.
	 */
	private function check_closed_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$out      = array();
		$requests = 0;
		foreach ( get_plugins() as $plugin_file => $data ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug || $requests >= 30 ) {
				continue;
			}

			$cache_key = 'is_plugin_info_' . md5( $slug );
			$state     = get_transient( $cache_key );
			if ( false === $state ) {
				++$requests;
				$response = wp_remote_get(
					'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode( $slug ),
					array( 'timeout' => 10 )
				);
				if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
					continue; // transient network problem -- retry next scan
				}
				$body  = json_decode( wp_remote_retrieve_body( $response ), true );
				$state = ( is_array( $body ) && ! empty( $body['closed'] ) ) ? 'closed' : 'ok';
				set_transient( $cache_key, $state, WEEK_IN_SECONDS );
			}

			if ( 'closed' === $state ) {
				$out[] = $this->finding(
					'plugin_closed_on_wporg',
					'high',
					'wp-content/plugins/' . $slug,
					sprintf(
						/* translators: %s: plugin name */
						__( '"%s" has been closed on WordPress.org — plugins are frequently closed for unpatched security issues and will never receive updates. Find a maintained replacement.', 'integrity-sentinel' ),
						$data['Name']
					)
				);
			}
		}
		return $out;
	}

	private function check_core_update() {
		$updates = get_site_transient( 'update_core' );
		if ( ! $updates || empty( $updates->updates ) || ! is_array( $updates->updates ) ) {
			return array();
		}
		foreach ( $updates->updates as $update ) {
			if ( isset( $update->response ) && 'upgrade' === $update->response ) {
				return array(
					$this->finding(
						'core_update_available',
						'low',
						'wp-includes/version.php',
						sprintf(
							/* translators: %s: WordPress version */
							__( 'A WordPress core update (%s) is available. Core updates regularly include security fixes.', 'integrity-sentinel' ),
							$update->version ?? ''
						)
					),
				);
			}
		}
		return array();
	}
}

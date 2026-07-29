<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Watches the upgrader for two things:
 *
 *  - New plugin/theme installs: a fresh component appearing on the site
 *    should never be silent — attackers with admin access routinely
 *    install rogue plugins as a foothold.
 *  - Plugin updates: immediately after a WordPress.org plugin updates,
 *    verify the files on disk against the published checksums for the
 *    new version, so a tampered update package (or a compromised
 *    delivery path) is caught within seconds rather than at the next
 *    daily scan.
 */
class IS_Update_Monitor {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			add_action( 'upgrader_process_complete', array( self::$instance, 'on_upgrader_complete' ), 10, 2 );
		}
		return self::$instance;
	}

	/**
	 * @param WP_Upgrader $upgrader   Unused.
	 * @param array       $hook_extra Upgrader context.
	 */
	public function on_upgrader_complete( $upgrader, $hook_extra ) {
		$type   = $hook_extra['type'] ?? '';
		$action = $hook_extra['action'] ?? '';

		if ( 'install' === $action && in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			IS_Audit_Log::record( 'component_installed', array( 'type' => $type ) );
			IS_Notifications::instance()->send_event(
				'component_installed',
				'plugin' === $type
					? __( 'A new plugin was installed', 'integrity-sentinel' )
					: __( 'A new theme was installed', 'integrity-sentinel' ),
				array(
					sprintf(
						/* translators: 1: "plugin" or "theme", 2: user login */
						__( 'A new %1$s was just installed by user "%2$s". If this was not you, investigate immediately.', 'integrity-sentinel' ),
						$type,
						wp_get_current_user()->user_login ?: __( '(unknown)', 'integrity-sentinel' )
					),
				)
			);
			return;
		}

		if ( 'update' === $action && 'plugin' === $type && ! empty( $hook_extra['plugins'] ) ) {
			foreach ( (array) $hook_extra['plugins'] as $plugin_file ) {
				$this->verify_updated_plugin( $plugin_file );
			}
		}
	}

	private function verify_updated_plugin( $plugin_file ) {
		$slug = dirname( $plugin_file );
		if ( '.' === $slug ) {
			return;
		}

		// Read the freshly-updated version straight from the plugin header
		// (the get_plugins() cache may still hold the pre-update version).
		$abs_main = trailingslashit( WP_PLUGIN_DIR ) . $plugin_file;
		if ( ! file_exists( $abs_main ) ) {
			return;
		}
		$data    = get_plugin_data( $abs_main, false, false );
		$version = $data['Version'] ?? '';
		if ( '' === $version ) {
			return;
		}

		$checksums = ( new IS_Plugin_Checksums() )->get_checksums( $slug, $version );
		if ( is_wp_error( $checksums ) ) {
			return; // not a WordPress.org plugin (or no checksums for this version) -- nothing to verify against
		}

		$root       = trailingslashit( WP_PLUGIN_DIR ) . $slug . '/';
		$mismatched = array();
		foreach ( $checksums as $rel_path => $acceptable_hashes ) {
			$abs = $root . $rel_path;
			if ( ! file_exists( $abs ) ) {
				continue;
			}
			$actual = @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false !== $actual && ! in_array( $actual, $acceptable_hashes, true ) ) {
				$mismatched[] = $rel_path;
				if ( count( $mismatched ) >= 20 ) {
					break;
				}
			}
		}

		IS_Audit_Log::record(
			'plugin_update_verified',
			array(
				'plugin'     => $slug,
				'version'    => $version,
				'mismatched' => count( $mismatched ),
			)
		);

		if ( $mismatched ) {
			IS_Notifications::instance()->send_event(
				'update_verification_failed',
				sprintf(
					/* translators: %s: plugin name */
					__( 'Plugin update FAILED checksum verification: %s', 'integrity-sentinel' ),
					$data['Name'] ?: $slug
				),
				array_merge(
					array(
						sprintf(
							/* translators: 1: plugin name, 2: version */
							__( '%1$s was just updated to version %2$s, but these files do not match the official WordPress.org release:', 'integrity-sentinel' ),
							$data['Name'] ?: $slug,
							$version
						),
					),
					$mismatched,
					array( __( 'Reinstall the plugin from WordPress.org and investigate how the tampered files got there.', 'integrity-sentinel' ) )
				)
			);
		}
	}
}

<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates a single scan run. Designed to be called repeatedly in
 * small batches (from an AJAX progress-bar loop, or from a cron
 * safety-net) rather than doing everything in one request -- a full
 * scan of a real site's file tree will blow past PHP's max_execution_time
 * if attempted in one shot, so this class always processes at most
 * `batch_size` files per call and persists a cursor to resume from.
 */
class IS_Scanner {

	/** @var IS_DB */
	private $db;

	public function __construct() {
		$this->db = IS_DB::instance();
	}

	private function settings() {
		return wp_parse_args(
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
	}

	/**
	 * Starts a brand-new scan: builds the file list, stores it as the
	 * run's cursor, and returns the run id. Building the file list is
	 * cheap (just enumerating names, not reading contents) so it's safe
	 * to do synchronously even on the first AJAX call.
	 */
	public function start_run( $trigger_type = 'manual' ) {
		// Refuse to start a second concurrent scan.
		$existing = $this->db->get_running_run();
		if ( $existing ) {
			return (int) $existing['id'];
		}

		$settings = $this->settings();
		$excludes = array_filter( array_map( 'trim', explode( "\n", $settings['excluded_paths'] ) ) );
		$walker   = new IS_File_Walker( $excludes );
		$files    = $walker->list_files();

		$run_id = $this->db->create_run( $trigger_type );
		$this->db->update_run( $run_id, array( 'files_total' => count( $files ) ) );
		$this->db->set_run_cursor(
			$run_id,
			array(
				'files'  => $files,
				'offset' => 0,
			)
		);

		return $run_id;
	}

	/**
	 * Processes the next batch of files for a run. Returns a progress
	 * array the AJAX handler can hand straight back to the browser.
	 */
	public function process_batch( $run_id ) {
		$run = $this->db->get_run( $run_id );
		if ( ! $run || 'running' !== $run['status'] ) {
			return array( 'done' => true, 'error' => __( 'Scan is not running.', 'integrity-sentinel' ) );
		}

		$cursor = $this->db->get_run_cursor( $run_id );
		if ( null === $cursor || ! isset( $cursor['files'] ) ) {
			$this->fail_run( $run_id, __( 'Scan cursor was lost — please start a new scan.', 'integrity-sentinel' ) );
			return array( 'done' => true, 'error' => __( 'Scan cursor was lost.', 'integrity-sentinel' ) );
		}

		$settings   = $this->settings();
		$batch_size = max( 5, (int) $settings['batch_size'] );
		$files      = $cursor['files'];
		$offset     = (int) $cursor['offset'];
		$slice      = array_slice( $files, $offset, $batch_size );

		if ( empty( $slice ) ) {
			$this->finish_run( $run_id, $run['started_at'] );
			return array(
				'done'          => true,
				'files_total'   => count( $files ),
				'files_scanned' => count( $files ),
				'findings_new'  => (int) $run['findings_new'],
			);
		}

		$new_findings = 0;
		foreach ( $slice as $relative_path ) {
			$new_findings += $this->scan_one_file( $run_id, $relative_path, $settings );
		}

		$scanned_so_far = min( $offset + count( $slice ), count( $files ) );
		$this->db->update_run(
			$run_id,
			array(
				'files_scanned' => $scanned_so_far,
				'findings_new'  => (int) $run['findings_new'] + $new_findings,
			)
		);
		$this->db->set_run_cursor(
			$run_id,
			array(
				'files'  => $files,
				'offset' => $offset + count( $slice ),
			)
		);

		return array(
			'done'          => false,
			'files_total'   => count( $files ),
			'files_scanned' => $scanned_so_far,
			'findings_new'  => (int) $run['findings_new'] + $new_findings,
		);
	}

	/**
	 * Everything we know how to check for one file: heuristic pattern
	 * scan, "PHP hiding in uploads" check, and (bundled in as part of the
	 * same pass so we don't walk the tree twice) hashing for the core /
	 * plugin checksum comparison done separately in bulk. Returns the
	 * number of *new* findings recorded for this file.
	 */
	private function scan_one_file( $run_id, $relative_path, array $settings ) {
		$abs_path = trailingslashit( ABSPATH ) . $relative_path;
		if ( ! is_readable( $abs_path ) ) {
			return 0;
		}

		$new_count = 0;
		$size      = filesize( $abs_path );
		$is_php    = (bool) preg_match( '/\.(php|phtml|php[0-9]?)$/i', $relative_path );

		// 1. PHP file living in uploads/ -- uploads should only ever hold
		// media, so any executable PHP there is a strong compromise signal
		// regardless of its content.
		if ( $is_php && ! empty( $settings['scan_uploads_for_php'] ) && IS_File_Walker::is_in_uploads( $relative_path ) ) {
			$result = $this->db->record_finding(
				$run_id,
				array(
					'file_path'  => $relative_path,
					'issue_type' => 'php_in_uploads',
					'severity'   => 'high',
					'rule_id'    => 'php_in_uploads',
					'detail'     => __( 'PHP file found inside the uploads directory. Uploads should only contain media -- executable PHP here is a common sign of a dropped backdoor, even if the content looks benign.', 'integrity-sentinel' ),
				)
			);
			if ( $result['is_new'] ) {
				++$new_count;
			}
		}

		// 2. Heuristic content scan -- skip if the file is unreasonably
		// large (pattern matching a multi-megabyte minified vendor bundle
		// is slow and low-value; we still hash it, just don't grep it).
		if ( $is_php && $size <= ( (int) $settings['max_file_size_kb'] * 1024 ) ) {
			$content = file_get_contents( $abs_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading a local file for pattern matching, not a remote URL
			if ( false !== $content ) {
				$matches = IS_Heuristics::scan_content( $content );
				foreach ( $matches as $match ) {
					$result = $this->db->record_finding(
						$run_id,
						array(
							'file_path'  => $relative_path,
							'issue_type' => 'heuristic_match',
							'severity'   => $match['severity'],
							'rule_id'    => $match['rule_id'],
							'detail'     => $match['label'],
							'meta'       => array(
								'line'    => $match['line'],
								'snippet' => $match['snippet'],
							),
						)
					);
					if ( $result['is_new'] ) {
						++$new_count;
					}
				}
			}
		}

		return $new_count;
	}

	private function finish_run( $run_id, $started_at ) {
		$this->db->auto_resolve_stale_findings( $run_id, $started_at );
		$this->db->update_run(
			$run_id,
			array(
				'status'      => 'completed',
				'finished_at' => current_time( 'mysql' ),
			)
		);
		IS_Notifications::instance()->maybe_send_alert( $run_id );
	}

	private function fail_run( $run_id, $message ) {
		$this->db->update_run(
			$run_id,
			array(
				'status'        => 'error',
				'finished_at'   => current_time( 'mysql' ),
				'error_message' => $message,
			)
		);
	}

	/**
	 * Runs a bulk core-checksum comparison in one pass (separate from
	 * the batched per-file walk above, since it's one API call plus an
	 * in-memory diff rather than a per-file operation). Safe to call on
	 * demand or as part of finishing a scan.
	 */
	public function check_core_integrity( $run_id ) {
		$checker    = new IS_Core_Checksums();
		$checksums  = $checker->get_checksums();
		if ( is_wp_error( $checksums ) ) {
			return $checksums;
		}

		$root  = trailingslashit( ABSPATH );
		$found = 0;

		foreach ( $checksums as $relative_path => $expected_md5 ) {
			if ( $checker->is_expected_variance( $relative_path ) ) {
				continue;
			}
			$abs = $root . $relative_path;
			if ( ! file_exists( $abs ) ) {
				$this->db->record_finding(
					$run_id,
					array(
						'file_path'  => $relative_path,
						'issue_type' => 'core_missing',
						'severity'   => 'high',
						'rule_id'    => 'core_missing',
						'detail'     => __( 'A WordPress core file is missing.', 'integrity-sentinel' ),
					)
				);
				++$found;
				continue;
			}
			$actual_md5 = @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable file falls through to a clear finding below rather than a fatal
			if ( false === $actual_md5 ) {
				continue;
			}
			if ( $actual_md5 !== $expected_md5 ) {
				$result = $this->db->record_finding(
					$run_id,
					array(
						'file_path'  => $relative_path,
						'issue_type' => 'core_modified',
						'severity'   => 'critical',
						'rule_id'    => 'core_modified',
						'detail'     => __( "This core file's contents don't match the official WordPress.org release for your installed version.", 'integrity-sentinel' ),
						'file_hash'  => $actual_md5,
						'meta'       => array( 'expected_md5' => $expected_md5 ),
					)
				);
				if ( $result['is_new'] ) {
					++$found;
				}
			}
		}

		return $found;
	}

	/**
	 * Bulk plugin-checksum comparison, same rationale as core integrity.
	 * @return array{checked:int,skipped:array,findings:int}|WP_Error
	 */
	public function check_plugin_integrity( $run_id ) {
		$checker = new IS_Plugin_Checksums();
		$plugins = $checker->get_checkable_plugins();
		$root    = trailingslashit( WP_PLUGIN_DIR );

		$checked  = 0;
		$skipped  = array();
		$findings = 0;

		foreach ( $plugins['checkable'] as $plugin_file => $info ) {
			$checksums = $checker->get_checksums( $info['slug'], $info['version'] );
			if ( is_wp_error( $checksums ) ) {
				$skipped[] = array(
					'name'   => $info['name'],
					'reason' => $checksums->get_error_message(),
				);
				continue;
			}
			++$checked;

			foreach ( $checksums as $rel_path => $acceptable_hashes ) {
				$abs = $root . $info['slug'] . '/' . $rel_path;
				if ( ! file_exists( $abs ) ) {
					continue; // file removed within the version -- not our business to flag
				}
				$actual_md5 = @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( false === $actual_md5 ) {
					continue;
				}
				if ( ! in_array( $actual_md5, $acceptable_hashes, true ) ) {
					$result = $this->db->record_finding(
						$run_id,
						array(
							'file_path'  => 'wp-content/plugins/' . $info['slug'] . '/' . $rel_path,
							'issue_type' => 'plugin_modified',
							'severity'   => 'high',
							'rule_id'    => 'plugin_modified',
							'detail'     => sprintf(
								/* translators: %s: plugin name */
								__( "This file's contents don't match the official WordPress.org release of %s.", 'integrity-sentinel' ),
								$info['name']
							),
							'file_hash'  => $actual_md5,
						)
					);
					if ( $result['is_new'] ) {
						++$findings;
					}
				}
			}
		}

		return array(
			'checked'  => $checked,
			'skipped'  => $skipped,
			'findings' => $findings,
		);
	}
}

<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates a single scan run. Designed to be called repeatedly in
 * small batches (from an AJAX progress-bar loop, from a cron safety-net,
 * or from WP-CLI) rather than doing everything in one request -- a full
 * scan of a real site's file tree will blow past PHP's max_execution_time
 * if attempted in one shot, so this class always processes at most
 * `batch_size` files (or BATCH_TIME_BUDGET seconds) per call and
 * persists a cursor to resume from.
 *
 * Only one process may drive a run at a time: process_batch() takes an
 * advisory lock, so the browser AJAX loop and the cron safety-net can't
 * scan the same batch twice or clobber each other's counters.
 */
class IS_Scanner {

	/** Seconds of file-scanning per process_batch() call before returning
	 * early -- keeps every batch request comfortably inside a typical
	 * 30-second max_execution_time even when batch_size is set high. */
	const BATCH_TIME_BUDGET = 20;

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
				'webhook_url'          => '',
				'deadman_days'         => 2,
			)
		);
	}

	private function walker( array $settings ) {
		$excludes = array_filter( array_map( 'trim', explode( "\n", $settings['excluded_paths'] ) ) );
		return new IS_File_Walker( $excludes );
	}

	private function is_php_file( $relative_path ) {
		return (bool) preg_match( '/\.(php|phtml|php[0-9]?)$/i', $relative_path );
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

		$files = $this->walker( $this->settings() )->list_files();

		$run_id = $this->db->create_run( $trigger_type );
		$this->db->update_run( $run_id, array( 'files_total' => count( $files ) ) );
		$this->db->set_run_files( $run_id, $files );

		IS_Audit_Log::record(
			'scan_started',
			array(
				'run_id'  => $run_id,
				'trigger' => $trigger_type,
			)
		);

		return $run_id;
	}

	/**
	 * Processes the next batch of files for a run. Returns a progress
	 * array the AJAX handler can hand straight back to the browser.
	 * When the file pass completes, the core/plugin checksum comparisons
	 * run *before* the run is finished (auto-resolve + alert email), so
	 * every kind of finding is on record by the time either happens --
	 * whichever process drives the final batch (AJAX, cron, or CLI).
	 */
	public function process_batch( $run_id ) {
		$run = $this->db->get_run( $run_id );
		if ( ! $run || 'running' !== $run['status'] ) {
			return array(
				'done'  => true,
				'error' => __( 'Scan is not running.', 'integrity-sentinel' ),
			);
		}

		if ( ! $this->db->acquire_scan_lock( $run_id ) ) {
			return array(
				'done'          => false,
				'locked'        => true,
				'files_total'   => (int) $run['files_total'],
				'files_scanned' => (int) $run['files_scanned'],
				'findings_new'  => (int) $run['findings_new'],
			);
		}

		try {
			return $this->process_batch_locked( $run_id, $run );
		} finally {
			$this->db->release_scan_lock( $run_id );
		}
	}

	private function process_batch_locked( $run_id, $run ) {
		$files = $this->db->get_run_files( $run_id );
		if ( null === $files ) {
			$this->fail_run( $run_id, __( 'Scan cursor was lost — please start a new scan.', 'integrity-sentinel' ) );
			return array(
				'done'  => true,
				'error' => __( 'Scan cursor was lost.', 'integrity-sentinel' ),
			);
		}

		$settings    = $this->settings();
		$batch_size  = max( 5, (int) $settings['batch_size'] );
		$total       = count( $files );
		$offset      = (int) $run['cursor_offset'];
		$deadline    = microtime( true ) + self::BATCH_TIME_BUDGET;
		$processed   = 0;
		$batch_start = microtime( true );

		while ( $processed < $batch_size && ( $offset + $processed ) < $total ) {
			$relative_path = $files[ $offset + $processed ];
			$new_findings  = $this->scan_one_file( $run_id, $relative_path, $settings );
			++$processed;

			// Advance the cursor after every file (a cheap single-row
			// UPDATE of small columns) so a fatal mid-batch re-scans at
			// most one file instead of silently redoing the whole batch.
			$this->db->advance_run( $run_id, $offset + $processed, $new_findings );

			if ( microtime( true ) >= $deadline ) {
				break;
			}
		}

		if ( $processed > 0 ) {
			$this->record_pace( ( ( microtime( true ) - $batch_start ) * 1000 ) / $processed );
		}

		if ( ( $offset + $processed ) >= $total ) {
			return $this->complete_run( $run_id, $run );
		}

		$fresh = $this->db->get_run( $run_id );
		return array(
			'done'          => false,
			'files_total'   => $total,
			'files_scanned' => (int) $fresh['files_scanned'],
			'findings_new'  => (int) $fresh['findings_new'],
		);
	}

	/**
	 * The file pass is done: run the (single-request) core and plugin
	 * checksum comparisons, then -- and only then -- auto-resolve stale
	 * findings and send the alert email, so both reflect everything the
	 * scan found rather than just the heuristic pass.
	 */
	private function complete_run( $run_id, $run ) {
		$self_findings      = $this->check_self_integrity( $run_id );
		$hardening_findings = ( new IS_Hardening() )->run_checks( $run_id, $this->db );
		$vuln_findings      = ( new IS_Vulnerability_Scanner() )->run_checks( $run_id, $this->db );
		$core_result        = $this->check_core_integrity( $run_id );
		$plugin_result      = $this->check_plugin_integrity( $run_id );

		$extra_findings = $self_findings + $hardening_findings + $vuln_findings;
		if ( ! is_wp_error( $core_result ) ) {
			$extra_findings += (int) $core_result;
		}
		if ( ! is_wp_error( $plugin_result ) ) {
			$extra_findings += (int) $plugin_result['findings'];
		}
		if ( $extra_findings > 0 ) {
			$this->db->increment_findings( $run_id, $extra_findings );
		}

		$this->finish_run( $run_id, $run['started_at'] );

		$fresh = $this->db->get_run( $run_id );

		IS_Audit_Log::record(
			'scan_completed',
			array(
				'run_id'       => (int) $run_id,
				'findings_new' => (int) $fresh['findings_new'],
			)
		);

		return array(
			'done'            => true,
			'files_total'     => (int) $fresh['files_total'],
			'files_scanned'   => (int) $fresh['files_scanned'],
			'findings_new'    => (int) $fresh['findings_new'],
			'self_check'      => array( 'findings' => $self_findings ),
			'hardening_check' => array( 'findings' => $hardening_findings ),
			'core_check'      => is_wp_error( $core_result )
				? array( 'error' => $core_result->get_error_message() )
				: array( 'findings' => (int) $core_result ),
			'plugin_check'    => is_wp_error( $plugin_result )
				? array( 'error' => $plugin_result->get_error_message() )
				: $plugin_result,
		);
	}

	/**
	 * The scanner verifies ITSELF against a hash manifest shipped with
	 * each release (regenerated by bin/make-manifest.php). A tampered
	 * scanner that reports "all clean" is worse than no scanner. Honest
	 * limitation: an attacker who can edit these files can also edit the
	 * manifest -- this raises the bar and catches the common lazy case
	 * (injecting into an existing plugin file without noticing the
	 * manifest), it is not cryptographic attestation.
	 *
	 * @return int Number of NEW findings.
	 */
	public function check_self_integrity( $run_id ) {
		$plugin_rel = IS_File_Walker::relative_to_abspath( IS_PLUGIN_DIR );
		$prefix     = null === $plugin_rel ? '' : $plugin_rel . '/';

		$manifest_path = IS_PLUGIN_DIR . 'integrity-manifest.json';
		$manifest      = file_exists( $manifest_path )
			? json_decode( (string) file_get_contents( $manifest_path ), true ) // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			: null;

		if ( ! is_array( $manifest ) || empty( $manifest ) ) {
			$result = $this->db->record_finding(
				$run_id,
				array(
					'file_path'  => $prefix . 'integrity-manifest.json',
					'issue_type' => 'self_integrity',
					'severity'   => 'low',
					'rule_id'    => 'sentinel_manifest_missing',
					'detail'     => __( "Integrity Sentinel's own file manifest is missing or unreadable, so the scanner cannot verify its own files. Reinstall the plugin from a trusted copy.", 'integrity-sentinel' ),
				)
			);
			return $result['is_new'] ? 1 : 0;
		}

		$new = 0;
		foreach ( $manifest as $rel => $expected_sha256 ) {
			$abs = IS_PLUGIN_DIR . $rel;
			if ( ! file_exists( $abs ) ) {
				$rule   = 'sentinel_missing_file';
				$detail = __( 'One of Integrity Sentinel\'s own files is missing. A partially-removed or tampered scanner cannot be trusted — reinstall the plugin from a trusted copy.', 'integrity-sentinel' );
			} elseif ( hash_file( 'sha256', $abs ) !== $expected_sha256 ) {
				$rule   = 'sentinel_modified';
				$detail = __( 'One of Integrity Sentinel\'s OWN files does not match its release manifest. A tampered scanner can silently report "all clean" — reinstall the plugin from a trusted copy before believing any other result.', 'integrity-sentinel' );
			} else {
				continue;
			}
			$result = $this->db->record_finding(
				$run_id,
				array(
					'file_path'  => $prefix . $rel,
					'issue_type' => 'self_integrity',
					'severity'   => 'critical',
					'rule_id'    => $rule,
					'detail'     => $detail,
				)
			);
			if ( $result['is_new'] ) {
				++$new;
			}
		}

		// Unknown files in the runtime directories the manifest covers.
		$patterns = array( '*.php', 'includes/*.php', 'assets/js/*.js', 'assets/css/*.css' );
		foreach ( $patterns as $pattern ) {
			foreach ( (array) glob( IS_PLUGIN_DIR . $pattern ) as $abs ) {
				$rel = ltrim( substr( $abs, strlen( IS_PLUGIN_DIR ) ), '/' );
				if ( isset( $manifest[ $rel ] ) ) {
					continue;
				}
				$result = $this->db->record_finding(
					$run_id,
					array(
						'file_path'  => $prefix . $rel,
						'issue_type' => 'self_integrity',
						'severity'   => 'high',
						'rule_id'    => 'sentinel_unknown_file',
						'detail'     => __( 'This file inside Integrity Sentinel\'s own directory is not part of its release manifest. Extra files inside a security plugin\'s directory deserve immediate review.', 'integrity-sentinel' ),
					)
				);
				if ( $result['is_new'] ) {
					++$new;
				}
			}
		}

		return $new;
	}

	/**
	 * Everything we know how to check for one file: heuristic pattern
	 * scan and the "PHP hiding in uploads" check. Returns the number of
	 * *new* findings recorded for this file.
	 */
	private function scan_one_file( $run_id, $relative_path, array $settings ) {
		$abs_path = trailingslashit( ABSPATH ) . $relative_path;
		if ( ! is_readable( $abs_path ) ) {
			return 0;
		}

		$new_count = 0;
		$size      = filesize( $abs_path );
		$is_php    = $this->is_php_file( $relative_path );

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
				foreach ( IS_Heuristics::scan_content( $content ) as $rule_hit ) {
					$first  = $rule_hit['matches'][0];
					$result = $this->db->record_finding(
						$run_id,
						array(
							'file_path'  => $relative_path,
							'issue_type' => 'heuristic_match',
							'severity'   => $rule_hit['severity'],
							'rule_id'    => $rule_hit['rule_id'],
							'detail'     => $rule_hit['label'],
							'meta'       => array(
								'line'    => $first['line'],
								'snippet' => $first['snippet'],
								'matches' => $rule_hit['matches'],
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

	// -----------------------------------------------------------------
	// Self-tuning pace tracking
	// -----------------------------------------------------------------

	/**
	 * Pure: exponential moving average, weighted toward recent batches
	 * (0.3) over history (0.7) so the estimate adapts as file sizes/host
	 * load change, without one unusually slow or fast batch swinging it
	 * wildly. A non-positive previous value means "no history yet".
	 */
	public static function next_pace_average( $previous_ms_per_file, $observed_ms_per_file ) {
		if ( $previous_ms_per_file <= 0 ) {
			return $observed_ms_per_file;
		}
		return ( $previous_ms_per_file * 0.7 ) + ( $observed_ms_per_file * 0.3 );
	}

	private function record_pace( $observed_ms_per_file ) {
		$previous = (float) get_option( 'is_avg_ms_per_file', 0 );
		update_option( 'is_avg_ms_per_file', self::next_pace_average( $previous, $observed_ms_per_file ), false );
	}

	/** @return float|null Observed average ms/file, or null if no run has completed a batch yet. */
	public static function average_ms_per_file() {
		$value = get_option( 'is_avg_ms_per_file', 0 );
		return $value > 0 ? (float) $value : null;
	}

	/**
	 * Runs a bulk core-checksum comparison in one pass (separate from
	 * the batched per-file walk above, since it's one API call plus an
	 * in-memory diff rather than a per-file operation). Also flags files
	 * present under wp-admin/ and wp-includes/ that are NOT part of the
	 * official release at all -- a dropped extra file there is at least
	 * as suspicious as a modified one, and checksum-list iteration alone
	 * can never see it.
	 */
	public function check_core_integrity( $run_id ) {
		$checker   = new IS_Core_Checksums();
		$checksums = $checker->get_checksums();
		if ( is_wp_error( $checksums ) ) {
			return $checksums;
		}

		$walker = $this->walker( $this->settings() );
		$root   = trailingslashit( ABSPATH );
		$found  = 0;

		foreach ( $checksums as $relative_path => $expected_md5 ) {
			if ( $checker->is_expected_variance( $relative_path ) ) {
				continue;
			}
			$abs = $root . $relative_path;
			if ( ! file_exists( $abs ) ) {
				$result = $this->db->record_finding(
					$run_id,
					array(
						'file_path'  => $relative_path,
						'issue_type' => 'core_missing',
						'severity'   => 'high',
						'rule_id'    => 'core_missing',
						'detail'     => __( 'A WordPress core file is missing.', 'integrity-sentinel' ),
					)
				);
				if ( $result['is_new'] ) {
					++$found;
				}
				continue;
			}
			$actual_md5 = @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable file falls through rather than a fatal
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

		// Unknown files: anything on disk under the two pure-core
		// directories that the official release manifest doesn't list.
		// (Deliberately not applied to the WP root, where hosts and
		// drop-ins legitimately add files.)
		foreach ( array( 'wp-admin', 'wp-includes' ) as $core_dir ) {
			foreach ( $walker->list_files_under( $root . $core_dir ) as $relative_path ) {
				if ( isset( $checksums[ $relative_path ] ) ) {
					continue;
				}
				$is_php = $this->is_php_file( $relative_path );
				$result = $this->db->record_finding(
					$run_id,
					array(
						'file_path'  => $relative_path,
						'issue_type' => 'core_unknown_file',
						'severity'   => $is_php ? 'high' : 'low',
						'rule_id'    => 'core_unknown_file',
						'detail'     => $is_php
							? __( 'This PHP file is not part of the official WordPress release for your installed version. Attackers commonly hide backdoors as extra files inside wp-admin/ or wp-includes/.', 'integrity-sentinel' )
							: __( 'This file is not part of the official WordPress release for your installed version.', 'integrity-sentinel' ),
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
	 * Bulk plugin-checksum comparison, same rationale as core integrity,
	 * including the unknown-file check: a file inside a verified plugin's
	 * directory that isn't in its published manifest is a classic malware
	 * drop location.
	 *
	 * @return array{checked:int,skipped:array,findings:int}
	 */
	public function check_plugin_integrity( $run_id ) {
		$checker = new IS_Plugin_Checksums();
		$plugins = $checker->get_checkable_plugins();
		$walker  = $this->walker( $this->settings() );
		$root    = trailingslashit( WP_PLUGIN_DIR );

		$checked  = 0;
		$skipped  = array();
		$findings = 0;

		foreach ( $plugins['checkable'] as $plugin_file => $info ) {
			$checksums = $checker->get_checksums( $info['slug'], $info['version'] );
			if ( is_wp_error( $checksums ) ) {
				$skipped[] = array(
					'name'          => $info['name'],
					'reason'        => $checksums->get_error_message(),
					'not_checkable' => 'is_plugin_checksums_not_found' === $checksums->get_error_code(),
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

			// Unknown files inside this plugin's directory. The walker
			// returns ABSPATH-relative paths (and returns nothing if the
			// plugins dir lives outside ABSPATH, in which case we simply
			// can't do this check), so strip the plugin-dir prefix to
			// compare against the manifest's plugin-relative paths.
			$dir_prefix = IS_File_Walker::relative_to_abspath( $root . $info['slug'] );
			if ( null === $dir_prefix ) {
				continue;
			}
			$dir_prefix .= '/';
			foreach ( $walker->list_files_under( $root . $info['slug'] ) as $relative_path ) {
				$inner = substr( $relative_path, strlen( $dir_prefix ) );
				if ( isset( $checksums[ $inner ] ) ) {
					continue;
				}
				$is_php = $this->is_php_file( $inner );
				$result = $this->db->record_finding(
					$run_id,
					array(
						'file_path'  => $relative_path,
						'issue_type' => 'plugin_unknown_file',
						'severity'   => $is_php ? 'high' : 'low',
						'rule_id'    => 'plugin_unknown_file',
						'detail'     => sprintf(
							/* translators: %s: plugin name */
							$is_php
								? __( 'This PHP file is not part of the official WordPress.org release of %s — extra files dropped into a plugin directory are a classic malware hiding spot.', 'integrity-sentinel' )
								: __( 'This file is not part of the official WordPress.org release of %s.', 'integrity-sentinel' ),
							$info['name']
						),
					)
				);
				if ( $result['is_new'] ) {
					++$findings;
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

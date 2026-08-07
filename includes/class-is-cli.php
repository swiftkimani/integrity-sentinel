<?php
/**
 * WP-CLI commands for Integrity Sentinel.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WP-CLI interface, for two reasons a wp-admin button can't cover:
 *  - WP-Cron is unreliable on low-traffic sites; `wp integrity-sentinel
 *    scan` from a real system crontab is the dependable way to schedule
 *    scans on a server you control.
 *  - Incident response usually happens over SSH, not in wp-admin.
 */
class IS_CLI {

	/**
	 * Runs a full integrity scan (file walk + heuristics + core and
	 * plugin checksum verification) and prints a summary.
	 *
	 * ## OPTIONS
	 *
	 * [--resume]
	 * : If a scan is already running, drive it to completion instead of
	 *   refusing to start.
	 *
	 * ## EXAMPLES
	 *
	 *     wp integrity-sentinel scan
	 *     wp integrity-sentinel scan --resume
	 *
	 * @param array $args       Positional arguments (unused).
	 * @param array $assoc_args Flags.
	 */
	public function scan( $args, $assoc_args ) {
		$db       = IS_DB::instance();
		$scanner  = new IS_Scanner();
		$existing = $db->get_running_run();

		if ( $existing && ! isset( $assoc_args['resume'] ) ) {
			WP_CLI::error( sprintf( 'Scan #%d is already running. Pass --resume to drive it to completion.', (int) $existing['id'] ) );
		}

		$run_id = $existing ? (int) $existing['id'] : $scanner->start_run( 'cli' );
		$run    = $db->get_run( $run_id );

		$progress_bar = \WP_CLI\Utils\make_progress_bar( 'Scanning files', (int) $run['files_total'] );
		$progress_bar->tick( (int) $run['files_scanned'] );
		$last_scanned = (int) $run['files_scanned'];

		do {
			$progress = $scanner->process_batch( $run_id );

			if ( ! empty( $progress['locked'] ) ) {
				WP_CLI::error( 'Another process is driving this scan (lock held). Try again shortly.' );
			}
			if ( ! empty( $progress['error'] ) ) {
				WP_CLI::error( $progress['error'] );
			}

			$scanned = (int) $progress['files_scanned'];
			$progress_bar->tick( $scanned - $last_scanned );
			$last_scanned = $scanned;
		} while ( empty( $progress['done'] ) );

		$progress_bar->finish();

		if ( isset( $progress['self_check']['findings'] ) ) {
			WP_CLI::log( sprintf( 'Self-integrity check: %d new finding(s).', (int) $progress['self_check']['findings'] ) );
		}
		if ( isset( $progress['hardening_check']['findings'] ) ) {
			WP_CLI::log( sprintf( 'Hardening checks: %d new finding(s).', (int) $progress['hardening_check']['findings'] ) );
		}

		if ( isset( $progress['core_check']['error'] ) ) {
			WP_CLI::warning( 'Core checksum verification failed: ' . $progress['core_check']['error'] );
		} else {
			WP_CLI::log( sprintf( 'Core checksum verification: %d new finding(s).', (int) $progress['core_check']['findings'] ) );
		}

		if ( isset( $progress['plugin_check']['error'] ) ) {
			WP_CLI::warning( 'Plugin checksum verification failed: ' . $progress['plugin_check']['error'] );
		} else {
			WP_CLI::log(
				sprintf(
					'Plugin checksum verification: %d plugin(s) checked, %d new finding(s).',
					(int) $progress['plugin_check']['checked'],
					(int) $progress['plugin_check']['findings']
				)
			);
			foreach ( (array) $progress['plugin_check']['skipped'] as $skip ) {
				WP_CLI::log( sprintf( '  Not verified: %s — %s', $skip['name'], $skip['reason'] ) );
			}
		}

		WP_CLI::success(
			sprintf(
				'Scan #%d complete: %d files scanned, %d new finding(s).',
				$run_id,
				(int) $progress['files_scanned'],
				(int) $progress['findings_new']
			)
		);

		if ( (int) $progress['findings_new'] > 0 ) {
			WP_CLI::log( 'Review them with: wp integrity-sentinel findings' );
			WP_CLI::halt( 1 ); // non-zero exit so a crontab/CI wrapper can alert on findings.
		}
	}

	/**
	 * Shows the most recent scan run.
	 *
	 * ## EXAMPLES
	 *
	 *     wp integrity-sentinel status
	 */
	public function status() {
		$run = IS_DB::instance()->get_latest_run();
		if ( ! $run ) {
			WP_CLI::log( 'No scan has run yet.' );
			return;
		}
		\WP_CLI\Utils\format_items(
			'table',
			array( $run ),
			array( 'id', 'status', 'trigger_type', 'started_at', 'finished_at', 'files_scanned', 'files_total', 'findings_new' )
		);
	}

	/**
	 * Lists findings.
	 *
	 * ## OPTIONS
	 *
	 * [--status=<status>]
	 * : Filter by status (new, acknowledged, ignored, resolved). Default: new.
	 *
	 * [--severity=<severity>]
	 * : Filter by severity (critical, high, medium, low, info).
	 *
	 * [--limit=<limit>]
	 * : Maximum rows to show. Default: 100.
	 *
	 * [--format=<format>]
	 * : table, csv, json, or yaml. Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp integrity-sentinel findings
	 *     wp integrity-sentinel findings --severity=critical --format=json
	 *
	 * @param array $args       Positional arguments (unused).
	 * @param array $assoc_args Flags.
	 */
	public function findings( $args, $assoc_args ) {
		$rows = IS_DB::instance()->get_findings(
			array(
				'status'   => $assoc_args['status'] ?? 'new',
				'severity' => $assoc_args['severity'] ?? '',
				'limit'    => (int) ( $assoc_args['limit'] ?? 100 ),
			)
		);

		if ( empty( $rows ) ) {
			WP_CLI::log( 'No findings match.' );
			return;
		}

		\WP_CLI\Utils\format_items(
			$assoc_args['format'] ?? 'table',
			$rows,
			array( 'id', 'severity', 'status', 'issue_type', 'file_path', 'first_seen', 'last_seen' )
		);
	}
}

<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two cron responsibilities:
 *  1. Kick off a fresh full scan on a schedule (daily by default).
 *  2. A safety net that resumes a scan if it was left "running" for an
 *     unreasonably long time -- e.g. the admin started a manual scan via
 *     AJAX and closed the browser tab mid-scan. Without this, that run
 *     would sit at "running" forever and block new scans from starting
 *     (IS_Scanner::start_run() refuses to start a second concurrent run).
 */
class IS_Cron {

	private static $instance = null;
	const STALL_THRESHOLD = 30 * MINUTE_IN_SECONDS;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	private function hooks() {
		add_action( IS_CRON_DAILY_SCAN, array( $this, 'run_daily_scan' ) );
		add_action( IS_CRON_RESUME_SCAN, array( $this, 'resume_stalled_scan' ) );

		// Register the resume-check to run every 5 minutes via a
		// custom cron schedule, self-healing rather than assuming a
		// fixed WordPress interval exists.
		add_filter( 'cron_schedules', array( $this, 'add_five_minute_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval
		if ( ! wp_next_scheduled( IS_CRON_RESUME_SCAN ) ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, 'is_five_minutes', IS_CRON_RESUME_SCAN );
		}
	}

	public function add_five_minute_schedule( $schedules ) {
		$schedules['is_five_minutes'] = array(
			'interval' => 5 * MINUTE_IN_SECONDS,
			'display'  => __( 'Every 5 minutes (Integrity Sentinel)', 'integrity-sentinel' ),
		);
		return $schedules;
	}

	public function run_daily_scan() {
		$scanner = new IS_Scanner();
		$db      = IS_DB::instance();

		if ( $db->get_running_run() ) {
			return; // don't stack a second scan on top of one already in progress
		}

		$run_id = $scanner->start_run( 'cron' );
		// Process the whole thing here in a loop of batches -- WP-Cron
		// requests aren't subject to the same tight timeout as a normal
		// page load, but we still cap total iterations defensively so a
		// misbehaving host can't spin this forever.
		$max_iterations = 500;
		do {
			$progress = $scanner->process_batch( $run_id );
			--$max_iterations;
		} while ( empty( $progress['done'] ) && $max_iterations > 0 );

		$scanner->check_core_integrity( $run_id );
		$scanner->check_plugin_integrity( $run_id );
	}

	public function resume_stalled_scan() {
		$db  = IS_DB::instance();
		$run = $db->get_running_run();
		if ( ! $run ) {
			return;
		}

		$age = time() - strtotime( $run['started_at'] );
		if ( $age < self::STALL_THRESHOLD ) {
			return; // still plausibly an active AJAX-driven scan, leave it alone
		}

		$scanner        = new IS_Scanner();
		$max_iterations = 200;
		do {
			$progress = $scanner->process_batch( (int) $run['id'] );
			--$max_iterations;
		} while ( empty( $progress['done'] ) && $max_iterations > 0 );
	}
}

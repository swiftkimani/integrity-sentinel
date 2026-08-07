<?php
/**
 * Cron scheduling: drives the periodic full scan and resumes any scan
 * whose driver went away before it finished.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two cron responsibilities:
 *  1. Kick off a fresh full scan on a schedule -- configurable
 *     (hourly/twicedaily/daily/weekly), daily by default. Despite its
 *     name, IS_CRON_DAILY_SCAN is just the hook identifier; the actual
 *     recurrence is whatever scan_frequency is currently set to.
 *  2. A safety net that resumes a scan whose driver went away -- e.g.
 *     the admin started a manual scan via AJAX and closed the browser
 *     tab mid-scan. Without this, that run would sit at "running"
 *     forever and block new scans from starting.
 *
 * Staleness is judged on the run's *last activity* (bumped on every
 * batch), not its start time -- a legitimately long AJAX-driven scan is
 * active the whole way through and must not be double-driven by cron.
 * process_batch() additionally holds an advisory lock, so even a
 * mistimed resume can't scan the same batch twice.
 */
class IS_Cron {

	/**
	 * Singleton instance.
	 *
	 * @var IS_Cron|null
	 */
	private static $instance = null;
	const STALL_THRESHOLD    = 15 * MINUTE_IN_SECONDS;

	/** WP core provides hourly/twicedaily/daily; weekly is the only gap. */
	const VALID_FREQUENCIES = array( 'hourly', 'twicedaily', 'daily', 'weekly' );

	/**
	 * Gets (and lazily creates) the singleton instance, wiring up hooks
	 * the first time it is created.
	 *
	 * @return IS_Cron
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	/**
	 * Registers the cron actions and ensures our custom schedules exist.
	 */
	private function hooks() {
		add_action( IS_CRON_DAILY_SCAN, array( $this, 'run_daily_scan' ) );
		add_action( IS_CRON_RESUME_SCAN, array( $this, 'resume_stalled_scan' ) );

		// Register our own schedules (the 5-minute resume check, and
		// 'weekly' for the configurable scan frequency) rather than
		// assuming they exist -- self-healing across WP core versions.
		add_filter( 'cron_schedules', array( $this, 'add_custom_schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval
		if ( ! wp_next_scheduled( IS_CRON_RESUME_SCAN ) ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, 'is_five_minutes', IS_CRON_RESUME_SCAN );
		}
	}

	/**
	 * Registers the extra cron schedules this module relies on, without
	 * assuming they don't already exist.
	 *
	 * @param array $schedules Existing cron schedules, as passed by the
	 *                         'cron_schedules' filter.
	 * @return array Schedules with our additions merged in.
	 */
	public function add_custom_schedules( $schedules ) {
		$schedules['is_five_minutes'] = array(
			'interval' => 5 * MINUTE_IN_SECONDS,
			'display'  => __( 'Every 5 minutes (Integrity Sentinel)', 'integrity-sentinel' ),
		);
		if ( ! isset( $schedules['weekly'] ) ) {
			$schedules['weekly'] = array(
				'interval' => WEEK_IN_SECONDS,
				'display'  => __( 'Once weekly', 'integrity-sentinel' ),
			);
		}
		return $schedules;
	}

	/**
	 * Pure: falls back to 'daily' for anything not one of our known schedules.
	 *
	 * @param string $frequency Candidate schedule slug.
	 * @return string A valid schedule slug.
	 */
	public static function normalize_frequency( $frequency ) {
		return in_array( $frequency, self::VALID_FREQUENCIES, true ) ? $frequency : 'daily';
	}

	/**
	 * Reschedules the recurring scan at a new frequency, replacing
	 * whatever was previously scheduled. Safe to call even if nothing
	 * was scheduled yet (e.g. from activation).
	 *
	 * @param string $frequency Desired schedule slug.
	 */
	public static function reschedule_scan( $frequency ) {
		$frequency = self::normalize_frequency( $frequency );
		$existing  = wp_next_scheduled( IS_CRON_DAILY_SCAN );
		if ( $existing ) {
			wp_unschedule_event( $existing, IS_CRON_DAILY_SCAN );
		}
		wp_schedule_event( time() + ( 2 * HOUR_IN_SECONDS ), $frequency, IS_CRON_DAILY_SCAN );
	}

	/**
	 * Fires on the configured recurrence: starts a fresh full scan and
	 * drives it to completion, unless one is already running.
	 */
	public function run_daily_scan() {
		$scanner = new IS_Scanner();
		$db      = IS_DB::instance();

		if ( $db->get_running_run() ) {
			return; // Don't stack a second scan on top of one already in progress.
		}

		$run_id = $scanner->start_run( 'cron' );
		$this->drive_to_completion( $scanner, $run_id, 500 );
	}

	/**
	 * Safety-net cron: picks a scan back up if it has gone stale (no
	 * activity within STALL_THRESHOLD), and checks the dead-man's switch.
	 */
	public function resume_stalled_scan() {
		$this->maybe_alert_dead_man();

		$db  = IS_DB::instance();
		$run = $db->get_running_run();
		if ( ! $run ) {
			return;
		}

		// Both timestamps are in the site's local timezone
		// (current_time('mysql') wrote them; current_time('timestamp')
		// reads "now" the same way), so the subtraction is a real age --
		// mixing in UTC time() here would skew the age by the TZ offset.
		$last_activity = ! empty( $run['last_activity_at'] ) ? $run['last_activity_at'] : $run['started_at'];
		$age           = current_time( 'timestamp' ) - strtotime( $last_activity ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- compared against current_time('mysql')-sourced values
		if ( $age < self::STALL_THRESHOLD ) {
			return; // Still plausibly an actively-driven scan, leave it alone.
		}

		$this->drive_to_completion( new IS_Scanner(), (int) $run['id'], 200 );
	}

	/**
	 * Dead-man's switch: if no scan has COMPLETED in the configured
	 * number of days, something has silently broken (scans erroring,
	 * cron half-dead, tables tampered with) and whoever reads the
	 * alerts needs to know they've gone blind. Throttled to one alert
	 * per day. Honest limitation: if WP-Cron itself is fully dead this
	 * never fires either -- which is exactly why the readme recommends
	 * driving scans from a real system crontab via WP-CLI.
	 */
	private function maybe_alert_dead_man() {
		$settings = get_option( 'is_scan_settings', array() );
		$days     = max( 1, min( 30, (int) ( $settings['deadman_days'] ?? 2 ) ) );

		$last = IS_DB::instance()->get_latest_completed_run();
		if ( ! $last || empty( $last['finished_at'] ) ) {
			return; // Nothing has ever completed; the first scan hasn't happened yet.
		}

		$age = current_time( 'timestamp' ) - strtotime( $last['finished_at'] ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- compared against current_time('mysql')-sourced values
		if ( $age < $days * DAY_IN_SECONDS ) {
			return;
		}

		if ( time() - (int) get_option( 'is_deadman_last_alert', 0 ) < DAY_IN_SECONDS ) {
			return;
		}
		update_option( 'is_deadman_last_alert', time(), false );

		IS_Audit_Log::record( 'deadman_alert', array( 'days_without_scan' => $days ) );
		IS_Notifications::instance()->send_event(
			'deadman',
			__( 'No completed integrity scan recently — the scanner may be blind', 'integrity-sentinel' ),
			array(
				sprintf(
					/* translators: 1: number of days, 2: datetime of last completed scan */
					__( 'No integrity scan has completed in over %1$d day(s). The last completed scan finished at %2$s.', 'integrity-sentinel' ),
					$days,
					$last['finished_at']
				),
				__( 'Check that the plugin is active and WP-Cron is firing, or run a scan manually (dashboard button or `wp integrity-sentinel scan`). A security scanner that has silently stopped scanning protects nothing.', 'integrity-sentinel' ),
			)
		);
	}

	/**
	 * Loop batches until the run finishes, another process holds the
	 * lock (it's driving; back off), or the defensive iteration cap is
	 * hit (a misbehaving host can't spin this forever -- the 5-minute
	 * safety net will pick the run back up).
	 *
	 * @param IS_Scanner $scanner        Scanner instance to drive.
	 * @param int        $run_id         ID of the run being processed.
	 * @param int        $max_iterations Defensive cap on the number of batches to process.
	 */
	private function drive_to_completion( IS_Scanner $scanner, $run_id, $max_iterations ) {
		do {
			$progress = $scanner->process_batch( $run_id );
			if ( ! empty( $progress['locked'] ) ) {
				return;
			}
			--$max_iterations;
		} while ( empty( $progress['done'] ) && $max_iterations > 0 );
	}
}

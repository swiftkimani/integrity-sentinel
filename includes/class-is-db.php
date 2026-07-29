<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Owns the two custom tables this plugin needs. A custom table (rather
 * than options/postmeta) is the right call here because a single scan on
 * a mid-sized site can produce thousands of file-level rows that need to
 * be paginated, filtered by severity/status, and queried efficiently --
 * none of which the options table is built for.
 */
class IS_DB {

	private static $instance = null;

	/**
	 * How long a batch lock may be held before another process is allowed
	 * to steal it. Generous because run completion includes remote
	 * checksum-API calls that can legitimately take a couple of minutes
	 * on a plugin-heavy site with a cold cache.
	 */
	const LOCK_TTL = 5 * MINUTE_IN_SECONDS;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'plugins_loaded', array( $this, 'maybe_upgrade' ) );
	}

	public function runs_table() {
		global $wpdb;
		return $wpdb->prefix . 'is_scan_runs';
	}

	public function findings_table() {
		global $wpdb;
		return $wpdb->prefix . 'is_findings';
	}

	public function audit_table() {
		global $wpdb;
		return $wpdb->prefix . 'is_audit_log';
	}

	public function maybe_upgrade() {
		if ( get_option( 'is_db_version' ) !== IS_DB_VERSION ) {
			$this->create_tables();
			update_option( 'is_db_version', IS_DB_VERSION, false );
		}
	}

	public function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$runs_table       = $this->runs_table();
		$findings_table   = $this->findings_table();
		$audit_table      = $this->audit_table();

		$sql = "CREATE TABLE {$runs_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			status VARCHAR(20) NOT NULL DEFAULT 'running',
			trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual',
			started_at DATETIME NOT NULL,
			finished_at DATETIME NULL,
			last_activity_at DATETIME NULL,
			files_total INT UNSIGNED NOT NULL DEFAULT 0,
			files_scanned INT UNSIGNED NOT NULL DEFAULT 0,
			cursor_offset INT UNSIGNED NOT NULL DEFAULT 0,
			findings_new INT UNSIGNED NOT NULL DEFAULT 0,
			cursor_data LONGTEXT NULL,
			error_message TEXT NULL,
			PRIMARY KEY  (id),
			KEY status (status)
		) {$charset_collate};

		CREATE TABLE {$findings_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			run_id BIGINT UNSIGNED NOT NULL,
			file_path VARCHAR(500) NOT NULL,
			issue_type VARCHAR(40) NOT NULL,
			severity VARCHAR(10) NOT NULL,
			rule_id VARCHAR(60) NULL,
			detail TEXT NULL,
			file_hash VARCHAR(64) NULL,
			meta LONGTEXT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'new',
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY file_path (file_path(191)),
			KEY severity (severity),
			KEY status (status),
			KEY run_id (run_id)
		) {$charset_collate};

		CREATE TABLE {$audit_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			user_login VARCHAR(60) NOT NULL DEFAULT '',
			ip VARCHAR(45) NOT NULL DEFAULT '',
			action VARCHAR(40) NOT NULL,
			detail TEXT NULL,
			PRIMARY KEY  (id),
			KEY action (action),
			KEY created_at (created_at)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	// ---------------------------------------------------------------
	// Scan run helpers
	// ---------------------------------------------------------------

	public function create_run( $trigger_type = 'manual' ) {
		global $wpdb;
		$now = current_time( 'mysql' );
		$wpdb->insert(
			$this->runs_table(),
			array(
				'status'           => 'running',
				'trigger_type'     => $trigger_type,
				'started_at'       => $now,
				'last_activity_at' => $now,
			),
			array( '%s', '%s', '%s', '%s' )
		);
		return (int) $wpdb->insert_id;
	}

	public function get_run( $run_id ) {
		global $wpdb;
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$this->runs_table()} WHERE id = %d", $run_id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name, not user input
			ARRAY_A
		);
	}

	public function get_latest_run() {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM {$this->runs_table()} ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}

	public function get_running_run() {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM {$this->runs_table()} WHERE status = 'running' ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}

	public function get_latest_completed_run() {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM {$this->runs_table()} WHERE status = 'completed' ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}

	public function update_run( $run_id, array $fields ) {
		global $wpdb;
		$formats = array();
		foreach ( $fields as $key => $value ) {
			$formats[] = is_int( $value ) ? '%d' : '%s';
		}
		$wpdb->update( $this->runs_table(), $fields, array( 'id' => $run_id ), $formats, array( '%d' ) );
	}

	/**
	 * The immutable file list for a run, written once at start_run() and
	 * only ever read afterwards. The moving parts (offset, counters) live
	 * in their own small columns -- rewriting a multi-megabyte JSON blob
	 * after every batch was the old design's biggest scaling problem.
	 */
	public function set_run_files( $run_id, array $files ) {
		$this->update_run( $run_id, array( 'cursor_data' => wp_json_encode( $files ) ) );
	}

	/**
	 * @return array|null Flat list of relative paths, or null if missing/corrupt.
	 */
	public function get_run_files( $run_id ) {
		$run = $this->get_run( $run_id );
		if ( ! $run || empty( $run['cursor_data'] ) ) {
			return null;
		}
		$decoded = json_decode( $run['cursor_data'], true );
		if ( ! is_array( $decoded ) ) {
			return null;
		}
		// Back-compat: a v1 cursor was {"files": [...], "offset": n}.
		if ( isset( $decoded['files'] ) && is_array( $decoded['files'] ) ) {
			return $decoded['files'];
		}
		return array_values( $decoded );
	}

	/**
	 * Atomically advance the scan cursor and add this step's new-finding
	 * count. findings_new is incremented in SQL (not read-modify-write in
	 * PHP) so two processes briefly overlapping can't lose each other's
	 * updates.
	 */
	public function advance_run( $run_id, $offset, $findings_delta = 0 ) {
		global $wpdb;
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$this->runs_table()} SET cursor_offset = %d, files_scanned = %d, findings_new = findings_new + %d, last_activity_at = %s WHERE id = %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$offset,
				$offset,
				max( 0, (int) $findings_delta ),
				current_time( 'mysql' ),
				$run_id
			)
		);
	}

	public function increment_findings( $run_id, $delta ) {
		global $wpdb;
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$this->runs_table()} SET findings_new = findings_new + %d WHERE id = %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				max( 0, (int) $delta ),
				$run_id
			)
		);
	}

	// ---------------------------------------------------------------
	// Batch locking
	// ---------------------------------------------------------------

	/**
	 * Advisory lock so only one process (browser AJAX loop, daily cron,
	 * resume cron, WP-CLI) drives a run's batches at a time. Implemented
	 * on the options table: add_option() is backed by an INSERT that
	 * fails if the row exists, which makes acquisition effectively
	 * atomic. A stale lock (holder fataled mid-batch) is stolen after
	 * LOCK_TTL rather than blocking the scan forever.
	 */
	public function acquire_scan_lock( $run_id ) {
		$name = 'is_scan_lock_' . (int) $run_id;
		$now  = time();

		if ( add_option( $name, (string) $now, '', false ) ) {
			return true;
		}

		$held_at = (int) get_option( $name );
		if ( $held_at && ( $now - $held_at ) > self::LOCK_TTL ) {
			update_option( $name, (string) $now, false );
			return true;
		}

		return false;
	}

	public function release_scan_lock( $run_id ) {
		delete_option( 'is_scan_lock_' . (int) $run_id );
	}

	// ---------------------------------------------------------------
	// Findings helpers
	// ---------------------------------------------------------------

	/**
	 * Upsert a finding: if the same file + issue_type + rule from a
	 * still-open problem already exists (status new/acknowledged), bump
	 * last_seen and refresh the detail instead of creating a duplicate
	 * row every single scan. rule_id is part of the identity so two
	 * different heuristic rules matching the same file stay two separate
	 * findings rather than overwriting each other.
	 */
	public function record_finding( $run_id, array $finding ) {
		global $wpdb;
		$table   = $this->findings_table();
		$now     = current_time( 'mysql' );
		$rule_id = $finding['rule_id'] ?? $finding['issue_type'];

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, status FROM {$table} WHERE file_path = %s AND issue_type = %s AND rule_id = %s AND status IN ('new','acknowledged') ORDER BY id DESC LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$finding['file_path'],
				$finding['issue_type'],
				$rule_id
			),
			ARRAY_A
		);

		if ( $existing ) {
			$wpdb->update(
				$table,
				array(
					'run_id'    => $run_id,
					'severity'  => $finding['severity'],
					'rule_id'   => $rule_id,
					'detail'    => $finding['detail'] ?? '',
					'file_hash' => $finding['file_hash'] ?? null,
					'meta'      => isset( $finding['meta'] ) ? wp_json_encode( $finding['meta'] ) : null,
					'last_seen' => $now,
				),
				array( 'id' => $existing['id'] ),
				null,
				array( '%d' )
			);
			return array( 'id' => (int) $existing['id'], 'is_new' => false );
		}

		$wpdb->insert(
			$table,
			array(
				'run_id'     => $run_id,
				'file_path'  => $finding['file_path'],
				'issue_type' => $finding['issue_type'],
				'severity'   => $finding['severity'],
				'rule_id'    => $rule_id,
				'detail'     => $finding['detail'] ?? '',
				'file_hash'  => $finding['file_hash'] ?? null,
				'meta'       => isset( $finding['meta'] ) ? wp_json_encode( $finding['meta'] ) : null,
				'status'     => 'new',
				'first_seen' => $now,
				'last_seen'  => $now,
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		return array( 'id' => (int) $wpdb->insert_id, 'is_new' => true );
	}

	/**
	 * Findings from a previous run that were NOT re-flagged in the given
	 * run are auto-resolved (the underlying issue is gone -- file fixed,
	 * restored, or deleted). Must only be called after *every* check in
	 * the run (file pass AND checksum passes) has recorded its findings.
	 */
	public function auto_resolve_stale_findings( $run_id, $current_run_started_at ) {
		global $wpdb;
		$table = $this->findings_table();
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET status = 'resolved' WHERE status IN ('new','acknowledged') AND last_seen < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$current_run_started_at
			)
		);
	}

	public function get_findings( array $args = array() ) {
		global $wpdb;
		$table   = $this->findings_table();
		$where   = array( '1=1' );
		$params  = array();

		if ( ! empty( $args['status'] ) ) {
			$where[]  = 'status = %s';
			$params[] = $args['status'];
		}
		if ( ! empty( $args['severity'] ) ) {
			$where[]  = 'severity = %s';
			$params[] = $args['severity'];
		}
		if ( ! empty( $args['search'] ) ) {
			$where[]  = 'file_path LIKE %s';
			$params[] = '%' . $wpdb->esc_like( $args['search'] ) . '%';
		}

		$limit  = isset( $args['limit'] ) ? (int) $args['limit'] : 50;
		$offset = isset( $args['offset'] ) ? (int) $args['offset'] : 0;

		$sql = "SELECT * FROM {$table} WHERE " . implode( ' AND ', $where ) . " ORDER BY FIELD(severity,'critical','high','medium','low','info'), last_seen DESC LIMIT %d OFFSET %d";
		$params[] = $limit;
		$params[] = $offset;

		return $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	public function count_findings( array $args = array() ) {
		global $wpdb;
		$table  = $this->findings_table();
		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $args['status'] ) ) {
			$where[]  = 'status = %s';
			$params[] = $args['status'];
		}
		if ( ! empty( $args['severity'] ) ) {
			$where[]  = 'severity = %s';
			$params[] = $args['severity'];
		}

		$sql = "SELECT COUNT(*) FROM {$table} WHERE " . implode( ' AND ', $where );
		if ( $params ) {
			return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		}
		return (int) $wpdb->get_var( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery
	}

	public function severity_counts( $status = 'new' ) {
		global $wpdb;
		$table = $this->findings_table();
		$rows  = $wpdb->get_results(
			$wpdb->prepare( "SELECT severity, COUNT(*) as c FROM {$table} WHERE status = %s GROUP BY severity", $status ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);
		return $this->fill_severity_counts( $rows );
	}

	/**
	 * Severity counts for findings that first appeared during the given
	 * run -- what an alert email should mean by "N new issue(s)", as
	 * opposed to every unacknowledged finding ever.
	 */
	public function severity_counts_for_run( $run_id, $run_started_at ) {
		global $wpdb;
		$table = $this->findings_table();
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) as c FROM {$table} WHERE run_id = %d AND status = 'new' AND first_seen >= %s GROUP BY severity", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$run_id,
				$run_started_at
			),
			ARRAY_A
		);
		return $this->fill_severity_counts( $rows );
	}

	private function fill_severity_counts( $rows ) {
		$counts = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'info'     => 0,
		);
		foreach ( (array) $rows as $row ) {
			if ( isset( $counts[ $row['severity'] ] ) ) {
				$counts[ $row['severity'] ] = (int) $row['c'];
			}
		}
		return $counts;
	}

	public function get_finding( $id ) {
		global $wpdb;
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$this->findings_table()} WHERE id = %d", $id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);
	}

	public function set_finding_status( $id, $status ) {
		global $wpdb;
		$wpdb->update( $this->findings_table(), array( 'status' => $status ), array( 'id' => $id ), array( '%s' ), array( '%d' ) );
	}
}

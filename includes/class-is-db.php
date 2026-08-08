<?php
/**
 * Owns the custom tables this plugin needs (scan runs, findings, audit
 * log, quarantine) and the queries against them.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Owns the custom tables this plugin needs. A custom table (rather
 * than options/postmeta) is the right call here because a single scan on
 * a mid-sized site can produce thousands of file-level rows that need to
 * be paginated, filtered by severity/status, and queried efficiently --
 * none of which the options table is built for.
 */
class IS_DB {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * How long a batch lock may be held before another process is allowed
	 * to steal it. Generous because run completion includes remote
	 * checksum-API calls that can legitimately take a couple of minutes
	 * on a plugin-heavy site with a cold cache.
	 */
	const LOCK_TTL = 5 * MINUTE_IN_SECONDS;

	/**
	 * Returns the singleton instance, creating it on first call.
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Hooks the table-version upgrade check into plugins_loaded.
	 */
	private function __construct() {
		add_action( 'plugins_loaded', array( $this, 'maybe_upgrade' ) );
	}

	/**
	 * Fully-qualified name of the scan-runs table.
	 */
	public function runs_table() {
		global $wpdb;
		return $wpdb->prefix . 'is_scan_runs';
	}

	/**
	 * Fully-qualified name of the findings table.
	 */
	public function findings_table() {
		global $wpdb;
		return $wpdb->prefix . 'is_findings';
	}

	/**
	 * Fully-qualified name of the audit-log table.
	 */
	public function audit_table() {
		global $wpdb;
		return $wpdb->prefix . 'is_audit_log';
	}

	/**
	 * Fully-qualified name of the quarantine table.
	 */
	public function quarantine_table() {
		global $wpdb;
		return $wpdb->prefix . 'is_quarantine';
	}

	/**
	 * Fully-qualified name of the file-hashes table (used by the ransomware/mass-defacement velocity check).
	 */
	public function file_hashes_table() {
		global $wpdb;
		return $wpdb->prefix . 'is_file_hashes';
	}

	/**
	 * Creates/updates the custom tables when the stored schema version
	 * doesn't match IS_DB_VERSION.
	 */
	public function maybe_upgrade() {
		if ( get_option( 'is_db_version' ) !== IS_DB_VERSION ) {
			$this->create_tables();
			update_option( 'is_db_version', IS_DB_VERSION, false );
		}
	}

	/**
	 * Creates (or updates, via dbDelta) all five custom tables.
	 */
	public function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate   = $wpdb->get_charset_collate();
		$runs_table        = $this->runs_table();
		$findings_table    = $this->findings_table();
		$audit_table       = $this->audit_table();
		$quarantine_table  = $this->quarantine_table();
		$file_hashes_table = $this->file_hashes_table();

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
			velocity_uploads_changed INT UNSIGNED NOT NULL DEFAULT 0,
			velocity_uploads_total INT UNSIGNED NOT NULL DEFAULT 0,
			velocity_themes_changed INT UNSIGNED NOT NULL DEFAULT 0,
			velocity_themes_total INT UNSIGNED NOT NULL DEFAULT 0,
			velocity_mu_plugins_changed INT UNSIGNED NOT NULL DEFAULT 0,
			velocity_mu_plugins_total INT UNSIGNED NOT NULL DEFAULT 0,
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
		) {$charset_collate};

		CREATE TABLE {$quarantine_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			finding_id BIGINT UNSIGNED NULL,
			original_path VARCHAR(500) NOT NULL,
			quarantine_path VARCHAR(500) NOT NULL,
			file_hash VARCHAR(64) NULL,
			file_size BIGINT UNSIGNED NULL,
			reason TEXT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'quarantined',
			quarantined_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
			quarantined_at DATETIME NOT NULL,
			reviewed_by BIGINT UNSIGNED NULL,
			reviewed_at DATETIME NULL,
			PRIMARY KEY  (id),
			KEY status (status),
			KEY original_path (original_path(191))
		) {$charset_collate};

		CREATE TABLE {$file_hashes_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			file_path VARCHAR(500) NOT NULL,
			hash VARCHAR(64) NOT NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY file_path (file_path(191))
		) {$charset_collate};";

		dbDelta( $sql );
	}

	// ---------------------------------------------------------------
	// Scan run helpers
	// ---------------------------------------------------------------

	/**
	 * Inserts a new scan-run row with status 'running' and returns its id.
	 *
	 * @param string $trigger_type How the run was started (e.g. 'manual', 'cron').
	 */
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

	/**
	 * Fetches a single scan-run row by id.
	 *
	 * @param int $run_id Scan-run id.
	 */
	public function get_run( $run_id ) {
		global $wpdb;
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$this->runs_table()} WHERE id = %d", $run_id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name, not user input
			ARRAY_A
		);
	}

	/**
	 * Fetches the most recently created scan-run row, regardless of status.
	 */
	public function get_latest_run() {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM {$this->runs_table()} ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name, not user input
	}

	/**
	 * Fetches the most recent scan-run row that is currently running, if any.
	 */
	public function get_running_run() {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM {$this->runs_table()} WHERE status = 'running' ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name, not user input; 'running' is a hardcoded literal, not user data
	}

	/**
	 * Fetches the most recently completed scan-run row, if any.
	 */
	public function get_latest_completed_run() {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM {$this->runs_table()} WHERE status = 'completed' ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name, not user input; 'completed' is a hardcoded literal, not user data
	}

	/**
	 * Updates arbitrary columns on a scan-run row, inferring %d/%s formats
	 * from each value's PHP type.
	 *
	 * @param int   $run_id Scan-run id.
	 * @param array $fields Column => value pairs to update.
	 */
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
	 *
	 * @param int   $run_id Scan-run id.
	 * @param array $files  Flat list of relative file paths for this run.
	 */
	public function set_run_files( $run_id, array $files ) {
		$this->update_run( $run_id, array( 'cursor_data' => wp_json_encode( $files ) ) );
	}

	/**
	 * Reads back the file list stored by set_run_files(), tolerating the
	 * older v1 cursor shape.
	 *
	 * @param int $run_id Scan-run id.
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
	 *
	 * @param int $run_id         Scan-run id.
	 * @param int $offset         New cursor offset / files-scanned count.
	 * @param int $findings_delta New findings to add to the running total.
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

	/**
	 * Maps a ransomware-canary scope name to its (changed, total) column pair on the runs table.
	 *
	 * @var array<string,string[]>
	 */
	const VELOCITY_SCOPE_COLUMNS = array(
		'uploads'    => array( 'velocity_uploads_changed', 'velocity_uploads_total' ),
		'themes'     => array( 'velocity_themes_changed', 'velocity_themes_total' ),
		'mu_plugins' => array( 'velocity_mu_plugins_changed', 'velocity_mu_plugins_total' ),
	);

	/**
	 * Atomically increments one scope's changed/total file counters for the
	 * ransomware/mass-defacement velocity check, in SQL (not read-modify-
	 * write in PHP) for the same reason advance_run() does its findings_new
	 * increment in SQL -- concurrent batches can't lose each other's counts.
	 *
	 * @param int    $run_id        Scan-run id.
	 * @param string $scope         One of the keys in VELOCITY_SCOPE_COLUMNS.
	 * @param bool   $file_changed  Whether this file's hash differed from its previously-stored hash.
	 */
	public function increment_velocity_counters( $run_id, $scope, $file_changed ) {
		if ( ! isset( self::VELOCITY_SCOPE_COLUMNS[ $scope ] ) ) {
			return;
		}
		global $wpdb;
		list( $changed_col, $total_col ) = self::VELOCITY_SCOPE_COLUMNS[ $scope ];
		$changed_delta                   = $file_changed ? 1 : 0;
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$this->runs_table()} SET {$changed_col} = {$changed_col} + %d, {$total_col} = {$total_col} + 1 WHERE id = %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- column names come from the fixed VELOCITY_SCOPE_COLUMNS whitelist above, never user input
				$changed_delta,
				$run_id
			)
		);
	}

	/**
	 * Atomically adds $delta to a run's findings_new counter.
	 *
	 * @param int $run_id Scan-run id.
	 * @param int $delta  Amount to add to the running total.
	 */
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
	 *
	 * @param int $run_id Scan-run id.
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

	/**
	 * Releases the advisory batch lock for a run.
	 *
	 * @param int $run_id Scan-run id.
	 */
	public function release_scan_lock( $run_id ) {
		delete_option( 'is_scan_lock_' . (int) $run_id );
	}

	// ---------------------------------------------------------------
	// Findings helpers
	// ---------------------------------------------------------------

	/**
	 * Pure: whether a freshly-matched finding should reuse an existing
	 * row (update in place) rather than insert a new one. new/
	 * acknowledged rows always refresh, as before. An ignored row also
	 * stays reused -- and therefore stays ignored -- as long as the
	 * file's content hasn't actually changed, which is the fix for
	 * "Ignore" not durably suppressing: previously, an ignored finding
	 * for an unchanged file would still spawn a brand-new 'new' row on
	 * the very next scan, because the old matching query excluded
	 * 'ignored' from its WHERE clause entirely. If the content HAS
	 * changed since it was ignored, that's a legitimate reason for
	 * fresh eyes, so a new row is correct in that case.
	 *
	 * @param array $existing Existing finding row from the database.
	 * @param array $incoming Freshly-matched finding data about to be recorded.
	 */
	public static function should_reuse_existing_finding( array $existing, array $incoming ) {
		if ( ! in_array( $existing['status'] ?? '', array( 'new', 'acknowledged', 'ignored' ), true ) ) {
			return false;
		}
		if ( 'ignored' !== $existing['status'] ) {
			return true;
		}

		$existing_hash = (string) ( $existing['file_hash'] ?? '' );
		$incoming_hash = (string) ( $incoming['file_hash'] ?? '' );
		if ( '' === $existing_hash || '' === $incoming_hash ) {
			return true; // No hash to compare (e.g. hardening findings) -- treat as unchanged.
		}
		return $existing_hash === $incoming_hash;
	}

	/**
	 * Upsert a finding: if a still-relevant row for the same file +
	 * issue_type + rule already exists, bump last_seen and refresh the
	 * detail instead of creating a duplicate row every single scan (see
	 * should_reuse_existing_finding() for exactly what counts as
	 * "still-relevant"). rule_id is part of the identity so two
	 * different heuristic rules matching the same file stay two separate
	 * findings rather than overwriting each other.
	 *
	 * @param int   $run_id  Scan-run id this finding was matched during.
	 * @param array $finding Finding data (file_path, issue_type, severity, etc.).
	 */
	public function record_finding( $run_id, array $finding ) {
		global $wpdb;
		$table   = $this->findings_table();
		$now     = current_time( 'mysql' );
		$rule_id = $finding['rule_id'] ?? $finding['issue_type'];

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, status, file_hash FROM {$table} WHERE file_path = %s AND issue_type = %s AND rule_id = %s AND status IN ('new','acknowledged','ignored') ORDER BY id DESC LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$finding['file_path'],
				$finding['issue_type'],
				$rule_id
			),
			ARRAY_A
		);

		if ( $existing && self::should_reuse_existing_finding( $existing, $finding ) ) {
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
			return array(
				'id'     => (int) $existing['id'],
				'is_new' => false,
			);
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
		return array(
			'id'     => (int) $wpdb->insert_id,
			'is_new' => true,
		);
	}

	/**
	 * Findings from a previous run that were NOT re-flagged in the given
	 * run are auto-resolved (the underlying issue is gone -- file fixed,
	 * restored, or deleted). Must only be called after *every* check in
	 * the run (file pass AND checksum passes) has recorded its findings.
	 *
	 * @param int    $run_id                 Scan-run id (unused directly; kept for call-site clarity).
	 * @param string $current_run_started_at MySQL datetime the current run started; findings last seen before this are stale.
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

	// ---------------------------------------------------------------
	// File-hash helpers (ransomware/mass-defacement velocity check)
	// ---------------------------------------------------------------

	/**
	 * Compares $hash against the stored hash for $file_path (if any),
	 * then upserts the new hash. Uniqueness of file_path is enforced
	 * here at the application layer (select-then-upsert), the same way
	 * record_finding() already handles its own VARCHAR(500) identity
	 * column -- a prefix-keyed VARCHAR(500) can't be a true unique/
	 * primary key in InnoDB. Callers already hold the scan batch lock
	 * (see acquire_scan_lock()) for the duration of a run, so this is
	 * already effectively serialized -- no additional locking needed.
	 *
	 * @param string $file_path Path relative to ABSPATH.
	 * @param string $hash      Newly-computed hash for the file.
	 * @return array{is_new:bool,changed:bool}
	 */
	public function check_and_update_file_hash( $file_path, $hash ) {
		global $wpdb;
		$table = $this->file_hashes_table();
		$now   = current_time( 'mysql' );

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, hash FROM {$table} WHERE file_path = %s LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$file_path
			),
			ARRAY_A
		);

		if ( $existing ) {
			$changed = ( (string) $existing['hash'] !== (string) $hash );
			$wpdb->update(
				$table,
				array(
					'hash'       => $hash,
					'updated_at' => $now,
				),
				array( 'id' => $existing['id'] ),
				array( '%s', '%s' ),
				array( '%d' )
			);
			return array(
				'is_new'  => false,
				'changed' => $changed,
			);
		}

		$wpdb->insert(
			$table,
			array(
				'file_path'  => $file_path,
				'hash'       => $hash,
				'updated_at' => $now,
			),
			array( '%s', '%s', '%s' )
		);
		return array(
			'is_new'  => true,
			'changed' => false,
		);
	}

	/**
	 * Removes file-hash rows under any of $scope_prefixes that weren't
	 * touched by the run that started at $run_started_at -- the file was
	 * deleted (or moved out of scope) since the last time it was seen.
	 * Mirrors auto_resolve_stale_findings()'s staleness pattern.
	 *
	 * @param string[] $scope_prefixes Relative-path prefixes (e.g. 'wp-content/uploads/') to prune within.
	 * @param string   $run_started_at MySQL datetime the current run started.
	 */
	public function prune_stale_file_hashes( array $scope_prefixes, $run_started_at ) {
		global $wpdb;
		$table = $this->file_hashes_table();
		foreach ( $scope_prefixes as $prefix ) {
			$prefix = (string) $prefix;
			if ( '' === $prefix ) {
				continue;
			}
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$table} WHERE file_path LIKE %s AND updated_at < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$wpdb->esc_like( $prefix ) . '%',
					$run_started_at
				)
			);
		}
	}

	/**
	 * Paginated, filterable list of findings, ordered by severity then
	 * most-recently-seen.
	 *
	 * @param array $args Optional filters: status, severity, search, limit, offset.
	 */
	public function get_findings( array $args = array() ) {
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
		if ( ! empty( $args['search'] ) ) {
			$where[]  = 'file_path LIKE %s';
			$params[] = '%' . $wpdb->esc_like( $args['search'] ) . '%';
		}

		$limit  = isset( $args['limit'] ) ? (int) $args['limit'] : 50;
		$offset = isset( $args['offset'] ) ? (int) $args['offset'] : 0;

		$sql      = "SELECT * FROM {$table} WHERE " . implode( ' AND ', $where ) . " ORDER BY FIELD(severity,'critical','high','medium','low','info'), last_seen DESC LIMIT %d OFFSET %d";
		$params[] = $limit;
		$params[] = $offset;

		return $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $sql is passed through $wpdb->prepare() with an array of args on the line above; the sniff can't see past the intermediate $sql variable
	}

	/**
	 * Count of findings matching the same filters as get_findings().
	 *
	 * @param array $args Optional filters: status, severity.
	 */
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
			return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $sql is passed through $wpdb->prepare() with an array of args on this same line; the sniff can't see past the intermediate $sql variable
		}
		return (int) $wpdb->get_var( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- no $params to bind (the WHERE clause is empty here), and the only interpolated value is the table name
	}

	/**
	 * Findings count per severity, filtered by status.
	 *
	 * @param string $status Finding status to filter by.
	 */
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
	 *
	 * @param int    $run_id         Scan-run id.
	 * @param string $run_started_at MySQL datetime the run started.
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

	/**
	 * Merges a sparse severity=>count result set into a fixed-shape array
	 * with every severity level present (defaulting to zero).
	 *
	 * @param array $rows Result rows with 'severity' and 'c' (count) keys.
	 */
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

	/**
	 * Fetches a single finding row by id.
	 *
	 * @param int $id Finding id.
	 */
	public function get_finding( $id ) {
		global $wpdb;
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$this->findings_table()} WHERE id = %d", $id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);
	}

	/**
	 * Updates a finding's status.
	 *
	 * @param int    $id     Finding id.
	 * @param string $status New status.
	 */
	public function set_finding_status( $id, $status ) {
		global $wpdb;
		$wpdb->update( $this->findings_table(), array( 'status' => $status ), array( 'id' => $id ), array( '%s' ), array( '%d' ) );
	}

	// ---------------------------------------------------------------
	// Quarantine
	// ---------------------------------------------------------------

	/**
	 * Inserts a new quarantine record and returns its id.
	 *
	 * @param array $record Quarantine data (original_path, quarantine_path, etc.).
	 */
	public function insert_quarantine_record( array $record ) {
		global $wpdb;
		$now = current_time( 'mysql' );
		$wpdb->insert(
			$this->quarantine_table(),
			array(
				'finding_id'      => $record['finding_id'] ?? null,
				'original_path'   => $record['original_path'],
				'quarantine_path' => $record['quarantine_path'],
				'file_hash'       => $record['file_hash'] ?? null,
				'file_size'       => $record['file_size'] ?? null,
				'reason'          => $record['reason'] ?? '',
				'status'          => 'quarantined',
				'quarantined_by'  => $record['quarantined_by'] ?? 0,
				'quarantined_at'  => $now,
			),
			array( '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%d', '%s' )
		);
		return (int) $wpdb->insert_id;
	}

	/**
	 * Fetches a single quarantine record by id.
	 *
	 * @param int $id Quarantine record id.
	 */
	public function get_quarantine_item( $id ) {
		global $wpdb;
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$this->quarantine_table()} WHERE id = %d", $id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);
	}

	/**
	 * Paginated list of quarantine records filtered by status.
	 *
	 * @param string $status Status to filter by.
	 * @param int    $limit  Max rows to return.
	 * @param int    $offset Rows to skip.
	 */
	public function get_quarantine_items( $status = 'quarantined', $limit = 50, $offset = 0 ) {
		global $wpdb;
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$this->quarantine_table()} WHERE status = %s ORDER BY id DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$status,
				max( 1, (int) $limit ),
				max( 0, (int) $offset )
			),
			ARRAY_A
		);
	}

	/**
	 * Count of quarantine records with the given status.
	 *
	 * @param string $status Status to filter by.
	 */
	public function count_quarantine_items( $status = 'quarantined' ) {
		global $wpdb;
		return (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$this->quarantine_table()} WHERE status = %s", $status ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);
	}

	/**
	 * Updates a quarantine record's status and review metadata.
	 *
	 * @param int    $id          Quarantine record id.
	 * @param string $status      New status.
	 * @param int    $reviewed_by User id of the reviewer.
	 */
	public function set_quarantine_status( $id, $status, $reviewed_by ) {
		global $wpdb;
		$wpdb->update(
			$this->quarantine_table(),
			array(
				'status'      => $status,
				'reviewed_by' => $reviewed_by,
				'reviewed_at' => current_time( 'mysql' ),
			),
			array( 'id' => $id ),
			array( '%s', '%d', '%s' ),
			array( '%d' )
		);
	}
}

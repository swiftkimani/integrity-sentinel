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

		$sql = "CREATE TABLE {$runs_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			status VARCHAR(20) NOT NULL DEFAULT 'running',
			trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual',
			started_at DATETIME NOT NULL,
			finished_at DATETIME NULL,
			files_total INT UNSIGNED NOT NULL DEFAULT 0,
			files_scanned INT UNSIGNED NOT NULL DEFAULT 0,
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
		) {$charset_collate};";

		dbDelta( $sql );
	}

	// ---------------------------------------------------------------
	// Scan run helpers
	// ---------------------------------------------------------------

	public function create_run( $trigger_type = 'manual' ) {
		global $wpdb;
		$wpdb->insert(
			$this->runs_table(),
			array(
				'status'       => 'running',
				'trigger_type' => $trigger_type,
				'started_at'   => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s' )
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

	public function update_run( $run_id, array $fields ) {
		global $wpdb;
		$formats = array();
		foreach ( $fields as $key => $value ) {
			$formats[] = is_int( $value ) ? '%d' : '%s';
		}
		$wpdb->update( $this->runs_table(), $fields, array( 'id' => $run_id ), $formats, array( '%d' ) );
	}

	public function set_run_cursor( $run_id, array $cursor ) {
		$this->update_run( $run_id, array( 'cursor_data' => wp_json_encode( $cursor ) ) );
	}

	public function get_run_cursor( $run_id ) {
		$run = $this->get_run( $run_id );
		if ( ! $run || empty( $run['cursor_data'] ) ) {
			return null;
		}
		$decoded = json_decode( $run['cursor_data'], true );
		return is_array( $decoded ) ? $decoded : null;
	}

	// ---------------------------------------------------------------
	// Findings helpers
	// ---------------------------------------------------------------

	/**
	 * Upsert a finding: if the same file + issue_type from a still-open
	 * problem already exists (status new/acknowledged), bump last_seen
	 * and refresh the detail instead of creating a duplicate row every
	 * single scan.
	 */
	public function record_finding( $run_id, array $finding ) {
		global $wpdb;
		$table = $this->findings_table();
		$now   = current_time( 'mysql' );

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, status FROM {$table} WHERE file_path = %s AND issue_type = %s AND status IN ('new','acknowledged') ORDER BY id DESC LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$finding['file_path'],
				$finding['issue_type']
			),
			ARRAY_A
		);

		if ( $existing ) {
			$wpdb->update(
				$table,
				array(
					'run_id'    => $run_id,
					'severity'  => $finding['severity'],
					'rule_id'   => $finding['rule_id'] ?? null,
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
				'rule_id'    => $finding['rule_id'] ?? null,
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
	 * restored, or deleted).
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
		$counts = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'info'     => 0,
		);
		foreach ( $rows as $row ) {
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

<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Every handler here:
 *  - requires manage_options (this is a security tool; a lower-privileged
 *    user should never see or trigger it),
 *  - verifies a nonce scoped to this plugin,
 *  - returns JSON via wp_send_json_success/error rather than echoing
 *    raw output, so there's no way to smuggle extra response content.
 */
class IS_Ajax {

	private static $instance = null;
	const NONCE_ACTION       = 'is_ajax_nonce';

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	private function hooks() {
		add_action( 'wp_ajax_is_start_scan', array( $this, 'start_scan' ) );
		add_action( 'wp_ajax_is_scan_batch', array( $this, 'scan_batch' ) );
		add_action( 'wp_ajax_is_scan_status', array( $this, 'scan_status' ) );
		add_action( 'wp_ajax_is_set_finding_status', array( $this, 'set_finding_status' ) );
		add_action( 'wp_ajax_is_view_finding', array( $this, 'view_finding' ) );
		add_action( 'wp_ajax_is_preview_login_design', array( $this, 'preview_login_design' ) );
	}

	private function guard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'integrity-sentinel' ) ), 403 );
		}
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
	}

	public function start_scan() {
		$this->guard();
		$scanner = new IS_Scanner();
		$run_id  = $scanner->start_run( 'manual' );
		wp_send_json_success( array( 'run_id' => $run_id ) );
	}

	public function scan_batch() {
		$this->guard();
		$run_id = isset( $_POST['run_id'] ) ? (int) $_POST['run_id'] : 0;
		if ( ! $run_id ) {
			wp_send_json_error( array( 'message' => __( 'Missing run id.', 'integrity-sentinel' ) ) );
		}

		// The scanner runs the core/plugin checksum comparisons itself as
		// part of completing the final batch (before auto-resolve and the
		// alert email), and includes their results in the progress array.
		// A 'locked' response means another process (cron, CLI) is driving
		// this run right now -- the JS switches to status polling.
		$scanner  = new IS_Scanner();
		$progress = $scanner->process_batch( $run_id );

		wp_send_json_success( $progress );
	}

	public function scan_status() {
		$this->guard();
		$db  = IS_DB::instance();
		$run = $db->get_running_run();
		if ( ! $run ) {
			wp_send_json_success( array( 'running' => false ) );
		}
		wp_send_json_success(
			array(
				'running'       => true,
				'run_id'        => (int) $run['id'],
				'files_total'   => (int) $run['files_total'],
				'files_scanned' => (int) $run['files_scanned'],
			)
		);
	}

	public function set_finding_status() {
		$this->guard();
		$id     = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
		$status = isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : '';

		if ( ! $id || ! in_array( $status, array( 'acknowledged', 'ignored', 'resolved', 'new' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid request.', 'integrity-sentinel' ) ) );
		}

		$db      = IS_DB::instance();
		$finding = $db->get_finding( $id );
		if ( ! $finding ) {
			wp_send_json_error( array( 'message' => __( 'Finding not found.', 'integrity-sentinel' ) ) );
		}

		$db->set_finding_status( $id, $status );
		IS_Audit_Log::record(
			'finding_status_changed',
			array(
				'finding_id' => $id,
				'file_path'  => $finding['file_path'],
				'from'       => $finding['status'],
				'to'         => $status,
			)
		);
		wp_send_json_success();
	}

	/**
	 * Returns a *safe, read-only* rendering of a finding's context: the
	 * matched snippet only (already captured/escaped at scan time), never
	 * the full file. This deliberately does not offer a raw file-content
	 * viewer -- that would turn an admin-ajax endpoint into a generic
	 * arbitrary-file-read primitive, which is not a trade worth making.
	 */
	public function view_finding() {
		$this->guard();
		$id      = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
		$finding = $id ? IS_DB::instance()->get_finding( $id ) : null;

		if ( ! $finding ) {
			wp_send_json_error( array( 'message' => __( 'Finding not found.', 'integrity-sentinel' ) ) );
		}

		$meta = json_decode( $finding['meta'] ?? '', true );
		wp_send_json_success(
			array(
				'file_path'    => $finding['file_path'],
				'issue_type'   => $finding['issue_type'],
				'severity'     => $finding['severity'],
				'detail'       => $finding['detail'],
				'line'         => $meta['line'] ?? null,
				'snippet'      => $meta['snippet'] ?? null,
				'matches'      => $meta['matches'] ?? null,
				'expected_md5' => $meta['expected_md5'] ?? null,
				'file_hash'    => $finding['file_hash'],
				'first_seen'   => $finding['first_seen'],
				'last_seen'    => $finding['last_seen'],
			)
		);
	}

	/**
	 * Stores a short-lived, per-admin draft of in-progress Login Design
	 * edits so the settings page can open a real preview of wp-login.php
	 * without saving anything yet. Runs the exact same sanitizer the real
	 * save path uses (IS_Admin::sanitize_login_design_input()), so a
	 * preview can never render anything a genuine save wouldn't also
	 * allow -- see IS_Login_Design::preview_override().
	 */
	public function preview_login_design() {
		$this->guard();
		// Same field name/shape the real settings form posts to options.php
		// with, so the JS can hand over a FormData(form) of the in-progress
		// (possibly unsaved) fields verbatim -- see initLoginDesignPreview()
		// in is-admin.js.
		$raw   = isset( $_POST['is_login_design_settings'] ) && is_array( $_POST['is_login_design_settings'] ) ? wp_unslash( $_POST['is_login_design_settings'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitize_login_design_input() below is the sanitizer
		$draft = IS_Admin::instance()->sanitize_login_design_input( $raw, IS_Login_Design::settings() );
		IS_Login_Design::store_preview( $draft );
		wp_send_json_success( array( 'preview_url' => add_query_arg( 'is_preview', '1', wp_login_url() ) ) );
	}
}

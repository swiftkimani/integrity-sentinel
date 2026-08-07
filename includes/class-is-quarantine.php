<?php
/**
 * Quarantine: suspends flagged files (moves them out of harm's way)
 * rather than deleting them, under explicit human control only.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Quarantine, the way this actually needs to work: suspend, don't
 * delete. A flagged file is moved (never copied-and-deleted, never
 * destroyed) into a locked-down directory outside its original
 * location, and stays there until a human explicitly restores it or
 * permanently deletes it. Nothing here ever runs unattended or acts on
 * a schedule -- every state transition is an explicit, nonce-protected,
 * capability-checked admin action, same as IS_Hardening's uploads block.
 *
 * Eligibility is deliberately narrow: only issue types that point at
 * genuinely EXTRA/unexpected files (a heuristic hit, PHP hiding in
 * uploads, an unknown file inside wp-admin/wp-includes or a verified
 * plugin's directory) are quarantinable. 'core_modified' and
 * 'plugin_modified' findings are excluded on purpose -- those point at
 * a file WordPress or a plugin actually needs to run; removing it would
 * be actively harmful, not protective. 'self_integrity' findings
 * (this plugin's own files) are excluded too, for the obvious reason.
 * A small hardcoded path list is checked as well, as defense in depth
 * in case an eligible issue type ever pointed somewhere it shouldn't.
 */
class IS_Quarantine {

	const DIR_NAME    = 'integrity-sentinel-quarantine';
	const BLOCK_BEGIN = '# BEGIN Integrity Sentinel Quarantine';
	const BLOCK_END   = '# END Integrity Sentinel Quarantine';

	const ELIGIBLE_ISSUE_TYPES = array( 'heuristic_match', 'php_in_uploads', 'core_unknown_file', 'plugin_unknown_file' );

	const PROTECTED_RELATIVE_PATHS = array(
		'wp-load.php',
		'wp-config.php',
		'wp-settings.php',
		'wp-blog-header.php',
		'index.php',
	);

	// -------------------------------------------------------------------
	// Pure logic
	// -------------------------------------------------------------------

	/**
	 * Pure: whether a finding's issue type is one this module quarantines.
	 *
	 * @param string $issue_type Finding's issue_type value.
	 * @return bool
	 */
	public static function is_eligible_issue_type( $issue_type ) {
		return in_array( $issue_type, self::ELIGIBLE_ISSUE_TYPES, true );
	}

	/**
	 * Pure: the actual protected-path check, parameterized on the
	 * plugin's own relative directory so it's testable without needing
	 * IS_PLUGIN_DIR/ABSPATH defined.
	 *
	 * @param string $relative_path       Path relative to ABSPATH.
	 * @param string $plugin_relative_dir This plugin's own directory, relative to ABSPATH.
	 * @return bool
	 */
	public static function is_protected_relative_path( $relative_path, $plugin_relative_dir ) {
		$relative_path = ltrim( (string) $relative_path, '/' );
		if ( in_array( $relative_path, self::PROTECTED_RELATIVE_PATHS, true ) ) {
			return true;
		}
		$plugin_relative_dir = trim( (string) $plugin_relative_dir, '/' );
		return '' !== $plugin_relative_dir && 0 === strpos( $relative_path, $plugin_relative_dir . '/' );
	}

	/**
	 * Pure: a collision-resistant quarantine filename -- a timestamp plus
	 * a short hash of the original path, so two files with the same
	 * basename from different directories never collide, and the name
	 * itself carries no clue about the original file. The .quarantined
	 * extension is never executable regardless of server config.
	 *
	 * @param string $relative_path Original path relative to ABSPATH.
	 * @param int    $timestamp     Timestamp to encode in the filename.
	 * @return string
	 */
	public static function quarantine_filename( $relative_path, $timestamp ) {
		return $timestamp . '-' . substr( hash( 'sha256', (string) $relative_path ), 0, 16 ) . '.quarantined';
	}

	// -------------------------------------------------------------------
	// WP-dependent glue
	// -------------------------------------------------------------------

	/**
	 * Whether $relative_path is protected from quarantine (a core
	 * bootstrap file, or something inside this plugin's own directory).
	 *
	 * @param string $relative_path Path relative to ABSPATH.
	 * @return bool
	 */
	public static function is_protected_path( $relative_path ) {
		$plugin_rel = defined( 'IS_PLUGIN_DIR' ) ? IS_File_Walker::relative_to_abspath( IS_PLUGIN_DIR ) : null;
		return self::is_protected_relative_path( $relative_path, null === $plugin_rel ? '' : $plugin_rel );
	}

	/**
	 * Absolute path to this site's quarantine directory (inside uploads).
	 *
	 * @return string
	 */
	public static function quarantine_dir() {
		$uploads = wp_upload_dir();
		return trailingslashit( $uploads['basedir'] ) . self::DIR_NAME;
	}

	/** Deny-all directory protection, created once on first use -- nothing in quarantine should ever be web-accessible. */
	private static function ensure_dir_protected() {
		$dir = self::quarantine_dir();
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$htaccess = trailingslashit( $dir ) . '.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			$rules = self::BLOCK_BEGIN . "\n"
				. "<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n"
				. "<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n"
				. self::BLOCK_END . "\n";
			@file_put_contents( $htaccess, $rules ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- best-effort; quarantine still proceeds (files aren't executable regardless of extension) even if this write fails
		}
		$index = trailingslashit( $dir ) . 'index.php';
		if ( ! file_exists( $index ) ) {
			@file_put_contents( $index, "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- best-effort directory-listing guard
		}
	}

	/**
	 * Moves a flagged file from its original location into quarantine.
	 * Never deletes it -- restore/delete_permanently are separate,
	 * explicit, human-approved actions.
	 *
	 * @param array $finding Finding record being quarantined.
	 * @param int   $user_id ID of the user performing the action.
	 * @return int|WP_Error New quarantine record ID, or WP_Error.
	 */
	public static function quarantine_finding( array $finding, $user_id ) {
		if ( ! self::is_eligible_issue_type( $finding['issue_type'] ?? '' ) ) {
			return new WP_Error( 'is_quarantine_ineligible', __( 'This type of finding cannot be quarantined -- it points at a file the site needs, or that this plugin doesn\'t quarantine.', 'integrity-sentinel' ) );
		}

		$relative = ltrim( (string) ( $finding['file_path'] ?? '' ), '/' );
		if ( '' === $relative || self::is_protected_path( $relative ) ) {
			return new WP_Error( 'is_quarantine_protected', __( 'This file is protected and cannot be quarantined.', 'integrity-sentinel' ) );
		}

		$abs       = trailingslashit( ABSPATH ) . $relative;
		$real_abs  = realpath( $abs );
		$real_root = realpath( ABSPATH );
		if ( false === $real_abs || false === $real_root || 0 !== strpos( $real_abs, $real_root ) || ! is_file( $real_abs ) ) {
			return new WP_Error( 'is_quarantine_missing', __( 'File not found on disk — it may already have been removed or moved.', 'integrity-sentinel' ) );
		}

		self::ensure_dir_protected();
		$filename = self::quarantine_filename( $relative, time() );
		$target   = trailingslashit( self::quarantine_dir() ) . $filename;

		$hash = @hash_file( 'sha256', $real_abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best-effort; recorded if available, quarantine proceeds either way
		$size = @filesize( $real_abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( ! @rename( $real_abs, $target ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- error surfaced below
			return new WP_Error( 'is_quarantine_move_failed', __( 'Could not move the file into quarantine — check filesystem permissions.', 'integrity-sentinel' ) );
		}
		@chmod( $target, 0400 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.chmod_chmod, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- best-effort defense in depth, not load-bearing (the directory is already deny-all); WP_Filesystem isn't guaranteed to be initialized here

		$db = IS_DB::instance();
		$id = $db->insert_quarantine_record(
			array(
				'finding_id'      => $finding['id'] ?? null,
				'original_path'   => $relative,
				'quarantine_path' => $filename,
				'file_hash'       => $hash ? $hash : null,
				'file_size'       => false !== $size ? $size : null,
				'reason'          => $finding['detail'] ?? '',
				'quarantined_by'  => $user_id,
			)
		);

		if ( ! empty( $finding['id'] ) ) {
			$db->set_finding_status( $finding['id'], 'resolved' );
		}

		IS_Audit_Log::record(
			'file_quarantined',
			array(
				'path'          => $relative,
				'quarantine_id' => $id,
			)
		);
		IS_Notifications::instance()->send_event(
			'file_quarantined',
			__( 'A file was quarantined', 'integrity-sentinel' ),
			array(
				sprintf(
					/* translators: %s: file path */
					__( 'File "%s" was moved to quarantine. It has NOT been deleted — review it under Integrity Sentinel → Quarantine and either restore it or permanently delete it.', 'integrity-sentinel' ),
					$relative
				),
			)
		);

		return $id;
	}

	/**
	 * Restores a quarantined file back to its original location.
	 *
	 * @param int $id      Quarantine record ID.
	 * @param int $user_id ID of the user performing the action.
	 * @return true|WP_Error
	 */
	public static function restore( $id, $user_id ) {
		$item = IS_DB::instance()->get_quarantine_item( $id );
		if ( ! $item || 'quarantined' !== $item['status'] ) {
			return new WP_Error( 'is_quarantine_not_found', __( 'Quarantine item not found, or it has already been reviewed.', 'integrity-sentinel' ) );
		}

		$source = trailingslashit( self::quarantine_dir() ) . $item['quarantine_path'];
		$dest   = trailingslashit( ABSPATH ) . $item['original_path'];

		if ( ! file_exists( $source ) ) {
			return new WP_Error( 'is_quarantine_missing', __( 'The quarantined file is missing on disk.', 'integrity-sentinel' ) );
		}
		if ( file_exists( $dest ) ) {
			return new WP_Error( 'is_quarantine_dest_exists', __( 'A file already exists at the original location — remove or rename it first, then try again.', 'integrity-sentinel' ) );
		}
		wp_mkdir_p( dirname( $dest ) );

		if ( ! @rename( $source, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- error surfaced below
			return new WP_Error( 'is_quarantine_move_failed', __( 'Could not restore the file — check filesystem permissions.', 'integrity-sentinel' ) );
		}

		IS_DB::instance()->set_quarantine_status( $id, 'restored', $user_id );
		IS_Audit_Log::record( 'file_restored_from_quarantine', array( 'path' => $item['original_path'] ) );
		IS_Notifications::instance()->send_event(
			'file_restored',
			__( 'A quarantined file was restored', 'integrity-sentinel' ),
			array(
				sprintf(
					/* translators: %s: file path */
					__( 'File "%s" was restored from quarantine to its original location.', 'integrity-sentinel' ),
					$item['original_path']
				),
			)
		);

		return true;
	}

	/**
	 * Permanently deletes a quarantined file from disk.
	 *
	 * @param int $id      Quarantine record ID.
	 * @param int $user_id ID of the user performing the action.
	 * @return true|WP_Error
	 */
	public static function delete_permanently( $id, $user_id ) {
		$item = IS_DB::instance()->get_quarantine_item( $id );
		if ( ! $item || 'quarantined' !== $item['status'] ) {
			return new WP_Error( 'is_quarantine_not_found', __( 'Quarantine item not found, or it has already been reviewed.', 'integrity-sentinel' ) );
		}

		$path = trailingslashit( self::quarantine_dir() ) . $item['quarantine_path'];
		if ( file_exists( $path ) && ! @unlink( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- error surfaced below
			return new WP_Error( 'is_quarantine_delete_failed', __( 'Could not delete the quarantined file — check filesystem permissions.', 'integrity-sentinel' ) );
		}

		IS_DB::instance()->set_quarantine_status( $id, 'deleted', $user_id );
		IS_Audit_Log::record( 'file_deleted_permanently', array( 'path' => $item['original_path'] ) );
		IS_Notifications::instance()->send_event(
			'file_deleted',
			__( 'A quarantined file was permanently deleted', 'integrity-sentinel' ),
			array(
				sprintf(
					/* translators: %s: file path */
					__( 'File "%s" was permanently deleted after human review. If this turns out to be a mistake, it will need to be restored from a backup.', 'integrity-sentinel' ),
					$item['original_path']
				),
			)
		);

		return true;
	}
}

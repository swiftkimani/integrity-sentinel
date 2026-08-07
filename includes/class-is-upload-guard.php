<?php
/**
 * Rejects executable file types at upload time, across the media uploader,
 * plugin/theme install-by-upload, and any importer that routes through
 * wp_handle_upload().
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rejects executable file types at upload time -- the media uploader,
 * plugin/theme install-by-upload, and any importer that routes through
 * wp_handle_upload() all funnel through the one filter hooked here. This
 * is a prevention layer, not a detection one: IS_Heuristics already
 * flags request-data-to-shell_exec()-style code once it lands on disk,
 * this stops an obviously-executable file from landing at all.
 *
 * Matching checks EVERY dot-separated segment of the filename, not just
 * the final extension: "shell.php.jpg" is rejected exactly like
 * "shell.php" is, since some misconfigured multi-extension handler
 * setups (AddHandler-style) execute either. Always on -- this never
 * affects legitimate media (images, documents, archives).
 */
class IS_Upload_Guard {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	const DANGEROUS_EXTENSIONS = array(
		'php',
		'phtml',
		'php2',
		'php3',
		'php4',
		'php5',
		'php7',
		'php8',
		'phar',
		'pht',
		'phps',
		'cgi',
		'pl',
		'py',
		'sh',
		'asp',
		'aspx',
		'exe',
		'dll',
		'jsp',
		'jspx',
	);

	/**
	 * Returns the singleton instance, creating and hooking it up on first call.
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	/**
	 * Wires the upload/sideload prefilters that block dangerous uploads.
	 */
	private function hooks() {
		add_filter( 'wp_handle_upload_prefilter', array( $this, 'block_dangerous_uploads' ) );
		add_filter( 'wp_handle_sideload_prefilter', array( $this, 'block_dangerous_uploads' ) );
	}

	/**
	 * Pure: true if any dot-separated segment of the filename (after the
	 * base name) is a known executable extension.
	 *
	 * @param string $filename Filename to check.
	 */
	public static function filename_has_dangerous_extension( $filename ) {
		$parts = explode( '.', strtolower( (string) $filename ) );
		array_shift( $parts ); // The first segment is the base name, not an extension.
		foreach ( $parts as $ext ) {
			if ( in_array( $ext, self::DANGEROUS_EXTENSIONS, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Filter callback for wp_handle_upload_prefilter/wp_handle_sideload_prefilter:
	 * blocks the upload and logs it if the filename has a dangerous extension.
	 *
	 * @param array $file Upload file array, as passed by wp_handle_upload().
	 */
	public function block_dangerous_uploads( $file ) {
		return IS_Guard::run(
			'upload_guard',
			function () use ( $file ) {
				if ( ! empty( $file['name'] ) && self::filename_has_dangerous_extension( $file['name'] ) ) {
					$file['error'] = __( 'For security, this file type cannot be uploaded.', 'integrity-sentinel' );
					IS_Audit_Log::record( 'dangerous_upload_blocked', array( 'filename' => $file['name'] ) );
				}
				return $file;
			},
			$file
		);
	}
}

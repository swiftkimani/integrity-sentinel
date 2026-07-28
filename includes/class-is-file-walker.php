<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Enumerates files under ABSPATH for the scanner to process.
 *
 * Safety properties that matter here:
 *  - Every path is resolved with realpath() and checked to still live
 *    under ABSPATH before being returned, so a symlink pointing outside
 *    the webroot can't smuggle in arbitrary filesystem paths.
 *  - Exclusions are matched against the path *relative to ABSPATH*, not
 *    the raw pattern, to avoid accidental over-broad matches.
 *  - This class only ever reads file metadata and (elsewhere) file
 *    contents for pattern matching -- it never writes, deletes, or
 *    executes anything it finds.
 */
class IS_File_Walker {

	/** @var string[] */
	private $exclude_patterns;

	public function __construct( array $exclude_patterns = array() ) {
		$this->exclude_patterns = array_filter( array_map( 'trim', $exclude_patterns ) );
	}

	/**
	 * Returns a flat, sorted array of paths *relative to ABSPATH* for
	 * every regular file under the WordPress install, skipping excluded
	 * paths. Sorted so batch-resume-by-index is stable across calls
	 * (assuming the filesystem hasn't changed between them, which is the
	 * same assumption every checksum/integrity scanner makes).
	 */
	public function list_files() {
		$root  = realpath( ABSPATH );
		$paths = array();

		if ( false === $root ) {
			return $paths;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			/** @var SplFileInfo $file */
			if ( ! $file->isFile() ) {
				continue;
			}

			$real = $file->getRealPath();
			if ( false === $real || 0 !== strpos( $real, $root ) ) {
				continue; // symlink escaping the webroot -- skip, don't follow.
			}

			$relative = ltrim( substr( $real, strlen( $root ) ), '/\\' );
			$relative = str_replace( '\\', '/', $relative );

			if ( $this->is_excluded( $relative ) ) {
				continue;
			}

			$paths[] = $relative;
		}

		sort( $paths );
		return $paths;
	}

	private function is_excluded( $relative_path ) {
		foreach ( $this->exclude_patterns as $pattern ) {
			if ( '' === $pattern ) {
				continue;
			}
			// fnmatch gives us simple shell-style globs ("wp-content/uploads/backup*")
			// without needing users to write regex in the settings screen.
			if ( fnmatch( $pattern, $relative_path ) || 0 === strpos( $relative_path, rtrim( $pattern, '/*' ) . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * True if a relative path is inside wp-content/uploads/ -- used by
	 * the scanner to flag executable PHP living somewhere it should
	 * never be (uploads is meant for media, not code).
	 */
	public static function is_in_uploads( $relative_path ) {
		$uploads   = wp_upload_dir();
		$abs_root  = realpath( ABSPATH );
		$abs_upload = realpath( $uploads['basedir'] );
		if ( false === $abs_root || false === $abs_upload ) {
			return false;
		}
		$relative_uploads = ltrim( substr( $abs_upload, strlen( $abs_root ) ), '/\\' );
		$relative_uploads = str_replace( '\\', '/', $relative_uploads );
		return 0 === strpos( $relative_path, $relative_uploads . '/' );
	}
}

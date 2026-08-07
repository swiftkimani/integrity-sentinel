<?php
/**
 * Enumerates files under ABSPATH for the scanner to process.
 *
 * @package Integrity_Sentinel
 */

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

	/**
	 * Shell-style glob patterns (relative to ABSPATH) to skip.
	 *
	 * @var string[]
	 */
	private $exclude_patterns;

	/**
	 * Constructor.
	 *
	 * @param string[] $exclude_patterns Shell-style glob patterns (relative to ABSPATH) to skip.
	 */
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
		$root = realpath( ABSPATH );
		if ( false === $root ) {
			return array();
		}
		return $this->collect( $root, $root );
	}

	/**
	 * Same as list_files() but limited to one subtree (e.g. wp-includes,
	 * or a single plugin directory). Paths are still returned relative to
	 * ABSPATH so they slot straight into findings and exclusion checks.
	 * Returns an empty array if the directory resolves outside ABSPATH.
	 *
	 * @param string $abs_dir Absolute path to the subtree to walk.
	 */
	public function list_files_under( $abs_dir ) {
		$root = realpath( ABSPATH );
		$dir  = ( is_string( $abs_dir ) && '' !== $abs_dir ) ? realpath( $abs_dir ) : false;
		if ( false === $root || false === $dir || 0 !== strpos( $dir, $root ) ) {
			return array();
		}
		return $this->collect( $dir, $root );
	}

	/**
	 * Recursively walks $start_dir and returns ABSPATH-relative paths for
	 * every regular, non-excluded file, skipping anything that resolves
	 * (via symlink) outside of $root.
	 *
	 * @param string $start_dir Absolute path to start walking from.
	 * @param string $root      Absolute path every resolved file must live under.
	 */
	private function collect( $start_dir, $root ) {
		$paths = array();

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $start_dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST,
				RecursiveIteratorIterator::CATCH_GET_CHILD // unreadable subdirectory: skip it, don't abort the whole walk.
			);

			foreach ( $iterator as $file ) {
				/** Current directory entry. @var SplFileInfo $file */
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
		} catch ( UnexpectedValueException $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch -- intentionally a no-op: the start directory itself was unreadable, return what we have.
			// The start directory itself was unreadable; return what we have.
		}

		sort( $paths );
		return $paths;
	}

	/**
	 * Whether a relative path matches one of the configured exclude patterns.
	 *
	 * @param string $relative_path Path relative to ABSPATH.
	 */
	public function is_excluded( $relative_path ) {
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
	 * Resolves an absolute path to its ABSPATH-relative form, or null if
	 * it doesn't resolve inside the webroot.
	 *
	 * @param string $abs_path Absolute filesystem path to resolve.
	 */
	public static function relative_to_abspath( $abs_path ) {
		$root = realpath( ABSPATH );
		$real = ( is_string( $abs_path ) && '' !== $abs_path ) ? realpath( $abs_path ) : false;
		if ( false === $root || false === $real || 0 !== strpos( $real, $root ) ) {
			return null;
		}
		return str_replace( '\\', '/', ltrim( substr( $real, strlen( $root ) ), '/\\' ) );
	}

	/**
	 * True if a relative path is inside wp-content/uploads/ -- used by
	 * the scanner to flag executable PHP living somewhere it should
	 * never be (uploads is meant for media, not code).
	 *
	 * @param string $relative_path Path relative to ABSPATH.
	 */
	public static function is_in_uploads( $relative_path ) {
		$uploads          = wp_upload_dir();
		$relative_uploads = self::relative_to_abspath( $uploads['basedir'] );
		if ( null === $relative_uploads ) {
			return false;
		}
		return 0 === strpos( $relative_path, $relative_uploads . '/' );
	}
}

<?php
/**
 * Mass file-change velocity detection (a "ransomware canary") for the
 * parts of a WordPress install that have no checksum-based drift
 * detection at all: uploads, themes, and mu-plugins.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Not to be confused with IS_Deception's unrelated "canary token"
 * honeypot feature -- this is a velocity/anomaly detector, no token or
 * trap involved.
 *
 * WordPress core files and any WordPress.org-hosted plugin are already
 * verified against official checksums, so a mass-change alarm there
 * would just be noisy/redundant with legitimate core or plugin updates.
 * But there is no equivalent for wp-content/uploads, wp-content/themes,
 * or wp-content/mu-plugins -- content and custom/uploaded code that has
 * no known-good baseline to diff against. This tracks a per-file hash
 * for that surface only, and flags an abrupt, large-scale change
 * (most of the tree flipping content between two scans) as a strong
 * ransomware/mass-defacement signal -- legitimate churn there is mostly
 * *additions*, which dilute a changed/total ratio rather than count
 * toward it, whereas mass encryption or defacement rewrites the content
 * of a large majority of already-existing files essentially at once.
 */
class IS_Ransomware_Canary {

	/**
	 * Default settings for this module. Local-only, no API key, so on
	 * by default (like the heuristics scanner) rather than opt-in
	 * (like an external-API integration).
	 */
	public static function default_settings() {
		return array(
			'enabled'              => 1,
			'threshold_ratio'      => 0.5,
			'min_files_uploads'    => 50,
			'min_files_themes'     => 15,
			'min_files_mu_plugins' => 3,
		);
	}

	/**
	 * Current settings, merged over the defaults.
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_ransomware_canary_settings', array() ), self::default_settings() );
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: the fraction of $total files that changed. 0.0 if $total is 0 or negative.
	 *
	 * @param int $changed Number of files whose hash differed from last scan.
	 * @param int $total   Total in-scope files hashed this scan.
	 */
	public static function changed_ratio( $changed, $total ) {
		$total = (int) $total;
		if ( $total <= 0 ) {
			return 0.0;
		}
		return (float) max( 0, (int) $changed ) / $total;
	}

	/**
	 * Pure: is $ratio alarming for this scope? False outright if $total
	 * hasn't reached $min_files yet -- a 3-file directory going 2/3
	 * "changed" is noise, not a signal, regardless of ratio.
	 *
	 * @param float $ratio     changed_ratio() output.
	 * @param int   $total     Total in-scope files hashed this scan.
	 * @param int   $min_files Minimum file count before evaluating this scope at all.
	 * @param float $threshold Ratio at/above which the change is considered alarming.
	 */
	public static function is_velocity_alarming( $ratio, $total, $min_files, $threshold ) {
		if ( (int) $total < (int) $min_files ) {
			return false;
		}
		return (float) $ratio >= (float) $threshold;
	}

	/**
	 * Pure: which scope (if any) $relative_path falls under, given a
	 * map of scope => ABSPATH-relative prefix. Prefixes come from
	 * scope_prefixes(); an empty prefix (e.g. no mu-plugins directory
	 * on this install) never matches.
	 *
	 * @param string                $relative_path Path relative to ABSPATH.
	 * @param array<string,?string> $prefixes      Scope name => relative prefix (or null/'' if not applicable).
	 * @return string|null Scope name, or null if not in any tracked scope.
	 */
	public static function classify_scope( $relative_path, array $prefixes ) {
		$relative_path = (string) $relative_path;
		foreach ( $prefixes as $scope => $prefix ) {
			$prefix = (string) $prefix;
			if ( '' === $prefix ) {
				continue;
			}
			if ( 0 === strpos( $relative_path, rtrim( $prefix, '/' ) . '/' ) ) {
				return $scope;
			}
		}
		return null;
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * ABSPATH-relative path prefixes for each tracked scope, resolved
	 * from the current install's actual directory layout. A scope whose
	 * directory doesn't exist on this install (e.g. no mu-plugins)
	 * resolves to null via IS_File_Walker::relative_to_abspath(), which
	 * classify_scope() treats as "never matches".
	 *
	 * @return array{uploads:?string,themes:?string,mu_plugins:?string}
	 */
	public static function scope_prefixes() {
		$uploads = wp_upload_dir();
		return array(
			'uploads'    => IS_File_Walker::relative_to_abspath( $uploads['basedir'] ),
			'themes'     => IS_File_Walker::relative_to_abspath( WP_CONTENT_DIR . '/themes' ),
			'mu_plugins' => IS_File_Walker::relative_to_abspath( WP_CONTENT_DIR . '/mu-plugins' ),
		);
	}
}

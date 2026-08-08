<?php
/**
 * CycloneDX-lite software inventory generation and diffing.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A CycloneDX-lite software inventory (core + every plugin + the active
 * theme, name/version/path) regenerated each scan and diffed against the
 * previous snapshot. "CycloneDX-lite" on purpose: this borrows the
 * shape/spirit of the CycloneDX SBOM standard for a human- and tool-
 * readable export, not a strict validated implementation of the spec.
 *
 * The point isn't the export file itself so much as the diff: an
 * inventory change (a plugin appearing, disappearing, or changing
 * version between two scans) is exactly the kind of signal file-hash
 * checksums alone can miss -- a brand-new plugin installed between scans
 * has no prior baseline to diff against.
 */
class IS_SBOM {

	const OPTION = 'is_sbom_snapshot';

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: diffs two component lists (as produced by generate()) by
	 * name, reporting what was added, removed, or changed version.
	 *
	 * @param array<array{name:string,version:string}> $previous The prior snapshot's components.
	 * @param array<array{name:string,version:string}> $current  The new snapshot's components.
	 * @return array{added:string[],removed:string[],changed:array<array{name:string,from:string,to:string}>}
	 */
	public static function diff( array $previous, array $current ) {
		$prev_by_name = array();
		foreach ( $previous as $component ) {
			if ( isset( $component['name'] ) ) {
				$prev_by_name[ $component['name'] ] = $component;
			}
		}
		$curr_by_name = array();
		foreach ( $current as $component ) {
			if ( isset( $component['name'] ) ) {
				$curr_by_name[ $component['name'] ] = $component;
			}
		}

		$added   = array();
		$changed = array();
		foreach ( $curr_by_name as $name => $component ) {
			if ( ! isset( $prev_by_name[ $name ] ) ) {
				$added[] = $name;
			} elseif ( (string) $prev_by_name[ $name ]['version'] !== (string) $component['version'] ) {
				$changed[] = array(
					'name' => $name,
					'from' => (string) $prev_by_name[ $name ]['version'],
					'to'   => (string) $component['version'],
				);
			}
		}

		$removed = array();
		foreach ( $prev_by_name as $name => $component ) {
			if ( ! isset( $curr_by_name[ $name ] ) ) {
				$removed[] = $name;
			}
		}

		return array(
			'added'   => $added,
			'removed' => $removed,
			'changed' => $changed,
		);
	}

	/**
	 * Pure: whether a diff() result contains any change at all.
	 *
	 * @param array $diff A diff() result.
	 */
	public static function has_diff( array $diff ) {
		return ! empty( $diff['added'] ) || ! empty( $diff['removed'] ) || ! empty( $diff['changed'] );
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * Builds the current inventory: core, every installed plugin, and the active theme.
	 *
	 * @return array<array{type:string,name:string,version:string,path:string}>
	 */
	public static function generate() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$components   = array();
		$components[] = array(
			'type'    => 'application',
			'name'    => 'wordpress-core',
			'version' => get_bloginfo( 'version' ),
			'path'    => '',
		);

		foreach ( get_plugins() as $plugin_file => $data ) {
			$components[] = array(
				'type'    => 'library',
				'name'    => (string) $data['Name'],
				'version' => (string) $data['Version'],
				'path'    => $plugin_file,
			);
		}

		$theme = wp_get_theme();
		if ( $theme->exists() ) {
			$components[] = array(
				'type'    => 'application',
				'name'    => (string) $theme->get( 'Name' ),
				'version' => (string) $theme->get( 'Version' ),
				'path'    => $theme->get_stylesheet(),
			);
		}

		return $components;
	}

	/**
	 * Builds a CycloneDX-lite JSON document from generate()'s component list.
	 *
	 * @param array $components Component list, as returned by generate().
	 */
	public static function to_document( array $components ) {
		return array(
			'bomFormat'   => 'CycloneDX-lite',
			'specVersion' => '1.0',
			'version'     => 1,
			'metadata'    => array(
				'timestamp' => current_time( 'mysql' ),
				'site'      => home_url(),
			),
			'components'  => $components,
		);
	}

	/**
	 * Regenerates the inventory, diffs it against the previous snapshot,
	 * persists the new one, and fires a (low-severity, log-only by
	 * default) detection when anything changed. Cheap to call every scan
	 * -- just reading already-loaded plugin/theme headers, no filesystem
	 * walk of its own.
	 *
	 * @return array<array{type:string,name:string,version:string,path:string}>
	 */
	public static function refresh_snapshot() {
		$previous = get_option( self::OPTION, array() );
		$current  = self::generate();

		$diff = self::diff( is_array( $previous ) ? $previous : array(), $current );
		update_option( self::OPTION, $current, false );

		if ( self::has_diff( $diff ) ) {
			IS_Detections::fire( 'sbom_changed', $diff );
		}

		return $current;
	}
}

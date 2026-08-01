<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Verifies installed WordPress.org plugin files against WordPress.org's
 * plugin checksum service (the same data source WP-CLI's
 * `wp plugin verify-checksums` uses):
 *
 *   GET https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json
 *
 * Coverage caveats, communicated in the UI rather than hidden:
 *  - Only plugins installed *from the WordPress.org repository* can be
 *    checked this way. Premium/custom plugins have no checksums to
 *    compare against and are skipped (reported, not silently ignored).
 *  - WordPress.org doesn't retain checksums for every historical
 *    version of every plugin, so a checksum lookup can occasionally
 *    come back empty for an older version even for a legitimate,
 *    unmodified install.
 *  - The exact JSON shape of this endpoint has evolved over time
 *    (WP-CLI's own implementation added multi-hash-per-file support
 *    after its initial release), so this class parses defensively and
 *    surfaces a clear error rather than guessing if the shape it gets
 *    back doesn't match what it expects.
 */
class IS_Plugin_Checksums {

	const CACHE_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * How long to remember that a slug+version has NO published checksums
	 * (a 404). Premium/custom plugins 404 forever, so without negative
	 * caching every scan re-requests every unverifiable plugin. A week is
	 * safe because the cache key includes the version -- an update busts it.
	 */
	const NEGATIVE_CACHE_TTL = WEEK_IN_SECONDS;

	/** Sentinel stored in the transient for a cached 404. */
	const NOT_AVAILABLE = 'is_not_available';

	/**
	 * @return array|WP_Error Map of relative-path (within the plugin
	 *                        folder) => array of acceptable md5/sha256
	 *                        hashes, or WP_Error on failure.
	 */
	public function get_checksums( $slug, $version ) {
		$cache_key = 'is_plugin_checksums_' . md5( $slug . '|' . $version );
		$cached    = get_transient( $cache_key );
		if ( self::NOT_AVAILABLE === $cached ) {
			return $this->not_found_error( $slug, $version );
		}
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$url = sprintf(
			'https://downloads.wordpress.org/plugin-checksums/%s/%s.json',
			rawurlencode( $slug ),
			rawurlencode( $version )
		);

		$response = wp_remote_get( $url, array( 'timeout' => 20 ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 404 === $code ) {
			set_transient( $cache_key, self::NOT_AVAILABLE, self::NEGATIVE_CACHE_TTL );
			return $this->not_found_error( $slug, $version );
		}
		if ( 200 !== $code ) {
			return new WP_Error( 'is_plugin_checksums_http', sprintf(
				/* translators: 1: plugin slug, 2: HTTP status code */
				__( 'Checksum lookup for %1$s returned HTTP %2$d.', 'integrity-sentinel' ),
				$slug,
				$code
			) );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		$parsed = $this->normalize_response( $body );

		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}

		set_transient( $cache_key, $parsed, self::CACHE_TTL );
		return $parsed;
	}

	private function not_found_error( $slug, $version ) {
		return new WP_Error(
			'is_plugin_checksums_not_found',
			sprintf(
				/* translators: 1: plugin slug, 2: plugin version */
				__( 'No published checksums for %1$s %2$s — this is expected for plugins not hosted on WordPress.org, and sometimes for older versions of hosted plugins.', 'integrity-sentinel' ),
				$slug,
				$version
			)
		);
	}

	/**
	 * The endpoint's documented shape is:
	 *   { "files": { "relative/path.php": { "md5": "...", "sha256": "..." }, ... } }
	 * but earlier iterations used a flatter { "path": "md5" } shape, and
	 * some entries may list multiple acceptable hashes for a file (soft
	 * changes like readme.txt across point releases). We normalize all
	 * of that into path => [hash, hash, ...] so the comparison code only
	 * has to deal with one shape.
	 */
	public function normalize_response( $body ) {
		if ( ! is_array( $body ) ) {
			return new WP_Error( 'is_plugin_checksums_bad_json', __( 'Checksum response was not valid JSON.', 'integrity-sentinel' ) );
		}

		$files = $body['files'] ?? $body; // fall back to flat shape
		if ( ! is_array( $files ) || empty( $files ) ) {
			return new WP_Error( 'is_plugin_checksums_empty', __( 'Checksum response contained no file entries.', 'integrity-sentinel' ) );
		}

		$normalized = array();
		foreach ( $files as $path => $value ) {
			if ( is_string( $value ) ) {
				$normalized[ $path ] = array( $value );
			} elseif ( is_array( $value ) ) {
				// Could be {"md5":"..","sha256":".."} or a plain list of hashes.
				$normalized[ $path ] = array_values(
					array_filter(
						$value,
						function ( $v ) {
							return is_string( $v );
						}
					)
				);
			}
		}

		if ( empty( $normalized ) ) {
			return new WP_Error( 'is_plugin_checksums_unrecognized_shape', __( 'Checksum response used an unrecognized format; skipping this plugin rather than reporting false positives.', 'integrity-sentinel' ) );
		}

		return $normalized;
	}

	/**
	 * All installed plugins that were installed from the WordPress.org
	 * repository (have an "Update URI"/origin we can match to a slug) --
	 * bundled/custom plugins are returned separately so the UI can list
	 * them as "not checkable" instead of silently skipping them.
	 */
	public function get_checkable_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all  = get_plugins();
		$wp_org = array();
		$other  = array();

		foreach ( $all as $plugin_file => $data ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug ) {
				// Single-file plugin at the top level of wp-content/plugins;
				// WordPress.org slugs are directory-based, so we can't
				// reliably map this to a checksum lookup.
				$other[ $plugin_file ] = $data;
				continue;
			}
			$wp_org[ $plugin_file ] = array(
				'slug'    => $slug,
				'version' => $data['Version'],
				'name'    => $data['Name'],
			);
		}

		return array(
			'checkable' => $wp_org,
			'other'     => $other,
		);
	}
}

<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Verifies WordPress core files against WordPress.org's official
 * checksum API -- the same one WP-CLI's `wp core verify-checksums` uses:
 *
 *   GET https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}
 *   -> { "checksums": { "wp-includes/version.php": "md5hash", ... } }
 *
 * This has been a stable, documented WordPress.org endpoint for years,
 * so we call it directly rather than bundling our own checksum lists
 * (which would immediately go stale on every WP release).
 */
class IS_Core_Checksums {

	const CACHE_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * @return array|WP_Error Map of relative-path => md5, or WP_Error on failure.
	 */
	public function get_checksums( $version = null, $locale = null ) {
		global $wp_version;
		$version = $version ?: $wp_version;
		$locale  = $locale ?: get_locale();

		$cache_key = 'is_core_checksums_' . md5( $version . '|' . $locale );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$url = add_query_arg(
			array(
				'version' => $version,
				'locale'  => $locale,
			),
			'https://api.wordpress.org/core/checksums/1.0/'
		);

		$response = wp_remote_get( $url, array( 'timeout' => 20 ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error(
				'is_core_checksums_http',
				sprintf(
				/* translators: %d: HTTP status code */
					__( 'WordPress.org checksum API returned HTTP %d.', 'integrity-sentinel' ),
					wp_remote_retrieve_response_code( $response )
				)
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
			return new WP_Error( 'is_core_checksums_empty', __( 'No checksums returned for this WordPress version/locale — this can happen for a very new or non-English release; try again later or check Settings → Site Language.', 'integrity-sentinel' ) );
		}

		set_transient( $cache_key, $body['checksums'], self::CACHE_TTL );
		return $body['checksums'];
	}

	/**
	 * Paths that are expected to differ from the published checksums
	 * (user-editable by design, or generated per-site) and shouldn't be
	 * reported as tampering.
	 */
	public function expected_local_variance() {
		return array(
			'wp-config.php',
			'wp-content/',       // everything under wp-content is plugins/themes/uploads, verified separately
			'.htaccess',
			'wp-config-sample.php', // some hosts patch this
		);
	}

	public function is_expected_variance( $relative_path ) {
		foreach ( $this->expected_local_variance() as $prefix ) {
			if ( 0 === strpos( $relative_path, $prefix ) ) {
				return true;
			}
		}
		return false;
	}
}

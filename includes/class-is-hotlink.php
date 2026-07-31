<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hotlink protection for the uploads directory. Static image requests
 * never go through PHP/WordPress at all (the webserver serves them
 * directly), so -- exactly like IS_Hardening's PHP-execution block --
 * this can only be enforced by writing a marker-delimited rule block
 * into uploads/.htaccess (Apache/LiteSpeed) and showing the nginx
 * equivalent for manual setup. Uses its own BEGIN/END markers so it can
 * coexist independently of the exec-block written by IS_Hardening.
 */
class IS_Hotlink {

	const BLOCK_BEGIN = '# BEGIN Integrity Sentinel Hotlink Protection';
	const BLOCK_END   = '# END Integrity Sentinel Hotlink Protection';
	const EXTENSIONS  = 'jpe?g|png|gif|webp|svg|bmp|ico';

	public static function default_settings() {
		return array( 'allowed_domains' => '' );
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_hotlink_settings', array() ), self::default_settings() );
	}

	/**
	 * Pure: parses a textarea's worth of domains, one per line. Tolerates
	 * a pasted full URL (strips scheme and any path) and "# note" comments.
	 *
	 * @return string[]
	 */
	public static function parse_domain_list( $text ) {
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $text ) as $line ) {
			$line = trim( preg_replace( '/#.*$/', '', $line ) );
			$line = preg_replace( '#^https?://#i', '', $line );
			$line = rtrim( strtok( $line, '/' ), '/' );
			if ( '' !== $line ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	/**
	 * Pure: the Apache rule block for a given home host + allowed
	 * domains list. Empty referers are always allowed (direct access,
	 * many browsers/apps, feed readers, and RSS/social-share previews
	 * that strip the referer) -- this blocks cross-SITE embedding, not
	 * anonymous access.
	 */
	public static function block_rules( $home_host, array $allowed_domains ) {
		$hosts         = array_map(
			function ( $host ) {
				return preg_quote( $host, '#' );
			},
			array_merge( array( $home_host ), $allowed_domains )
		);
		$hosts_pattern = implode( '|', array_filter( $hosts ) );

		return self::BLOCK_BEGIN . "\n"
			. "<IfModule mod_rewrite.c>\n"
			. "\tRewriteEngine On\n"
			. "\tRewriteCond %{HTTP_REFERER} !^$\n"
			. "\tRewriteCond %{HTTP_REFERER} !^https?://(?:www\\.)?(?:{$hosts_pattern})(?:/.*)?$ [NC]\n"
			. "\tRewriteRule \\.(?:" . self::EXTENSIONS . ')$ - [F,NC,L]' . "\n"
			. "</IfModule>\n"
			. self::BLOCK_END . "\n";
	}

	public static function nginx_snippet( $home_host, array $allowed_domains ) {
		$valid = array_merge( array( $home_host ), $allowed_domains );
		return 'location ~* \\.(' . self::EXTENSIONS . ") {\n"
			. "\tvalid_referers none blocked " . implode( ' ', $valid ) . ";\n"
			. "\tif (\$invalid_referer) {\n\t\treturn 403;\n\t}\n"
			. '}';
	}

	public static function htaccess_path() {
		$uploads = wp_upload_dir();
		return trailingslashit( $uploads['basedir'] ) . '.htaccess';
	}

	public static function active() {
		$path = self::htaccess_path();
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return false;
		}
		return false !== strpos( (string) file_get_contents( $path ), self::BLOCK_BEGIN ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	}

	/** @return true|WP_Error */
	public static function apply() {
		if ( self::active() ) {
			return true;
		}
		$home_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$allowed   = self::parse_domain_list( self::settings()['allowed_domains'] );

		$path     = self::htaccess_path();
		$existing = file_exists( $path ) ? (string) file_get_contents( $path ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$content  = rtrim( $existing );
		$content  = ( '' === $content ? '' : $content . "\n\n" ) . self::block_rules( $home_host, $allowed );

		if ( false === @file_put_contents( $path, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- single well-known file, error surfaced below
			return new WP_Error( 'is_htaccess_unwritable', __( 'Could not write the uploads .htaccess file — check directory permissions.', 'integrity-sentinel' ) );
		}
		IS_Audit_Log::record( 'hotlink_block_applied', array() );
		return true;
	}

	/** @return true|WP_Error */
	public static function remove() {
		if ( ! self::active() ) {
			return true;
		}
		$path    = self::htaccess_path();
		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$pattern = '/\n?' . preg_quote( self::BLOCK_BEGIN, '/' ) . '.*?' . preg_quote( self::BLOCK_END, '/' ) . '\n?/s';
		$content = trim( (string) preg_replace( $pattern, '', $content ) );

		$written = ( '' === $content )
			? @unlink( $path ) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- removing a now-empty file we created
			: ( false !== @file_put_contents( $path, $content . "\n" ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents

		if ( ! $written ) {
			return new WP_Error( 'is_htaccess_unwritable', __( 'Could not update the uploads .htaccess file — check directory permissions.', 'integrity-sentinel' ) );
		}
		IS_Audit_Log::record( 'hotlink_block_removed', array() );
		return true;
	}

	/**
	 * Regenerates the rule block from current settings if it's currently
	 * active, so editing the allowed-domains list doesn't leave a stale
	 * block in place with the old domains.
	 */
	public static function reapply_if_active() {
		if ( self::active() ) {
			self::remove();
			self::apply();
		}
	}
}

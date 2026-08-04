<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Optional, off-by-default: rewrites every front-end-visible URL this
 * plugin can reach (enqueued scripts/styles, uploads, theme/plugin asset
 * URLs) from /wp-content/ and /wp-includes/ to an admin-chosen alias, so
 * viewing page source or a browser's Sources panel doesn't immediately
 * read "this is WordPress" the way a literal wp-content path does.
 *
 * This is the riskiest thing this plugin writes to disk: unlike every
 * other opt-in feature here, IS_SAFE_MODE cannot undo it. Safe mode
 * stops the WordPress-level URL-rewriting filters (so freshly-rendered
 * pages go back to real wp-content URLs), but it has no effect on the
 * root .htaccess rule that makes the disguised URLs actually resolve to
 * real files -- that's a static file the web server reads independently
 * of whether WordPress can even boot. If something looks wrong after
 * enabling this, use the "Remove" button on this page (which undoes
 * both halves) rather than relying on safe mode alone; the true fallback
 * if the site becomes unreachable is a manual FTP/SSH edit of the root
 * .htaccess, same as for any hand-written rewrite rule.
 *
 * Also worth knowing going in: a theme or plugin that hardcodes literal
 * "/wp-content/..." paths instead of building them through WordPress's
 * own URL functions won't be caught by these filters -- this reduces
 * the wp-content/wp-includes fingerprint, it does not guarantee it
 * never appears anywhere on the site.
 */
class IS_Asset_Cloak {

	private static $instance = null;

	const BLOCK_BEGIN = '# BEGIN Integrity Sentinel Asset Cloak';
	const BLOCK_END   = '# END Integrity Sentinel Asset Cloak';

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	public static function default_settings() {
		return array(
			'enabled' => 0,
			'alias'   => '',
		);
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_asset_cloak_settings', array() ), self::default_settings() );
	}

	private function hooks() {
		add_filter( 'style_loader_src', array( $this, 'filter_url' ) );
		add_filter( 'script_loader_src', array( $this, 'filter_url' ) );
		add_filter( 'content_url', array( $this, 'filter_url' ) );
		add_filter( 'plugins_url', array( $this, 'filter_url' ) );
		add_filter( 'stylesheet_directory_uri', array( $this, 'filter_url' ) );
		add_filter( 'template_directory_uri', array( $this, 'filter_url' ) );
		add_filter( 'upload_dir', array( $this, 'filter_upload_dir' ) );
	}

	// ===================================================================
	// Pure logic
	// ===================================================================

	/**
	 * Pure: normalizes a raw admin-entered alias down to safe characters
	 * and rejects anything that would collide with a literal WordPress
	 * core path.
	 */
	public static function sanitize_alias( $raw ) {
		$alias = strtolower( trim( (string) $raw ) );
		$alias = trim( $alias, '/' );
		$alias = preg_replace( '/[^a-z0-9\-]/', '', $alias );

		if ( null === $alias || '' === $alias ) {
			return '';
		}

		$reserved = array( 'wp', 'wp-content', 'wp-includes', 'wp-admin', 'content', 'includes', 'admin', 'wp-json', 'wp-login' );
		return in_array( $alias, $reserved, true ) ? '' : $alias;
	}

	/**
	 * Pure: rewrites a wp-content/wp-includes URL to use the alias
	 * instead. Only touches URLs on the site's own host (an explicit
	 * host that doesn't match $site_host is left untouched) -- a
	 * relative/protocol-relative/host-less URL is treated as same-host,
	 * since that's what it resolves to in a browser.
	 */
	public static function rewrite_asset_url( $url, $alias, $site_host ) {
		if ( '' === $alias || '' === $site_host || ! is_string( $url ) || '' === $url ) {
			return $url;
		}

		$parsed   = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- pure/no-WP-dependency by design, see class docblock
		$url_host = isset( $parsed['host'] ) ? $parsed['host'] : '';
		if ( '' !== $url_host && strtolower( $url_host ) !== strtolower( $site_host ) ) {
			return $url;
		}

		$url = str_replace( '/wp-content/', "/{$alias}-content/", $url );
		$url = str_replace( '/wp-includes/', "/{$alias}-includes/", $url );
		return $url;
	}

	// ===================================================================
	// WordPress glue
	// ===================================================================

	private function site_host() {
		static $host = null;
		if ( null === $host ) {
			$parsed = wp_parse_url( home_url() );
			$host   = isset( $parsed['host'] ) ? $parsed['host'] : '';
		}
		return $host;
	}

	public function filter_url( $url ) {
		return IS_Guard::run(
			'asset_cloak',
			function () use ( $url ) {
				$settings = self::settings();
				if ( empty( $settings['enabled'] ) || '' === $settings['alias'] ) {
					return $url;
				}
				return self::rewrite_asset_url( $url, $settings['alias'], $this->site_host() );
			},
			$url
		);
	}

	public function filter_upload_dir( $uploads ) {
		return IS_Guard::run(
			'asset_cloak',
			function () use ( $uploads ) {
				$settings = self::settings();
				if ( empty( $settings['enabled'] ) || '' === $settings['alias'] || ! is_array( $uploads ) ) {
					return $uploads;
				}
				foreach ( array( 'url', 'baseurl' ) as $key ) {
					if ( isset( $uploads[ $key ] ) ) {
						$uploads[ $key ] = self::rewrite_asset_url( $uploads[ $key ], $settings['alias'], $this->site_host() );
					}
				}
				return $uploads;
			},
			$uploads
		);
	}

	// ===================================================================
	// .htaccess (Apache) -- see class docblock for the ordering rationale
	// ===================================================================

	public static function htaccess_path() {
		return trailingslashit( ABSPATH ) . '.htaccess';
	}

	public static function block_active() {
		$path = self::htaccess_path();
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return false;
		}
		return false !== strpos( (string) file_get_contents( $path ), self::BLOCK_BEGIN ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	}

	/** Pure: strips our marker block from raw .htaccess content, leaving everything else untouched. */
	public static function strip_block( $content ) {
		$pattern = '/' . preg_quote( self::BLOCK_BEGIN, '/' ) . '.*?' . preg_quote( self::BLOCK_END, '/' ) . '\n?/s';
		return (string) preg_replace( $pattern, '', (string) $content );
	}

	/**
	 * Pure: the Apache rules for a given alias. Wrapped in
	 * <IfModule mod_rewrite.c> so this is a no-op (not a parse error) on
	 * a server without mod_rewrite.
	 */
	public static function block_rules( $alias ) {
		return self::BLOCK_BEGIN . "\n"
			. "# Serves wp-content/wp-includes assets under a disguised path.\n"
			. "# Must stay ABOVE any WordPress block below it in this file --\n"
			. "# WordPress's own catch-all rewrite rule would otherwise match\n"
			. "# first and these two rules would never run.\n"
			. "<IfModule mod_rewrite.c>\n"
			. "RewriteEngine On\n"
			. "RewriteRule ^{$alias}-content/(.*)$ wp-content/\$1 [L]\n"
			. "RewriteRule ^{$alias}-includes/(.*)$ wp-includes/\$1 [L]\n"
			. "</IfModule>\n"
			. self::BLOCK_END . "\n";
	}

	/** Shown for manual configuration on non-Apache servers. */
	public static function nginx_snippet( $alias ) {
		$alias = '' !== $alias ? $alias : 'ALIAS';
		return "location ~ ^/{$alias}-content/(.*)$ {\n\trewrite ^/{$alias}-content/(.*)$ /wp-content/\$1 last;\n}\nlocation ~ ^/{$alias}-includes/(.*)$ {\n\trewrite ^/{$alias}-includes/(.*)$ /wp-includes/\$1 last;\n}";
	}

	/**
	 * Writes our block at the very TOP of the root .htaccess (ahead of
	 * any existing content, including WordPress's own block) -- see the
	 * class docblock for why this must be a prepend, not the usual
	 * append other .htaccess-writing features in this plugin use.
	 *
	 * @return true|WP_Error
	 */
	public static function apply_block( $alias ) {
		$path     = self::htaccess_path();
		$existing = file_exists( $path ) ? (string) file_get_contents( $path ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$existing = self::strip_block( $existing );
		$content  = self::block_rules( $alias ) . "\n" . ltrim( $existing );

		if ( false === @file_put_contents( $path, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- single well-known file, error surfaced below
			return new WP_Error( 'is_htaccess_unwritable', __( 'Could not write the .htaccess file — check directory permissions.', 'integrity-sentinel' ) );
		}
		IS_Audit_Log::record( 'asset_cloak_applied', array( 'alias' => $alias ) );
		return true;
	}

	/**
	 * Removes ONLY our marker-delimited block, leaving the rest of the
	 * file (including WordPress's own block) untouched. Never deletes
	 * the file itself, even if that leaves it empty -- unlike a
	 * subdirectory .htaccess this plugin creates itself elsewhere, the
	 * root .htaccess routinely holds content this plugin didn't write
	 * (WordPress's own block, host-injected rules), so removing the
	 * file is never a safe assumption here.
	 *
	 * @return true|WP_Error
	 */
	public static function remove_block() {
		if ( ! self::block_active() ) {
			return true;
		}
		$path    = self::htaccess_path();
		$content = self::strip_block( (string) file_get_contents( $path ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

		if ( false === @file_put_contents( $path, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return new WP_Error( 'is_htaccess_unwritable', __( 'Could not update the .htaccess file — check directory permissions.', 'integrity-sentinel' ) );
		}
		IS_Audit_Log::record( 'asset_cloak_removed', array() );
		return true;
	}
}

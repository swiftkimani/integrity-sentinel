<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Editable IP allow/deny lists, CIDR-aware (IPv4 and IPv6). A blacklisted
 * IP is denied at plugins_loaded, before most of WordPress has loaded;
 * whitelisting always wins over blacklisting, and later PRs (login rate
 * limiting) treat the whitelist as a bypass too.
 *
 * Client-IP resolution is REMOTE_ADDR-only by default -- the same
 * strict rule IS_Audit_Log::request_ip() already uses -- because
 * X-Forwarded-For and friends are attacker-controlled unless something
 * in front of PHP is known to set them honestly. An admin who runs
 * behind a reverse proxy/CDN can explicitly name that proxy's IP
 * range(s) and which header it sets; the header is trusted ONLY when
 * REMOTE_ADDR itself falls inside that configured range, so a direct
 * attacker (who isn't coming through the proxy) can't forge the header
 * to impersonate an allow-listed IP or dodge a block.
 */
class IS_IP_List {

	private static $instance        = null;
	private static $client_ip_cache = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	public static function default_settings() {
		return array(
			'whitelist'            => '',
			'blacklist'            => '',
			'trusted_proxy_ranges' => '',
			'trusted_ip_header'    => '', // '', 'X-Forwarded-For', 'CF-Connecting-IP', 'X-Real-IP'
		);
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_ip_list_settings', array() ), self::default_settings() );
	}

	private function hooks() {
		// 'init', not 'plugins_loaded': this class is instantiated from
		// is_init(), which is itself a 'plugins_loaded' callback --
		// 'plugins_loaded' fires exactly once per request, so a callback
		// registered for it from inside another 'plugins_loaded' callback
		// is registered too late to ever run. 'init' fires immediately
		// after 'plugins_loaded' completes and hasn't happened yet at
		// this point, so it's the earliest hook that's actually safe to
		// register from here -- still well before any output is sent.
		add_action( 'init', array( $this, 'enforce' ), 1 );
	}

	public function enforce() {
		IS_Guard::run(
			'ip_list',
			function () {
				$ip = self::client_ip();
				if ( '' === $ip ) {
					return;
				}
				if ( self::is_whitelisted( $ip ) ) {
					return;
				}
				if ( self::is_blacklisted( $ip ) ) {
					IS_Audit_Log::record( 'ip_blocked', array( 'ip' => $ip ) );
					wp_die(
						esc_html__( 'Access denied.', 'integrity-sentinel' ),
						'',
						array( 'response' => 403 )
					);
				}
				if ( self::is_temp_banned( $ip ) ) {
					IS_Audit_Log::record( 'ip_temp_banned_blocked', array( 'ip' => $ip ) );
					wp_die(
						esc_html__( 'Access denied.', 'integrity-sentinel' ),
						'',
						array( 'response' => 403 )
					);
				}
			}
		);
	}

	// -----------------------------------------------------------------
	// List parsing / matching (pure, unit-tested)
	// -----------------------------------------------------------------

	/**
	 * Parses a textarea's worth of list entries: one IP or CIDR per
	 * line, blank lines ignored, "# ..." trailing comments stripped.
	 *
	 * @return string[]
	 */
	public static function parse_list_text( $text ) {
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $text ) as $line ) {
			$line = trim( preg_replace( '/#.*$/', '', $line ) );
			if ( '' !== $line ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	/**
	 * Whether $ip falls inside a single IP or CIDR entry. Handles plain
	 * IPv4/IPv6 addresses and CIDR ranges of either family; a family
	 * mismatch (e.g. an IPv4 $ip against an IPv6 CIDR) never matches.
	 */
	public static function ip_in_entry( $ip, $entry ) {
		$ip_bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid input is expected and handled below
		if ( false === $ip_bin ) {
			return false;
		}

		if ( false === strpos( $entry, '/' ) ) {
			$entry_bin = @inet_pton( $entry ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return false !== $entry_bin && hash_equals( $entry_bin, $ip_bin );
		}

		list( $subnet, $prefix ) = explode( '/', $entry, 2 );
		$subnet_bin              = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$prefix                  = (int) $prefix;

		if ( false === $subnet_bin || strlen( $subnet_bin ) !== strlen( $ip_bin ) ) {
			return false; // malformed entry, or address-family mismatch
		}

		$max_prefix = strlen( $subnet_bin ) * 8;
		if ( $prefix < 0 || $prefix > $max_prefix ) {
			return false;
		}

		$full_bytes     = intdiv( $prefix, 8 );
		$remainder_bits = $prefix % 8;

		if ( $full_bytes > 0 && strncmp( $ip_bin, $subnet_bin, $full_bytes ) !== 0 ) {
			return false;
		}
		if ( 0 === $remainder_bits ) {
			return true;
		}

		$mask = chr( 0xFF << ( 8 - $remainder_bits ) & 0xFF );
		return ( $ip_bin[ $full_bytes ] & $mask ) === ( $subnet_bin[ $full_bytes ] & $mask );
	}

	/**
	 * @param string   $ip      Client IP.
	 * @param string[] $entries Parsed list entries.
	 */
	public static function ip_matches_list( $ip, array $entries ) {
		if ( '' === $ip ) {
			return false;
		}
		foreach ( $entries as $entry ) {
			if ( self::ip_in_entry( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Pure: resolves the client IP from a $_SERVER-like array and the
	 * plugin's trusted-proxy settings. The configured header is used
	 * only when REMOTE_ADDR itself is inside a configured trusted-proxy
	 * range -- otherwise REMOTE_ADDR is always the answer, so a request
	 * that didn't actually come through the trusted proxy can't spoof
	 * its way past this with a forged header.
	 */
	public static function resolve_client_ip( array $server, array $settings ) {
		$remote_addr = isset( $server['REMOTE_ADDR'] ) ? trim( (string) $server['REMOTE_ADDR'] ) : '';
		$remote_addr = false !== @inet_pton( $remote_addr ) ? $remote_addr : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- validating, not suppressing a real error

		$header = trim( (string) ( $settings['trusted_ip_header'] ?? '' ) );
		$ranges = self::parse_list_text( $settings['trusted_proxy_ranges'] ?? '' );

		if ( '' === $header || empty( $ranges ) || '' === $remote_addr || ! self::ip_matches_list( $remote_addr, $ranges ) ) {
			return $remote_addr;
		}

		$server_key = 'HTTP_' . strtoupper( str_replace( '-', '_', $header ) );
		if ( empty( $server[ $server_key ] ) ) {
			return $remote_addr;
		}

		// X-Forwarded-For may be a comma-separated chain; the first hop is
		// the original client as seen by the nearest trusted proxy.
		$candidate     = trim( explode( ',', (string) $server[ $server_key ] )[0] );
		$candidate_bin = @inet_pton( $candidate ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return false !== $candidate_bin ? $candidate : $remote_addr;
	}

	/**
	 * Temporary bans: a programmatic, expiring counterpart to the static
	 * admin-edited blacklist above. Nothing in this class writes one
	 * itself; other modules (IS_Deception's honeypots/canary token,
	 * future automated-response features) call temp_ban() when they
	 * catch something the static blacklist was never meant to cover.
	 */
	public static function default_ban_record() {
		return array(
			'banned_until' => null,
			'reason'       => '',
		);
	}

	/** Pure: is a ban record currently in effect? */
	public static function is_ban_active( array $record, $now ) {
		return ! empty( $record['banned_until'] ) && $record['banned_until'] > $now;
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	private static function ban_transient_key( $ip ) {
		return 'is_ip_temp_ban_' . md5( (string) $ip );
	}

	/**
	 * @param string $ip
	 * @param string $reason           Short machine-readable reason, stored for the admin's benefit -- never shown to the banned visitor.
	 * @param int    $duration_seconds
	 */
	public static function temp_ban( $ip, $reason, $duration_seconds ) {
		$duration_seconds = max( MINUTE_IN_SECONDS, (int) $duration_seconds );
		$record           = array(
			'banned_until' => time() + $duration_seconds,
			'reason'       => (string) $reason,
		);
		set_transient( self::ban_transient_key( $ip ), $record, $duration_seconds );
		return $record;
	}

	public static function is_temp_banned( $ip = null ) {
		$ip = null === $ip ? self::client_ip() : $ip;
		if ( '' === $ip ) {
			return false;
		}
		$record = get_transient( self::ban_transient_key( $ip ) );
		$record = is_array( $record ) ? wp_parse_args( $record, self::default_ban_record() ) : self::default_ban_record();
		return self::is_ban_active( $record, time() );
	}

	public static function client_ip() {
		if ( null === self::$client_ip_cache ) {
			self::$client_ip_cache = self::resolve_client_ip( $_SERVER, self::settings() ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- resolve_client_ip() validates every value it reads via inet_pton()
		}
		return self::$client_ip_cache;
	}

	public static function is_whitelisted( $ip = null ) {
		$ip = null === $ip ? self::client_ip() : $ip;
		return self::ip_matches_list( $ip, self::parse_list_text( self::settings()['whitelist'] ) );
	}

	public static function is_blacklisted( $ip = null ) {
		$ip = null === $ip ? self::client_ip() : $ip;
		return self::ip_matches_list( $ip, self::parse_list_text( self::settings()['blacklist'] ) );
	}
}

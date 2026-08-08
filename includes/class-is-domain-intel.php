<?php
/**
 * Opt-in domain-phishing intelligence: typosquat-domain DNS checks and
 * Certificate Transparency log monitoring for the site's own domain.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generates common typosquat variants of the site's own domain (adjacent-
 * character swaps, omissions, duplications, homoglyph substitutions, and
 * common TLD swaps) and checks two things about each: is it already
 * registered (a DNS hit), and has a TLS certificate recently been issued
 * for it (a crt.sh Certificate Transparency log hit -- free, keyless).
 * A live cert on a lookalike domain is a strong, early signal of active
 * phishing infrastructure, often available before the phishing site is
 * even indexed anywhere.
 *
 * Self-check only: the target domain always comes from home_url(), never
 * a configurable/arbitrary field, matching IS_TLS_Check/IS_Email_Auth.
 * Opt-in and off by default, matching IS_Threat_Intel's stance on new
 * outbound dependencies -- DNS lookups are cheap and run for every
 * variant, but crt.sh lookups are paced (MAX_CT_REQUESTS_PER_RUN,
 * transient-cached) across the existing daily scan cadence rather than a
 * new cron job, the same way IS_Hardening::check_closed_plugins() paces
 * its own WordPress.org lookups.
 */
class IS_Domain_Intel {

	const CACHE_TTL               = DAY_IN_SECONDS;
	const MAX_CT_REQUESTS_PER_RUN = 8;
	const MAX_VARIANTS            = 60;
	const TYPOSQUAT_TLDS          = array( 'com', 'net', 'org', 'info', 'xyz', 'top', 'co' );
	const HOMOGLYPH_MAP           = array(
		'o' => '0',
		'l' => '1',
		'i' => '1',
		'e' => '3',
		'a' => '4',
		's' => '5',
	);

	/**
	 * Default settings for this module.
	 */
	public static function default_settings() {
		return array(
			'enabled' => 0,
		);
	}

	/**
	 * Current settings, merged over the defaults.
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_domain_intel_settings', array() ), self::default_settings() );
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: lowercases and strips a leading "www." from a domain.
	 *
	 * @param string $domain Raw domain/hostname.
	 */
	public static function normalize_domain( $domain ) {
		$domain = strtolower( trim( (string) $domain ) );
		if ( 0 === strpos( $domain, 'www.' ) ) {
			$domain = substr( $domain, 4 );
		}
		return $domain;
	}

	/**
	 * Pure: splits a domain into its label and TLD on the last dot. A
	 * simplification (doesn't consult a public-suffix list, so
	 * "example.co.uk" splits as "example.co" / "uk") that's acceptable
	 * here since the input is always this site's own single registered
	 * domain, not an arbitrary one.
	 *
	 * @param string $domain Normalized domain.
	 * @return array{0:string,1:string} [label, tld].
	 */
	public static function split_domain( $domain ) {
		$domain = (string) $domain;
		$pos    = strrpos( $domain, '.' );
		if ( false === $pos ) {
			return array( $domain, '' );
		}
		return array( substr( $domain, 0, $pos ), substr( $domain, $pos + 1 ) );
	}

	/**
	 * Pure: every variant of $label with one adjacent pair of characters swapped.
	 *
	 * @param string $label Domain label (no TLD).
	 * @return string[]
	 */
	public static function adjacent_swap_variants( $label ) {
		$label = (string) $label;
		$len   = strlen( $label );
		$out   = array();
		for ( $i = 0; $i < $len - 1; $i++ ) {
			if ( $label[ $i ] === $label[ $i + 1 ] ) {
				continue;
			}
			$swapped           = $label;
			$swapped[ $i ]     = $label[ $i + 1 ];
			$swapped[ $i + 1 ] = $label[ $i ];
			$out[]             = $swapped;
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Pure: every variant of $label with one character removed.
	 *
	 * @param string $label Domain label (no TLD).
	 * @return string[]
	 */
	public static function omission_variants( $label ) {
		$label = (string) $label;
		$len   = strlen( $label );
		$out   = array();
		for ( $i = 0; $i < $len; $i++ ) {
			$variant = substr( $label, 0, $i ) . substr( $label, $i + 1 );
			if ( '' !== $variant ) {
				$out[] = $variant;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Pure: every variant of $label with one character duplicated.
	 *
	 * @param string $label Domain label (no TLD).
	 * @return string[]
	 */
	public static function duplication_variants( $label ) {
		$label = (string) $label;
		$len   = strlen( $label );
		$out   = array();
		for ( $i = 0; $i < $len; $i++ ) {
			$out[] = substr( $label, 0, $i + 1 ) . $label[ $i ] . substr( $label, $i + 1 );
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Pure: every variant of $label with one character swapped for a common visual homoglyph.
	 *
	 * @param string $label Domain label (no TLD).
	 * @return string[]
	 */
	public static function homoglyph_variants( $label ) {
		$label = (string) $label;
		$len   = strlen( $label );
		$out   = array();
		foreach ( self::HOMOGLYPH_MAP as $from => $to ) {
			for ( $i = 0; $i < $len; $i++ ) {
				if ( $label[ $i ] !== $from ) {
					continue;
				}
				$variant       = $label;
				$variant[ $i ] = $to;
				$out[]         = $variant;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Pure: $label under every TLD in $tlds, as full domains.
	 *
	 * @param string   $label Domain label (no TLD).
	 * @param string[] $tlds  TLDs to generate.
	 * @return string[] Full domains (label.tld).
	 */
	public static function tld_swap_variants( $label, array $tlds ) {
		$out = array();
		foreach ( $tlds as $tld ) {
			$out[] = $label . '.' . $tld;
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Pure: the full, deduplicated set of typosquat domain variants for
	 * $domain, excluding the real domain itself and capped at
	 * MAX_VARIANTS.
	 *
	 * @param string   $domain Site's own domain.
	 * @param string[] $tlds   TLDs to use for tld_swap_variants().
	 * @return string[] Full domains.
	 */
	public static function generate_variants( $domain, array $tlds = self::TYPOSQUAT_TLDS ) {
		$domain              = self::normalize_domain( $domain );
		list( $label, $tld ) = self::split_domain( $domain );
		if ( '' === $label || '' === $tld ) {
			return array();
		}

		$label_variants = array_unique(
			array_merge(
				self::adjacent_swap_variants( $label ),
				self::omission_variants( $label ),
				self::duplication_variants( $label ),
				self::homoglyph_variants( $label )
			)
		);

		$variants = array();
		foreach ( $label_variants as $variant_label ) {
			$variants[] = $variant_label . '.' . $tld;
		}
		$variants = array_merge( $variants, self::tld_swap_variants( $label, $tlds ) );

		$variants = array_values( array_unique( $variants ) );
		$variants = array_values( array_diff( $variants, array( $domain ) ) );

		if ( count( $variants ) > self::MAX_VARIANTS ) {
			$variants = array_slice( $variants, 0, self::MAX_VARIANTS );
		}
		return $variants;
	}

	/**
	 * Pure: the crt.sh Certificate Transparency search URL for a domain.
	 *
	 * @param string $domain Domain to query.
	 */
	public static function crtsh_query_url( $domain ) {
		return 'https://crt.sh/?q=' . rawurlencode( (string) $domain ) . '&output=json';
	}

	/**
	 * Pure: extracts {domain, issuer, timestamp} rows from a decoded crt.sh JSON response.
	 *
	 * @param mixed $body Decoded crt.sh JSON response body.
	 * @return array<array{domain:string,issuer:string,timestamp:string}>
	 */
	public static function parse_crtsh_response( $body ) {
		if ( ! is_array( $body ) ) {
			return array();
		}
		$out = array();
		foreach ( $body as $row ) {
			if ( ! is_array( $row ) || empty( $row['common_name'] ) ) {
				continue;
			}
			$out[] = array(
				'domain'    => (string) $row['common_name'],
				'issuer'    => isset( $row['issuer_name'] ) ? (string) $row['issuer_name'] : '',
				'timestamp' => isset( $row['entry_timestamp'] ) ? (string) $row['entry_timestamp'] : '',
			);
		}
		return $out;
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * The site's own domain -- always self, never a configurable target.
	 */
	public static function site_domain() {
		return (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * Whether $domain currently resolves (A, AAAA, or MX record).
	 *
	 * @param string $domain Domain to check.
	 */
	private static function is_variant_registered( $domain ) {
		$fqdn = rtrim( (string) $domain, '.' ) . '.';
		return @checkdnsrr( $fqdn, 'A' ) || @checkdnsrr( $fqdn, 'AAAA' ) || @checkdnsrr( $fqdn, 'MX' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a non-existent hostname is an expected outcome, not a code error
	}

	/**
	 * Looks up crt.sh for certificates issued on $domain, using the
	 * transient cache before spending a request.
	 *
	 * @param string $domain Domain to query.
	 * @return array<array{domain:string,issuer:string,timestamp:string}>
	 */
	public function lookup_certificates( $domain ) {
		$cache_key = 'is_domain_intel_ct_' . md5( $domain );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get( self::crtsh_query_url( $domain ), array( 'timeout' => 10 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return array(); // A failed/rate-limited lookup just means no data this run, not a scan failure.
		}

		$certs = self::parse_crtsh_response( json_decode( wp_remote_retrieve_body( $response ), true ) );
		set_transient( $cache_key, $certs, self::CACHE_TTL );
		return $certs;
	}

	/**
	 * Runs the full domain-intel sweep for $host: a DNS check across
	 * every typosquat variant (cheap, always run in full) and a
	 * crt.sh check across cache-misses only, paced by
	 * MAX_CT_REQUESTS_PER_RUN so a large variant list is covered across
	 * several days of the existing daily scan cadence.
	 *
	 * @param string $host Site's own domain.
	 * @return array{registered:string[],certificates:array<array{domain:string,issuer:string}>}
	 */
	public function run_checks( $host ) {
		$out = array(
			'registered'   => array(),
			'certificates' => array(),
		);

		$variants = self::generate_variants( $host );
		if ( empty( $variants ) ) {
			return $out;
		}

		foreach ( $variants as $variant ) {
			if ( self::is_variant_registered( $variant ) ) {
				$out['registered'][] = $variant;
			}
		}

		$requests = 0;
		foreach ( $variants as $variant ) {
			$cache_key = 'is_domain_intel_ct_' . md5( $variant );
			$is_cached = is_array( get_transient( $cache_key ) );
			if ( ! $is_cached ) {
				if ( $requests >= self::MAX_CT_REQUESTS_PER_RUN ) {
					continue;
				}
				++$requests;
			}
			foreach ( $this->lookup_certificates( $variant ) as $cert ) {
				$out['certificates'][] = array(
					'domain' => $variant,
					'issuer' => $cert['issuer'],
				);
			}
		}

		return $out;
	}
}

<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only SPF/DMARC/DKIM presence check for the site's sending domain,
 * via plain DNS TXT lookups -- no third-party API, no key, nothing sent
 * off-server. DKIM in particular has no fixed, discoverable DNS name (the
 * selector is chosen by whoever configured the mail sender), so this
 * tries a short list of common selectors and reports the first hit; a
 * miss here means "not found under a common selector", not "definitely
 * absent".
 */
class IS_Email_Auth {

	/** Selectors common enough across major ESPs/mail providers to be worth a guess; not exhaustive. */
	const DKIM_SELECTORS_TO_TRY = array( 'default', 'google', 'selector1', 'selector2', 'k1', 'dkim', 'mail' );

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/** Pure: does a list of TXT record value strings contain a valid SPF record? */
	public static function has_spf( array $txt_values ) {
		foreach ( $txt_values as $value ) {
			if ( 0 === stripos( trim( (string) $value ), 'v=spf1' ) ) {
				return true;
			}
		}
		return false;
	}

	/** Pure: does a list of TXT record value strings contain a valid DMARC record? */
	public static function has_dmarc( array $txt_values ) {
		foreach ( $txt_values as $value ) {
			if ( 0 === stripos( trim( (string) $value ), 'v=DMARC1' ) ) {
				return true;
			}
		}
		return false;
	}

	/** Pure: extracts the p= enforcement level from a DMARC record string; '' if absent/malformed. */
	public static function dmarc_policy( $dmarc_record ) {
		if ( preg_match( '/;\s*p\s*=\s*(none|quarantine|reject)/i', ';' . (string) $dmarc_record, $m ) ) {
			return strtolower( $m[1] );
		}
		return '';
	}

	/** Pure: does a list of TXT record value strings look like a DKIM public-key record? */
	public static function has_dkim( array $txt_values ) {
		foreach ( $txt_values as $value ) {
			$value = (string) $value;
			if ( false !== stripos( $value, 'v=DKIM1' ) || false !== stripos( $value, 'k=rsa' ) ) {
				return true;
			}
		}
		return false;
	}

	// -----------------------------------------------------------------
	// WP/PHP-dependent glue
	// -----------------------------------------------------------------

	/** @return string[] every TXT record's text value for $hostname. */
	private static function txt_values_for( $hostname ) {
		$records = @dns_get_record( $hostname, DNS_TXT ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a non-existent hostname is an expected outcome, not a code error
		if ( ! is_array( $records ) ) {
			return array();
		}
		$out = array();
		foreach ( $records as $record ) {
			if ( isset( $record['txt'] ) ) {
				$out[] = $record['txt'];
			} elseif ( isset( $record['entries'] ) ) {
				$out[] = implode( '', (array) $record['entries'] );
			}
		}
		return $out;
	}

	/**
	 * @return array{domain:string,spf:bool,dmarc:bool,dmarc_policy:string,dkim:bool,dkim_selector:string}
	 */
	public static function check_domain( $domain ) {
		$domain = strtolower( trim( (string) $domain ) );
		$result = array(
			'domain'        => $domain,
			'spf'           => false,
			'dmarc'         => false,
			'dmarc_policy'  => '',
			'dkim'          => false,
			'dkim_selector' => '',
		);
		if ( '' === $domain ) {
			return $result;
		}

		$result['spf'] = self::has_spf( self::txt_values_for( $domain ) );

		$dmarc_txt       = self::txt_values_for( '_dmarc.' . $domain );
		$result['dmarc'] = self::has_dmarc( $dmarc_txt );
		if ( $result['dmarc'] ) {
			foreach ( $dmarc_txt as $value ) {
				if ( self::has_dmarc( array( $value ) ) ) {
					$result['dmarc_policy'] = self::dmarc_policy( $value );
					break;
				}
			}
		}

		foreach ( self::DKIM_SELECTORS_TO_TRY as $selector ) {
			if ( self::has_dkim( self::txt_values_for( $selector . '._domainkey.' . $domain ) ) ) {
				$result['dkim']          = true;
				$result['dkim_selector'] = $selector;
				break;
			}
		}

		return $result;
	}

	/** The domain this check should default to: the site's own sending-email domain. */
	public static function site_domain() {
		$email = get_option( 'admin_email' );
		$at    = strrpos( (string) $email, '@' );
		return false !== $at ? substr( $email, $at + 1 ) : '';
	}
}

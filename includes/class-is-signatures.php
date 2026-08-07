<?php
/**
 * Admin-curated known-bad SHA-256 file-hash signature matching.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exact-hash signature matching, complementary to IS_Heuristics's
 * structural/regex pattern matching: this catches a file that IS a
 * byte-for-byte known-bad artifact (with zero false-positive risk, since
 * it's an exact match), while heuristics catches code that LOOKS
 * dangerous by shape.
 *
 * Deliberately does NOT ship with a bundled "malware hash database" --
 * fabricating or copying a list of "known-malicious" hashes without a
 * verifiable, currently-accurate source would be actively misleading in
 * a security tool (a wrong hash either gives false confidence or, worse,
 * could coincidentally match and flag an unrelated legitimate file).
 * Instead this is an admin-curated known-bad-hash list -- the same
 * pattern IS_IP_List already uses for allow/deny lists -- meant to be
 * populated from hashes gathered during an actual incident, a threat-
 * intel feed, or a VirusTotal/MalwareBazaar report, then checked
 * automatically on every future scan.
 */
class IS_Signatures {

	/**
	 * Default settings: signature matching enabled, with an empty
	 * admin-curated known-bad hash list.
	 */
	public static function default_settings() {
		return array(
			'enabled' => 1,
			'hashes'  => '',
		);
	}

	/**
	 * Returns the stored `is_signatures_settings` option merged over the defaults.
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_signatures_settings', array() ), self::default_settings() );
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: parses a textarea's worth of "sha256  # optional label" lines
	 * into a hash => label map. Malformed lines (not a 64-char hex sha256)
	 * are skipped rather than guessed at.
	 *
	 * @param string $text Raw textarea contents: one "sha256  # optional label" entry per line.
	 * @return array<string,string>
	 */
	public static function parse_hash_list( $text ) {
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $text ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			$parts = preg_split( '/\s*#\s*/', $line, 2 );
			$hash  = strtolower( trim( $parts[0] ) );
			if ( ! preg_match( '/^[a-f0-9]{64}$/', $hash ) ) {
				continue;
			}
			$out[ $hash ] = isset( $parts[1] ) ? trim( $parts[1] ) : '';
		}
		return $out;
	}

	/**
	 * Pure: does $content_sha256 match one of the configured known-bad
	 * hashes? Returns the match's label ('' if none was given), or null
	 * for no match.
	 *
	 * @param string               $content_sha256 The scanned content's SHA-256 hash (any case).
	 * @param array<string,string> $known_hashes   Map of lowercase sha256 => label, as returned by parse_hash_list().
	 */
	public static function match_hash( $content_sha256, array $known_hashes ) {
		$content_sha256 = strtolower( (string) $content_sha256 );
		return array_key_exists( $content_sha256, $known_hashes ) ? $known_hashes[ $content_sha256 ] : null;
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * Same return shape as IS_Heuristics::scan_content(), so
	 * IS_Scanner::scan_one_file() can record findings from both
	 * identically.
	 *
	 * @param string $content Raw file content to hash and check against the known-bad hash list.
	 * @return array<array{rule_id:string,label:string,severity:string,matches:array}>
	 */
	public static function scan_content( $content ) {
		$settings = self::settings();
		if ( empty( $settings['enabled'] ) ) {
			return array();
		}

		$known = self::parse_hash_list( $settings['hashes'] );
		if ( empty( $known ) ) {
			return array();
		}

		$hash  = hash( 'sha256', $content );
		$label = self::match_hash( $hash, $known );
		if ( null === $label ) {
			return array();
		}

		return array(
			array(
				'rule_id'  => 'known_bad_hash',
				'label'    => '' !== $label
					? sprintf(
						/* translators: %s: the admin-supplied label for this hash */
						__( 'File hash matches a known-bad signature you added: %s', 'integrity-sentinel' ),
						$label
					)
					: __( 'File hash matches a known-bad signature you added.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'matches'  => array(
					array(
						'line'    => 0,
						'snippet' => $hash,
					),
				),
			),
		);
	}
}

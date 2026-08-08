<?php
/**
 * Pattern-based detection of hardcoded credentials (API keys, private
 * keys, tokens) accidentally committed into theme/plugin files.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A sibling to IS_Heuristics, not a category folded into it -- that
 * class's own docblock scopes it to "malware/webshell techniques";
 * leaked credentials are a distinct taxonomy, and this codebase already
 * drew this exact line once before (IS_Signatures is its own class for
 * the same reason). Every rule here matches a *shape* known-vendor key
 * formats always take, or a generic high-entropy value assigned to a
 * credential-named variable -- none of this reproduces or requires any
 * actual secret to work, matching IS_Heuristics' own convention of never
 * shipping a literal that could match this very file.
 *
 * Ships unconditionally active, like IS_Heuristics -- no settings
 * toggle, since a false positive is durably suppressible via the
 * existing per-finding Ignore workflow.
 */
class IS_Secrets {

	/** Max reported occurrences of one rule in one file. */
	const MAX_MATCHES_PER_RULE = 10;

	/** File extensions worth reading for secrets, beyond the PHP files IS_Heuristics already reads. */
	const SCANNABLE_EXTENSIONS = array( 'php', 'phtml', 'js', 'json', 'env', 'ini', 'yml', 'yaml', 'txt', 'config', 'conf', 'xml' );

	/** Minimum length of a quoted value assigned to a credential-named variable before it's considered. */
	const MIN_VARIABLE_SECRET_LENGTH = 12;

	/** Bits/byte -- lower than IS_Heuristics' packed-payload threshold (4.8), since a genuine API key is shorter and drawn from a smaller alphabet than a packed binary blob, but still clearly non-natural-language. */
	const VARIABLE_SECRET_ENTROPY_THRESHOLD = 3.4;

	/**
	 * The full set of regex-based known-vendor-key-format rules.
	 *
	 * @return array<array{id:string,label:string,severity:string,pattern:string}>
	 */
	public static function rules() {
		return array(
			array(
				'id'       => 'aws_access_key_id',
				'label'    => __( 'An AWS access key ID is present in this file.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'pattern'  => '/\bAKIA[0-9A-Z]{16}\b/',
			),
			array(
				'id'       => 'private_key_pem_block',
				'label'    => __( 'A private key (PEM block) is present in this file.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'pattern'  => '/-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/',
			),
			array(
				'id'       => 'github_token',
				'label'    => __( 'A GitHub access token is present in this file.', 'integrity-sentinel' ),
				'severity' => 'high',
				'pattern'  => '/\bgh[posu]_[A-Za-z0-9]{36,}\b/',
			),
			array(
				'id'       => 'slack_token',
				'label'    => __( 'A Slack token is present in this file.', 'integrity-sentinel' ),
				'severity' => 'high',
				'pattern'  => '/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/',
			),
			array(
				'id'       => 'stripe_live_key',
				'label'    => __( 'A Stripe LIVE API key is present in this file — this is not a test key.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'pattern'  => '/\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/',
			),
			array(
				'id'       => 'google_api_key',
				'label'    => __( 'A Google API key is present in this file.', 'integrity-sentinel' ),
				'severity' => 'high',
				'pattern'  => '/\bAIza[0-9A-Za-z\-_]{35}\b/',
			),
		);
	}

	/**
	 * Runs every rule (known-key-format patterns, plus the generic
	 * variable-assignment check) against a chunk of file content. Same
	 * shape as IS_Heuristics::scan_content().
	 *
	 * @param string $content File content to scan.
	 * @return array<array{rule_id:string,label:string,severity:string,matches:array<array{line:int,snippet:string}>}>
	 */
	public static function scan_content( $content ) {
		$rules_out = array();
		$lines     = null;

		foreach ( self::rules() as $rule ) {
			if ( ! preg_match_all( $rule['pattern'], $content, $m, PREG_OFFSET_CAPTURE ) ) {
				continue;
			}

			if ( null === $lines ) {
				$lines = explode( "\n", $content );
			}

			$matches = array();
			foreach ( array_slice( $m[0], 0, self::MAX_MATCHES_PER_RULE ) as $hit ) {
				$matches[] = self::line_context_from_lines( $content, $lines, $hit[1] );
			}

			$rules_out[] = array(
				'rule_id'  => $rule['id'],
				'label'    => $rule['label'],
				'severity' => $rule['severity'],
				'matches'  => $matches,
			);
		}

		$variable_hits = self::find_variable_assigned_secrets( $content );
		if ( ! empty( $variable_hits ) ) {
			$rules_out[] = array(
				'rule_id'  => 'variable_assigned_secret',
				'label'    => __( 'A variable named like a credential (api_key/secret/password/token) is assigned a long, high-entropy value — possibly a hardcoded secret.', 'integrity-sentinel' ),
				'severity' => 'high',
				'matches'  => array_map(
					function ( $hit ) use ( $content ) {
						return self::line_context( $content, $hit['offset'] );
					},
					$variable_hits
				),
			);
		}

		return $rules_out;
	}

	/**
	 * Pure: whether $relative_path's extension is worth reading for secrets.
	 *
	 * @param string $relative_path Path relative to ABSPATH.
	 */
	public static function is_scannable_extension( $relative_path ) {
		$ext = strtolower( pathinfo( (string) $relative_path, PATHINFO_EXTENSION ) );
		return in_array( $ext, self::SCANNABLE_EXTENSIONS, true );
	}

	/**
	 * Pure: is $value an obvious placeholder rather than a real secret --
	 * "CHANGE_ME", "your_api_key_here", a run of a single repeated
	 * character, etc.
	 *
	 * @param string $value Candidate secret value.
	 */
	public static function is_placeholder_value( $value ) {
		$value = (string) $value;
		if ( preg_match( '/^(change[_-]?me|your[_-]?api[_-]?key([_-]?here)?|xxx+|0+|123456[0-9]*|example|placeholder|todo|replace[_-]?me|test|dummy|fake)$/i', $value ) ) {
			return true;
		}
		// A string made of a single repeated character has no real entropy regardless of length.
		return 1 === count( array_unique( str_split( $value ) ) );
	}

	/**
	 * Pure: quoted values assigned to a variable named like a credential
	 * (api_key/secret/password/token), long and high-entropy enough to
	 * plausibly be a real secret rather than a placeholder.
	 *
	 * @param string $content File content to scan.
	 * @return array<array{offset:int}>
	 */
	public static function find_variable_assigned_secrets( $content ) {
		$pattern = '/\$\w*(?:api[_-]?key|secret|passwd?|password|token)\w*\s*=\s*[\'"]([^\'"]{' . self::MIN_VARIABLE_SECRET_LENGTH . ',})[\'"]/i';
		if ( ! preg_match_all( $pattern, $content, $m, PREG_OFFSET_CAPTURE ) ) {
			return array();
		}

		$out = array();
		foreach ( $m[1] as $match ) {
			$value = $match[0];
			if ( self::is_placeholder_value( $value ) ) {
				continue;
			}
			if ( IS_Heuristics::shannon_entropy( $value ) < self::VARIABLE_SECRET_ENTROPY_THRESHOLD ) {
				continue;
			}
			$out[] = array( 'offset' => $match[1] );
			if ( count( $out ) >= self::MAX_MATCHES_PER_RULE ) {
				break;
			}
		}
		return $out;
	}

	/**
	 * Builds the {line, snippet} pair for a byte offset into $content.
	 *
	 * @param string $content File content the offset is within.
	 * @param int    $offset  Byte offset of the match.
	 * @return array{line:int,snippet:string}
	 */
	private static function line_context( $content, $offset ) {
		return self::line_context_from_lines( $content, explode( "\n", $content ), $offset );
	}

	/**
	 * Same as line_context() but reuses an already-exploded line array,
	 * so scan_content()'s rule loop doesn't re-explode $content per rule.
	 *
	 * @param string   $content File content the offset is within.
	 * @param string[] $lines   $content pre-exploded on "\n".
	 * @param int      $offset  Byte offset of the match.
	 * @return array{line:int,snippet:string}
	 */
	private static function line_context_from_lines( $content, array $lines, $offset ) {
		$line_no = substr_count( substr( $content, 0, $offset ), "\n" ) + 1;
		$snippet = isset( $lines[ $line_no - 1 ] ) ? trim( $lines[ $line_no - 1 ] ) : '';
		return array(
			'line'    => $line_no,
			'snippet' => mb_substr( $snippet, 0, 200 ),
		);
	}
}

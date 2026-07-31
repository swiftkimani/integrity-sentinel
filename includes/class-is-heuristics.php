<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pattern-based detection of common WordPress malware/webshell
 * techniques. This is deliberately a *heuristic* layer, not a
 * signature-perfect antivirus: it flags code shapes that are extremely
 * common in real-world WP compromises (obfuscated eval chains, dynamic
 * code execution from request data, disguised uploads) so a human can
 * review them, and it errs toward flagging-for-review over silence.
 *
 * Every rule matches structural code *patterns* -- none of this
 * reproduces or requires any actual malicious payload to work.
 *
 * Note the string-concatenation in some patterns below: the scanner
 * scans its own files too, so no rule may contain a literal that would
 * match this very file (v1.0 shipped the webshell name markers as plain
 * literals and flagged itself as a critical finding on every scan).
 */
class IS_Heuristics {

	/** Max reported occurrences of one rule in one file -- enough to show
	 * the problem is widespread without bloating the finding row. */
	const MAX_MATCHES_PER_RULE = 10;

	/**
	 * @return array<array{id:string,label:string,severity:string,pattern:string}>
	 */
	public static function rules() {
		return array(
			array(
				'id'       => 'eval_base64',
				'label'    => __( 'eval() of base64-decoded content — one of the most common WordPress backdoor patterns.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'pattern'  => '/\beval\s*\(\s*(?:\$\w+\s*=\s*)?base64_decode\s*\(/i',
			),
			array(
				'id'       => 'eval_gzinflate',
				'label'    => __( 'eval() of gzinflate/gzuncompress-decoded content — a common obfuscation wrapper for injected code.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'pattern'  => '/\beval\s*\(\s*(?:\$\w+\s*=\s*)?(?:gzinflate|gzuncompress|gzdecode)\s*\(/i',
			),
			array(
				'id'       => 'eval_str_rot13',
				'label'    => __( 'eval() combined with str_rot13() — used to obscure injected code from casual inspection.', 'integrity-sentinel' ),
				'severity' => 'high',
				'pattern'  => '/\beval\s*\([^)]*str_rot13\s*\(/i',
			),
			array(
				'id'       => 'preg_replace_e_modifier',
				'label'    => __( 'preg_replace() with the deprecated /e modifier — historically used as a remote-code-execution vector.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'pattern'  => '/preg_replace\s*\(\s*[\'"][^\'"]*\/[a-zA-Z]*e[a-zA-Z]*[\'"]/i',
			),
			array(
				'id'       => 'create_function_dynamic',
				'label'    => __( 'create_function() (deprecated) building code from a variable — a classic obfuscated-eval substitute.', 'integrity-sentinel' ),
				'severity' => 'high',
				'pattern'  => '/create_function\s*\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$/i',
			),
			array(
				'id'       => 'request_to_shell',
				'label'    => __( 'Request data (GET/POST/REQUEST/COOKIE) passed directly into a shell-execution function.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'pattern'  => '/\b(?:shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
			),
			array(
				'id'       => 'request_to_eval_chain',
				'label'    => __( 'Request data passed through eval(), assert(), or call_user_func() — a common remote-command backdoor shape.', 'integrity-sentinel' ),
				'severity' => 'critical',
				'pattern'  => '/\b(?:eval|assert|call_user_func|call_user_func_array)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
			),
			array(
				'id'       => 'suspicious_error_suppressed_include',
				// 'low' rather than 'medium': this pattern alone is a weak
				// signal on its own -- error-suppressed includes of a
				// variable template path are routine in real WordPress
				// themes/plugins (template-part loading, page builders).
				// It's worth surfacing for review, not worth an alert.
				'label'    => __( 'Error-suppressed include/require of a variable path. Common in legitimate template-loading code too, so treat this as a hint worth a quick look rather than a confirmed problem on its own.', 'integrity-sentinel' ),
				'severity' => 'low',
				'pattern'  => '/@(?:include|include_once|require|require_once)\s*\(\s*\$/i',
			),
			array(
				'id'       => 'long_base64_blob',
				// 'low' rather than 'medium': a long base64-looking string
				// by itself is common in legitimate code too (embedded
				// fonts/images as data URIs, license keys, serialized
				// data). The genuinely dangerous combination -- base64
				// content actually passed to eval() -- already has its
				// own dedicated 'eval_base64' rule at 'critical'.
				'label'    => __( 'A very long base64-looking string literal. Often legitimate (embedded font/image data, license keys), but occasionally the payload body of an injected backdoor -- worth a quick look, not a confirmed problem on its own.', 'integrity-sentinel' ),
				'severity' => 'low',
				'pattern'  => '/[\'"][A-Za-z0-9+\/]{500,}={0,2}[\'"]/',
			),
			array(
				'id'       => 'php_uname_system_probe',
				'label'    => __( 'Environment/system fingerprinting calls (php_uname, phpversion, disable_functions checks) bundled together — common in webshell "info" panels.', 'integrity-sentinel' ),
				'severity' => 'low',
				'pattern'  => '/php_uname\s*\(.*disable_functions/is',
			),
			array(
				'id'       => 'known_webshell_marker',
				'label'    => __( 'A string strongly associated with a known public webshell family.', 'integrity-sentinel' ),
				'severity' => 'critical',
				// Matching on the *name* strings a webshell announces itself
				// with (as commonly indexed by AV/webshell scanners), not on
				// any functional payload. Concatenated so this file's own
				// source never matches its own rule.
				'pattern'  => '/(?:' . implode(
					'|',
					array(
						'Files' . 'Man',
						'b3' . '74k',
						'WSO' . '\s*[0-9.]*\s*We' . 'b\s*Sh' . 'ell',
						'c9' . '9shell',
						'r5' . '7shell',
					)
				) . ')/i',
			),
			array(
				'id'       => 'ffi_or_dl_call',
				// Label deliberately writes "the dl function" WITHOUT the
				// usual parentheses after the name: the parenthesized form
				// would match this rule's own pattern when the scanner
				// reads this file.
				'label'    => __( 'Use of FFI or the dl function to load a native extension at runtime — very rarely legitimate in a WordPress plugin/theme.', 'integrity-sentinel' ),
				'severity' => 'medium',
				'pattern'  => '/\b(?:FFI::cdef|FFI::load|\bdl)\s*\(/i',
			),
		);
	}

	/**
	 * Runs every rule against a chunk of file content. Returns one entry
	 * per matched *rule* with every occurrence (capped) listed under
	 * `matches`, each with a 1-line context snippet (line-numbered,
	 * HTML-escaped by the caller before display -- this method returns
	 * plain text).
	 *
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
				$offset  = $hit[1];
				$line_no = substr_count( substr( $content, 0, $offset ), "\n" ) + 1;
				$snippet = isset( $lines[ $line_no - 1 ] ) ? trim( $lines[ $line_no - 1 ] ) : '';

				$matches[] = array(
					'line'    => $line_no,
					'snippet' => mb_substr( $snippet, 0, 200 ),
				);
			}

			$rules_out[] = array(
				'rule_id'  => $rule['id'],
				'label'    => $rule['label'],
				'severity' => $rule['severity'],
				'matches'  => $matches,
			);
		}

		return $rules_out;
	}
}

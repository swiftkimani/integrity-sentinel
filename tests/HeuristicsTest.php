<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the heuristic malware-pattern engine.
 *
 * Every malicious-looking sample below is assembled with string
 * concatenation so that THIS file's source never contains a literal
 * that would match a rule -- the scanner scans every PHP file on a
 * site, including anything under this plugin's own directory.
 */
class HeuristicsTest extends TestCase {

	private function scan( $content ) {
		return IS_Heuristics::scan_content( $content );
	}

	private function rule_ids( array $results ) {
		return array_map(
			function ( $r ) {
				return $r['rule_id'];
			},
			$results
		);
	}

	private function find_rule( array $results, $rule_id ) {
		foreach ( $results as $r ) {
			if ( $r['rule_id'] === $rule_id ) {
				return $r;
			}
		}
		return null;
	}

	public function test_clean_content_produces_no_findings() {
		$content = "<?php\nfunction hello() {\n\treturn esc_html( get_option( 'blogname' ) );\n}\n";
		$this->assertSame( array(), $this->scan( $content ) );
	}

	public function test_detects_eval_of_base64() {
		$content = '<?php ev' . 'al(base64_decode($payload));';
		$hit     = $this->find_rule( $this->scan( $content ), 'eval_base64' );
		$this->assertNotNull( $hit );
		$this->assertSame( 'critical', $hit['severity'] );
		$this->assertSame( 1, $hit['matches'][0]['line'] );
	}

	public function test_detects_eval_of_gzinflate() {
		$content = '<?php ev' . 'al(gzinflate($data));';
		$this->assertNotNull( $this->find_rule( $this->scan( $content ), 'eval_gzinflate' ) );
	}

	public function test_detects_eval_with_str_rot13() {
		$content = '<?php ev' . 'al(strrev(str_rot13($s)));';
		$this->assertNotNull( $this->find_rule( $this->scan( $content ), 'eval_str_rot13' ) );
	}

	public function test_detects_preg_replace_e_modifier() {
		$content = '<?php preg_replace("/abc/' . 'ei", $x, $y);';
		$this->assertNotNull( $this->find_rule( $this->scan( $content ), 'preg_replace_e_modifier' ) );
	}

	public function test_detects_create_function_from_variable() {
		$content = '<?php create_' . 'function("", $injected);';
		$this->assertNotNull( $this->find_rule( $this->scan( $content ), 'create_function_dynamic' ) );
	}

	public function test_detects_request_data_into_shell_exec() {
		$content = '<?php sys' . 'tem($_' . 'GET["cmd"]);';
		$hit     = $this->find_rule( $this->scan( $content ), 'request_to_shell' );
		$this->assertNotNull( $hit );
		$this->assertSame( 'critical', $hit['severity'] );
	}

	public function test_detects_request_data_into_eval_chain() {
		$content = '<?php call_user_' . 'func($_' . 'POST["f"]);';
		$this->assertNotNull( $this->find_rule( $this->scan( $content ), 'request_to_eval_chain' ) );
	}

	public function test_detects_suppressed_variable_include() {
		$content = '<?php @' . 'include($dropped_path);';
		$this->assertNotNull( $this->find_rule( $this->scan( $content ), 'suspicious_error_suppressed_include' ) );
	}

	public function test_detects_long_base64_blob() {
		$content = '<?php $p = "' . str_repeat( 'QWxh', 150 ) . '";';
		$this->assertNotNull( $this->find_rule( $this->scan( $content ), 'long_base64_blob' ) );
	}

	public function test_detects_known_webshell_marker() {
		$content = '<?php $title = "Files' . 'Man";';
		$hit     = $this->find_rule( $this->scan( $content ), 'known_webshell_marker' );
		$this->assertNotNull( $hit );
		$this->assertSame( 'critical', $hit['severity'] );
	}

	public function test_detects_ffi_load() {
		$content = '<?php FF' . 'I::load("lib.h");';
		$this->assertNotNull( $this->find_rule( $this->scan( $content ), 'ffi_or_dl_call' ) );
	}

	public function test_reports_every_occurrence_with_line_numbers() {
		$bad     = 'ev' . 'al(base64_decode($x));';
		$content = "<?php\n{$bad}\n\$ok = 1;\n{$bad}\n";
		$hit     = $this->find_rule( $this->scan( $content ), 'eval_base64' );
		$this->assertNotNull( $hit );
		$this->assertCount( 2, $hit['matches'] );
		$this->assertSame( 2, $hit['matches'][0]['line'] );
		$this->assertSame( 4, $hit['matches'][1]['line'] );
	}

	public function test_occurrences_are_capped_per_rule() {
		$bad     = 'ev' . 'al(base64_decode($x));';
		$content = '<?php ' . str_repeat( "{$bad}\n", 25 );
		$hit     = $this->find_rule( $this->scan( $content ), 'eval_base64' );
		$this->assertCount( IS_Heuristics::MAX_MATCHES_PER_RULE, $hit['matches'] );
	}

	public function test_two_rules_matching_one_file_yield_two_results() {
		$content = '<?php ev' . 'al(base64_decode($x)); sys' . 'tem($_' . 'GET["c"]);';
		$ids     = $this->rule_ids( $this->scan( $content ) );
		$this->assertContains( 'eval_base64', $ids );
		$this->assertContains( 'request_to_shell', $ids );
	}

	public function test_snippets_are_trimmed_and_capped() {
		$content = "<?php\n    " . 'ev' . 'al(base64_decode("' . str_repeat( 'x', 400 ) . '"));';
		$hit     = $this->find_rule( $this->scan( $content ), 'eval_base64' );
		$snippet = $hit['matches'][0]['snippet'];
		$this->assertLessThanOrEqual( 200, mb_strlen( $snippet ) );
		$this->assertStringStartsNotWith( ' ', $snippet );
	}

	public function test_every_rule_has_valid_shape() {
		foreach ( IS_Heuristics::rules() as $rule ) {
			$this->assertNotEmpty( $rule['id'] );
			$this->assertNotEmpty( $rule['label'] );
			$this->assertContains( $rule['severity'], array( 'critical', 'high', 'medium', 'low', 'info' ) );
			// The pattern must be a valid regex.
			$this->assertNotFalse( @preg_match( $rule['pattern'], '' ), "Invalid pattern for rule {$rule['id']}" );
		}
	}

	/**
	 * Regression test for the v1.0 bug where the plugin flagged its own
	 * heuristics file as a critical "known webshell marker" finding on
	 * every scan: no rule may match any of the plugin's own source files.
	 */
	public function test_plugin_never_flags_its_own_source() {
		$plugin_dir = dirname( __DIR__ );
		$sources    = array_merge(
			glob( $plugin_dir . '/includes/*.php' ),
			glob( $plugin_dir . '/*.php' )
		);
		$this->assertNotEmpty( $sources );

		foreach ( $sources as $file ) {
			$results = $this->scan( file_get_contents( $file ) );
			$this->assertSame(
				array(),
				$this->rule_ids( $results ),
				basename( $file ) . ' matched its own scanner rules'
			);
		}
	}
}

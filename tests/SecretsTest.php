<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Secrets (rule matching,
 * placeholder filtering, variable-assignment detection). Sample secrets
 * below are built via string concatenation so this test file's own
 * literal text never contains a string that would match the scanner --
 * same convention as HeuristicsTest.php.
 */
class SecretsTest extends TestCase {

	// ---- rules() / scan_content -------------------------------------------

	public function test_detects_aws_access_key_id() {
		$content = '<?php $key = "AK' . 'IAIOSFODNN7EXAMPLE";';
		$hits    = IS_Secrets::scan_content( $content );
		$this->assertNotEmpty( $hits );
		$this->assertSame( 'aws_access_key_id', $hits[0]['rule_id'] );
		$this->assertSame( 'critical', $hits[0]['severity'] );
	}

	public function test_detects_private_key_pem_block() {
		$content = "<?php\n-----BEGIN RSA " . "PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----";
		$hits    = IS_Secrets::scan_content( $content );
		$rule_ids = array_column( $hits, 'rule_id' );
		$this->assertContains( 'private_key_pem_block', $rule_ids );
	}

	public function test_detects_github_token() {
		$content = '<?php $t = "gh' . 'p_' . str_repeat( 'a', 40 ) . '";';
		$hits    = IS_Secrets::scan_content( $content );
		$rule_ids = array_column( $hits, 'rule_id' );
		$this->assertContains( 'github_token', $rule_ids );
	}

	public function test_detects_slack_token() {
		$content = '<?php $t = "xo' . 'xb-' . str_repeat( '1', 15 ) . '";';
		$hits    = IS_Secrets::scan_content( $content );
		$rule_ids = array_column( $hits, 'rule_id' );
		$this->assertContains( 'slack_token', $rule_ids );
	}

	public function test_detects_stripe_live_key() {
		$content = '<?php $t = "sk' . '_live_' . str_repeat( 'a', 24 ) . '";';
		$hits    = IS_Secrets::scan_content( $content );
		$rule_ids = array_column( $hits, 'rule_id' );
		$this->assertContains( 'stripe_live_key', $rule_ids );
	}

	public function test_detects_google_api_key() {
		$content = '<?php $t = "AI' . 'za' . str_repeat( 'a', 35 ) . '";';
		$hits    = IS_Secrets::scan_content( $content );
		$rule_ids = array_column( $hits, 'rule_id' );
		$this->assertContains( 'google_api_key', $rule_ids );
	}

	public function test_clean_file_has_no_hits() {
		$content = "<?php\nfunction greet( \$name ) {\n\treturn 'Hello, ' . \$name;\n}\n";
		$this->assertSame( array(), IS_Secrets::scan_content( $content ) );
	}

	public function test_matches_include_line_and_snippet() {
		$content = "<?php\n\$key = \"AK" . 'IAIOSFODNN7EXAMPLE";';
		$hits    = IS_Secrets::scan_content( $content );
		$this->assertSame( 2, $hits[0]['matches'][0]['line'] );
		$this->assertNotEmpty( $hits[0]['matches'][0]['snippet'] );
	}

	// ---- is_scannable_extension --------------------------------------------

	public function test_scannable_extensions() {
		$this->assertTrue( IS_Secrets::is_scannable_extension( 'wp-config.php' ) );
		$this->assertTrue( IS_Secrets::is_scannable_extension( '.env' ) );
		$this->assertTrue( IS_Secrets::is_scannable_extension( 'config.yml' ) );
		$this->assertTrue( IS_Secrets::is_scannable_extension( 'settings.json' ) );
	}

	public function test_unscannable_extensions() {
		$this->assertFalse( IS_Secrets::is_scannable_extension( 'photo.jpg' ) );
		$this->assertFalse( IS_Secrets::is_scannable_extension( 'style.css' ) );
		$this->assertFalse( IS_Secrets::is_scannable_extension( 'readme.md' ) );
	}

	// ---- is_placeholder_value --------------------------------------------------

	public function test_placeholder_values() {
		$this->assertTrue( IS_Secrets::is_placeholder_value( 'CHANGE_ME' ) );
		$this->assertTrue( IS_Secrets::is_placeholder_value( 'your_api_key_here' ) );
		$this->assertTrue( IS_Secrets::is_placeholder_value( 'xxxxxxxxxxxx' ) );
		$this->assertTrue( IS_Secrets::is_placeholder_value( '000000000000' ) );
		$this->assertTrue( IS_Secrets::is_placeholder_value( 'aaaaaaaaaaaaaaaa' ) ); // repeated char, whatever it is
	}

	public function test_non_placeholder_value() {
		$this->assertFalse( IS_Secrets::is_placeholder_value( 'Zx9$kLp2#mQ7wR4t' ) );
	}

	// ---- find_variable_assigned_secrets --------------------------------------------

	public function test_finds_high_entropy_credential_named_variable() {
		$content = '<?php $api_key = "' . 'Zx9pKq2wRmL7tYv4bNc8dFg1' . '";';
		$hits    = IS_Secrets::find_variable_assigned_secrets( $content );
		$this->assertNotEmpty( $hits );
	}

	public function test_ignores_short_values() {
		$content = '<?php $api_key = "short";';
		$this->assertSame( array(), IS_Secrets::find_variable_assigned_secrets( $content ) );
	}

	public function test_ignores_placeholder_variable_value() {
		$content = '<?php $secret_token = "' . str_repeat( 'CHANGE_ME_', 3 ) . '";';
		$this->assertSame( array(), IS_Secrets::find_variable_assigned_secrets( $content ) );
	}

	public function test_ignores_unrelated_variable_names() {
		$content = '<?php $long_description = "' . 'This is just a normal, ordinary sentence of text.' . '";';
		$this->assertSame( array(), IS_Secrets::find_variable_assigned_secrets( $content ) );
	}
}

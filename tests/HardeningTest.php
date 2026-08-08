<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of the hardening layer. The
 * WP-dependent checks (loopback requests, user queries) are exercised
 * in a real WordPress, not here.
 */
class HardeningTest extends TestCase {

	// ---- salt validation -------------------------------------------

	public function test_undefined_salt_is_weak() {
		$this->assertTrue( IS_Hardening::is_weak_salt_value( '' ) );
		$this->assertTrue( IS_Hardening::is_weak_salt_value( null ) );
	}

	public function test_placeholder_salt_is_weak() {
		$this->assertTrue( IS_Hardening::is_weak_salt_value( 'put your unique phrase here' ) );
		$this->assertTrue( IS_Hardening::is_weak_salt_value( 'PUT YOUR UNIQUE PHRASE HERE padding padding' ) );
	}

	public function test_short_salt_is_weak() {
		$this->assertTrue( IS_Hardening::is_weak_salt_value( 'tooshort' ) );
	}

	public function test_real_salt_is_accepted() {
		$this->assertFalse( IS_Hardening::is_weak_salt_value( 'x#K9$mP2@vL5!qR8&wT1*yU4^zA7%bC0(dE3)fG6' ) );
	}

	// ---- backup archive matching -----------------------------------

	public function test_database_dumps_and_archives_match() {
		foreach ( array( 'backup.sql', 'site.SQL', 'dump.sql.gz', 'site.zip', 'old.tar.gz', 'files.tgz', 'wp-config.php.bak' ) as $name ) {
			$this->assertTrue( IS_Hardening::looks_like_backup_file( $name ), "$name should match" );
		}
	}

	public function test_normal_webroot_files_do_not_match() {
		foreach ( array( 'index.php', 'readme.txt', 'photo.jpg', 'style.css', 'license.txt', 'sqlite.php' ) as $name ) {
			$this->assertFalse( IS_Hardening::looks_like_backup_file( $name ), "$name should not match" );
		}
	}

	// ---- uploads .htaccess block content ---------------------------

	public function test_block_rules_are_marker_delimited() {
		$rules = IS_Hardening::block_rules();
		$this->assertStringStartsWith( IS_Hardening::BLOCK_BEGIN, $rules );
		$this->assertStringContainsString( IS_Hardening::BLOCK_END, $rules );
	}

	public function test_block_rules_cover_php_variants_and_both_apache_generations() {
		$rules = IS_Hardening::block_rules();
		$this->assertStringContainsString( 'phtml', $rules );
		$this->assertStringContainsString( 'Require all denied', $rules );
		$this->assertStringContainsString( 'Deny from all', $rules );
	}

	public function test_nginx_snippet_denies_uploads_php() {
		$snippet = IS_Hardening::nginx_snippet();
		$this->assertStringContainsString( 'uploads', $snippet );
		$this->assertStringContainsString( 'deny all', $snippet );
	}

	// ---- dangerous shell functions ----------------------------------

	public function test_all_dangerous_functions_reported_when_none_disabled() {
		$this->assertSame( IS_Hardening::DANGEROUS_SHELL_FUNCTIONS, IS_Hardening::still_enabled_dangerous_functions( '' ) );
	}

	public function test_disabled_functions_are_excluded() {
		$still = IS_Hardening::still_enabled_dangerous_functions( 'exec,shell_exec,system' );
		$this->assertNotContains( 'exec', $still );
		$this->assertNotContains( 'shell_exec', $still );
		$this->assertContains( 'proc_open', $still );
	}

	public function test_all_disabled_reports_none_still_enabled() {
		$this->assertSame( array(), IS_Hardening::still_enabled_dangerous_functions( implode( ',', IS_Hardening::DANGEROUS_SHELL_FUNCTIONS ) ) );
	}

	public function test_handles_whitespace_around_entries() {
		$still = IS_Hardening::still_enabled_dangerous_functions( ' exec , shell_exec ,system ' );
		$this->assertNotContains( 'exec', $still );
		$this->assertNotContains( 'system', $still );
	}

	// ---- duplicate_salt_names -------------------------------------------

	public function test_no_duplicates_among_distinct_salts() {
		$salts = array(
			'AUTH_KEY'   => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
			'AUTH_SALT'  => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
		);
		$this->assertSame( array(), IS_Hardening::duplicate_salt_names( $salts ) );
	}

	public function test_flags_two_identical_salts() {
		$salts = array(
			'AUTH_KEY'  => 'same-value-same-value-same-value',
			'AUTH_SALT' => 'same-value-same-value-same-value',
		);
		$result = IS_Hardening::duplicate_salt_names( $salts );
		$this->assertContains( 'AUTH_KEY', $result );
		$this->assertContains( 'AUTH_SALT', $result );
		$this->assertCount( 2, $result );
	}

	public function test_ignores_empty_or_non_string_values() {
		$salts = array(
			'AUTH_KEY'  => '',
			'AUTH_SALT' => null,
		);
		$this->assertSame( array(), IS_Hardening::duplicate_salt_names( $salts ) );
	}

	public function test_three_way_duplicate_lists_all_three_once() {
		$salts = array(
			'AUTH_KEY'        => 'dupe',
			'AUTH_SALT'       => 'dupe',
			'SECURE_AUTH_KEY' => 'dupe',
			'NONCE_KEY'       => 'unique',
		);
		$result = IS_Hardening::duplicate_salt_names( $salts );
		sort( $result );
		$this->assertSame( array( 'AUTH_KEY', 'AUTH_SALT', 'SECURE_AUTH_KEY' ), $result );
	}

	// ---- options_with_plaintext_secrets -----------------------------------

	public function test_flags_an_option_with_a_non_empty_api_key() {
		$all = array( 'is_vulnerability_scanner_settings' => array( 'api_key' => 'abc123' ) );
		$this->assertSame( array( 'is_vulnerability_scanner_settings' ), IS_Hardening::options_with_plaintext_secrets( $all ) );
	}

	public function test_ignores_an_option_with_no_secret_configured() {
		$all = array( 'is_vulnerability_scanner_settings' => array( 'api_key' => '' ) );
		$this->assertSame( array(), IS_Hardening::options_with_plaintext_secrets( $all ) );
	}

	public function test_flags_multiple_secret_fields_in_one_option() {
		$all = array( 'is_threat_intel_settings' => array( 'abuseipdb_key' => 'x', 'virustotal_key' => 'y' ) );
		$this->assertSame( array( 'is_threat_intel_settings' ), IS_Hardening::options_with_plaintext_secrets( $all ) );
	}

	public function test_flags_each_option_at_most_once() {
		$all = array(
			'is_vulnerability_scanner_settings' => array( 'api_key' => 'abc123' ),
			'is_threat_intel_settings'          => array( 'abuseipdb_key' => 'x' ),
		);
		$this->assertSame( array( 'is_vulnerability_scanner_settings', 'is_threat_intel_settings' ), IS_Hardening::options_with_plaintext_secrets( $all ) );
	}
}

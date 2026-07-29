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
}

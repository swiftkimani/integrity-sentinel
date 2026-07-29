<?php
use PHPUnit\Framework\TestCase;

/**
 * Guards the self-integrity manifest: if a runtime file changes without
 * `php bin/make-manifest.php` being re-run, the shipped scanner would
 * flag ITSELF as tampered on every site. This test (and the same check
 * in CI) makes that impossible to forget.
 */
class ManifestTest extends TestCase {

	public function test_manifest_matches_the_actual_runtime_files() {
		$root     = dirname( __DIR__ );
		$manifest = json_decode( (string) file_get_contents( $root . '/integrity-manifest.json' ), true );

		$this->assertIsArray( $manifest, 'integrity-manifest.json is missing or invalid — run: php bin/make-manifest.php' );
		$this->assertNotEmpty( $manifest );

		$patterns = array( '*.php', 'includes/*.php', 'assets/js/*.js', 'assets/css/*.css' );
		$actual   = array();
		foreach ( $patterns as $pattern ) {
			foreach ( (array) glob( $root . '/' . $pattern ) as $abs ) {
				$rel            = ltrim( substr( $abs, strlen( $root ) ), '/' );
				$actual[ $rel ] = hash_file( 'sha256', $abs );
			}
		}
		ksort( $actual );

		$this->assertSame( $actual, $manifest, 'integrity-manifest.json is stale — run: php bin/make-manifest.php' );
	}
}

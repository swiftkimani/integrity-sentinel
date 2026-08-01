<?php
/**
 * Regenerates integrity-manifest.json — the sha256 manifest the scanner
 * uses to verify its OWN files at scan time (see
 * IS_Scanner::check_self_integrity()).
 *
 * Run after any change to a runtime file, before release:
 *   php bin/make-manifest.php          (rewrite the manifest)
 *   php bin/make-manifest.php --check  (exit 1 if the manifest is stale — used in CI)
 *
 * Covers runtime files only (root PHP, includes/, assets/); dev files
 * (tests/, bin/, languages/) are deliberately excluded.
 */

$root     = dirname( __DIR__ );
$patterns = array( '*.php', 'includes/*.php', 'assets/js/*.js', 'assets/css/*.css' );

$manifest = array();
foreach ( $patterns as $pattern ) {
	foreach ( (array) glob( $root . '/' . $pattern ) as $abs ) {
		$rel              = ltrim( substr( $abs, strlen( $root ) ), '/' );
		$manifest[ $rel ] = hash_file( 'sha256', $abs );
	}
}
ksort( $manifest );

$path = $root . '/integrity-manifest.json';
$json = json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";

if ( in_array( '--check', $argv, true ) ) {
	if ( ! file_exists( $path ) || file_get_contents( $path ) !== $json ) {
		fwrite( STDERR, "integrity-manifest.json is stale — run: php bin/make-manifest.php\n" );
		exit( 1 );
	}
	echo "integrity-manifest.json is up to date.\n";
	exit( 0 );
}

file_put_contents( $path, $json );
echo 'Wrote ' . count( $manifest ) . " entries to integrity-manifest.json\n";

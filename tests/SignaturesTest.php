<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure parts of IS_Signatures. scan_content() itself
 * needs get_option() (WP-dependent) and is exercised in a real
 * WordPress, not here.
 */
class SignaturesTest extends TestCase {

	const VALID_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

	public function test_parses_a_bare_hash() {
		$out = IS_Signatures::parse_hash_list( self::VALID_HASH );
		$this->assertSame( array( self::VALID_HASH => '' ), $out );
	}

	public function test_parses_a_hash_with_a_label() {
		$out = IS_Signatures::parse_hash_list( self::VALID_HASH . '  # known webshell' );
		$this->assertSame( array( self::VALID_HASH => 'known webshell' ), $out );
	}

	public function test_lowercases_the_hash() {
		$out = IS_Signatures::parse_hash_list( strtoupper( self::VALID_HASH ) );
		$this->assertArrayHasKey( self::VALID_HASH, $out );
	}

	public function test_ignores_malformed_lines() {
		$out = IS_Signatures::parse_hash_list( "not-a-hash\ntoo-short-abc123\n" );
		$this->assertSame( array(), $out );
	}

	public function test_ignores_blank_lines_and_comment_only_lines() {
		$out = IS_Signatures::parse_hash_list( "\n# just a comment\n" . self::VALID_HASH );
		$this->assertSame( array( self::VALID_HASH => '' ), $out );
	}

	public function test_parses_multiple_lines() {
		$other = str_repeat( 'a', 64 );
		$out   = IS_Signatures::parse_hash_list( self::VALID_HASH . "\n" . $other . ' # other' );
		$this->assertCount( 2, $out );
		$this->assertSame( '', $out[ self::VALID_HASH ] );
		$this->assertSame( 'other', $out[ $other ] );
	}

	public function test_match_hash_finds_a_known_hash() {
		$known = array( self::VALID_HASH => 'a label' );
		$this->assertSame( 'a label', IS_Signatures::match_hash( self::VALID_HASH, $known ) );
	}

	public function test_match_hash_is_case_insensitive() {
		$known = array( self::VALID_HASH => '' );
		$this->assertSame( '', IS_Signatures::match_hash( strtoupper( self::VALID_HASH ), $known ) );
	}

	public function test_match_hash_returns_null_when_absent() {
		$known = array( self::VALID_HASH => '' );
		$this->assertNull( IS_Signatures::match_hash( str_repeat( 'b', 64 ), $known ) );
	}
}

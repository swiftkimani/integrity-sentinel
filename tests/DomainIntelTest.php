<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Domain_Intel (typosquat
 * variant generation, crt.sh URL/response parsing). The WP-dependent
 * glue (DNS lookups, the crt.sh HTTP request, transient caching) is
 * exercised in a real WordPress, not here.
 */
class DomainIntelTest extends TestCase {

	// ---- normalize_domain / split_domain -----------------------------------

	public function test_normalize_domain_lowercases_and_strips_www() {
		$this->assertSame( 'example.com', IS_Domain_Intel::normalize_domain( 'WWW.Example.COM' ) );
		$this->assertSame( 'example.com', IS_Domain_Intel::normalize_domain( ' example.com ' ) );
	}

	public function test_split_domain_splits_on_last_dot() {
		$this->assertSame( array( 'example', 'com' ), IS_Domain_Intel::split_domain( 'example.com' ) );
	}

	public function test_split_domain_with_no_dot_returns_empty_tld() {
		$this->assertSame( array( 'localhost', '' ), IS_Domain_Intel::split_domain( 'localhost' ) );
	}

	// ---- adjacent_swap_variants ---------------------------------------------

	public function test_adjacent_swap_variants() {
		$variants = IS_Domain_Intel::adjacent_swap_variants( 'abc' );
		$this->assertContains( 'bac', $variants );
		$this->assertContains( 'acb', $variants );
		$this->assertCount( 2, $variants );
	}

	public function test_adjacent_swap_skips_identical_neighbors() {
		$variants = IS_Domain_Intel::adjacent_swap_variants( 'aab' );
		$this->assertNotContains( 'aab', $variants );
	}

	// ---- omission_variants ----------------------------------------------------

	public function test_omission_variants() {
		$variants = IS_Domain_Intel::omission_variants( 'abc' );
		$this->assertContains( 'bc', $variants );
		$this->assertContains( 'ac', $variants );
		$this->assertContains( 'ab', $variants );
	}

	public function test_omission_variants_never_empty_string() {
		$variants = IS_Domain_Intel::omission_variants( 'a' );
		$this->assertSame( array(), $variants );
	}

	// ---- duplication_variants --------------------------------------------------

	public function test_duplication_variants() {
		$variants = IS_Domain_Intel::duplication_variants( 'ab' );
		$this->assertContains( 'aab', $variants );
		$this->assertContains( 'abb', $variants );
	}

	// ---- homoglyph_variants ---------------------------------------------------

	public function test_homoglyph_variants_substitutes_known_characters() {
		$variants = IS_Domain_Intel::homoglyph_variants( 'lots' );
		$this->assertContains( '1ots', $variants ); // l -> 1
		$this->assertContains( 'lot5', $variants ); // s -> 5
	}

	public function test_homoglyph_variants_empty_for_no_matching_characters() {
		$this->assertSame( array(), IS_Domain_Intel::homoglyph_variants( 'xyz' ) );
	}

	// ---- tld_swap_variants ------------------------------------------------------

	public function test_tld_swap_variants() {
		$variants = IS_Domain_Intel::tld_swap_variants( 'example', array( 'net', 'org' ) );
		$this->assertSame( array( 'example.net', 'example.org' ), $variants );
	}

	// ---- generate_variants -----------------------------------------------------

	public function test_generate_variants_excludes_the_real_domain() {
		$variants = IS_Domain_Intel::generate_variants( 'example.com' );
		$this->assertNotContains( 'example.com', $variants );
	}

	public function test_generate_variants_includes_a_tld_swap() {
		$variants = IS_Domain_Intel::generate_variants( 'example.com', array( 'net' ) );
		$this->assertContains( 'example.net', $variants );
	}

	public function test_generate_variants_includes_a_label_variant_with_original_tld() {
		$variants = IS_Domain_Intel::generate_variants( 'example.com', array() );
		$this->assertContains( 'exmaple.com', $variants ); // adjacent swap of 'a' and 'm'
	}

	public function test_generate_variants_is_capped() {
		$variants = IS_Domain_Intel::generate_variants( 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com' );
		$this->assertLessThanOrEqual( IS_Domain_Intel::MAX_VARIANTS, count( $variants ) );
	}

	public function test_generate_variants_empty_for_domain_without_tld() {
		$this->assertSame( array(), IS_Domain_Intel::generate_variants( 'localhost' ) );
	}

	// ---- crtsh_query_url --------------------------------------------------------

	public function test_crtsh_query_url() {
		$this->assertSame(
			'https://crt.sh/?q=example.com&output=json',
			IS_Domain_Intel::crtsh_query_url( 'example.com' )
		);
	}

	// ---- parse_crtsh_response --------------------------------------------------

	public function test_parse_crtsh_response_extracts_expected_fields() {
		$body = array(
			array(
				'common_name'     => 'evil-example.com',
				'issuer_name'     => "C=US, O=Let's Encrypt, CN=R3",
				'entry_timestamp' => '2026-01-01T00:00:00',
			),
		);
		$this->assertSame(
			array(
				array(
					'domain'    => 'evil-example.com',
					'issuer'    => "C=US, O=Let's Encrypt, CN=R3",
					'timestamp' => '2026-01-01T00:00:00',
				),
			),
			IS_Domain_Intel::parse_crtsh_response( $body )
		);
	}

	public function test_parse_crtsh_response_skips_rows_without_a_common_name() {
		$this->assertSame( array(), IS_Domain_Intel::parse_crtsh_response( array( array( 'issuer_name' => 'x' ) ) ) );
	}

	public function test_parse_crtsh_response_non_array_body() {
		$this->assertSame( array(), IS_Domain_Intel::parse_crtsh_response( null ) );
		$this->assertSame( array(), IS_Domain_Intel::parse_crtsh_response( 'not json' ) );
	}
}

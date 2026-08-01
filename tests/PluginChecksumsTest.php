<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the defensive parsing of WordPress.org's plugin
 * checksum endpoint, whose JSON shape has changed over the years.
 */
class PluginChecksumsTest extends TestCase {

	private function normalize( $body ) {
		return ( new IS_Plugin_Checksums() )->normalize_response( $body );
	}

	public function test_documented_shape_with_md5_and_sha256() {
		$result = $this->normalize(
			array(
				'files' => array(
					'plugin.php'  => array(
						'md5'    => 'aaa',
						'sha256' => 'bbb',
					),
					'readme.txt'  => array( 'md5' => 'ccc' ),
				),
			)
		);
		$this->assertSame( array( 'aaa', 'bbb' ), $result['plugin.php'] );
		$this->assertSame( array( 'ccc' ), $result['readme.txt'] );
	}

	public function test_legacy_flat_shape() {
		$result = $this->normalize( array( 'plugin.php' => 'aaa' ) );
		$this->assertSame( array( 'aaa' ), $result['plugin.php'] );
	}

	public function test_multiple_acceptable_hashes_as_list() {
		$result = $this->normalize(
			array( 'files' => array( 'readme.txt' => array( 'aaa', 'bbb' ) ) )
		);
		$this->assertSame( array( 'aaa', 'bbb' ), $result['readme.txt'] );
	}

	public function test_non_string_hash_values_are_dropped() {
		$result = $this->normalize(
			array( 'files' => array( 'a.php' => array( 'md5' => 'aaa', 'weird' => array( 'nested' ) ) ) )
		);
		$this->assertSame( array( 'aaa' ), $result['a.php'] );
	}

	public function test_invalid_json_body_is_an_error() {
		$this->assertTrue( is_wp_error( $this->normalize( null ) ) );
		$this->assertTrue( is_wp_error( $this->normalize( 'not-an-array' ) ) );
	}

	public function test_empty_file_list_is_an_error() {
		$this->assertTrue( is_wp_error( $this->normalize( array( 'files' => array() ) ) ) );
		$this->assertTrue( is_wp_error( $this->normalize( array() ) ) );
	}

	public function test_unrecognized_entry_shapes_are_an_error_not_a_guess() {
		$result = $this->normalize( array( 'files' => array( 'a.php' => 12345 ) ) );
		$this->assertTrue( is_wp_error( $result ) );
	}
}

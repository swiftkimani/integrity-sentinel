<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic piece of IS_Upload_Guard. The
 * WP-dependent glue (the actual upload-filter hook) is exercised in a
 * real WordPress, not here.
 */
class UploadGuardTest extends TestCase {

	public function test_plain_php_extension_is_dangerous() {
		$this->assertTrue( IS_Upload_Guard::filename_has_dangerous_extension( 'shell.php' ) );
	}

	public function test_double_extension_disguise_is_still_dangerous() {
		$this->assertTrue( IS_Upload_Guard::filename_has_dangerous_extension( 'shell.php.jpg' ) );
		$this->assertTrue( IS_Upload_Guard::filename_has_dangerous_extension( 'shell.jpg.php' ) );
	}

	public function test_case_insensitive() {
		$this->assertTrue( IS_Upload_Guard::filename_has_dangerous_extension( 'shell.PHP' ) );
		$this->assertTrue( IS_Upload_Guard::filename_has_dangerous_extension( 'shell.PhP5' ) );
	}

	public function test_ordinary_media_files_are_not_flagged() {
		foreach ( array( 'photo.jpg', 'document.pdf', 'archive.zip', 'notes.docx', 'video.mp4' ) as $name ) {
			$this->assertFalse( IS_Upload_Guard::filename_has_dangerous_extension( $name ), "$name should not be flagged" );
		}
	}

	public function test_multi_dot_filenames_without_a_dangerous_segment_are_safe() {
		$this->assertFalse( IS_Upload_Guard::filename_has_dangerous_extension( 'my.notes.final.v2.docx' ) );
	}

	public function test_various_scripting_extensions_are_dangerous() {
		foreach ( array( 'x.phtml', 'x.phar', 'x.cgi', 'x.pl', 'x.py', 'x.sh', 'x.asp', 'x.aspx', 'x.jsp' ) as $name ) {
			$this->assertTrue( IS_Upload_Guard::filename_has_dangerous_extension( $name ), "$name should be flagged" );
		}
	}
}

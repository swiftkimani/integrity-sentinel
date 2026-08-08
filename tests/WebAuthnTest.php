<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_WebAuthn. Everything else
 * (the actual registration/authentication ceremonies) is glue around
 * web-auth/webauthn-lib -- gated behind is_available() (PHP 8.2+ and the
 * vendored library loaded) and exercised live, not here, same
 * convention as every other WP-dependent glue in this codebase.
 */
class WebAuthnTest extends TestCase {

	public function test_credential_label_uses_stored_label_when_present() {
		$entry = array( 'label' => 'My YubiKey' );
		$this->assertSame( 'My YubiKey', IS_WebAuthn::credential_label( $entry, 0 ) );
	}

	public function test_credential_label_falls_back_to_position_when_blank() {
		$entry = array( 'label' => '' );
		$this->assertSame( 'Security key #1', IS_WebAuthn::credential_label( $entry, 0 ) );
		$this->assertSame( 'Security key #3', IS_WebAuthn::credential_label( $entry, 2 ) );
	}

	public function test_credential_label_falls_back_when_missing_entirely() {
		$this->assertSame( 'Security key #1', IS_WebAuthn::credential_label( array(), 0 ) );
	}

	public function test_credential_label_trims_whitespace_only_label() {
		$entry = array( 'label' => '   ' );
		$this->assertSame( 'Security key #1', IS_WebAuthn::credential_label( $entry, 0 ) );
	}
}

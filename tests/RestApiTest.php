<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Rest_API. The WP-dependent
 * parts (the actual rest_pre_dispatch/template_redirect hooks) are
 * exercised in a real WordPress, not here.
 */
class RestApiTest extends TestCase {

	public function test_detects_users_collection_route() {
		$this->assertTrue( IS_Rest_API::is_user_enumeration_route( '/wp/v2/users' ) );
	}

	public function test_detects_single_user_route() {
		$this->assertTrue( IS_Rest_API::is_user_enumeration_route( '/wp/v2/users/1' ) );
	}

	public function test_does_not_flag_unrelated_routes() {
		$this->assertFalse( IS_Rest_API::is_user_enumeration_route( '/wp/v2/posts' ) );
		$this->assertFalse( IS_Rest_API::is_user_enumeration_route( '/wp/v2/users-export' ) );
	}

	public function test_own_namespace_always_allowlisted() {
		$this->assertTrue( IS_Rest_API::route_is_allowlisted( '/integrity-sentinel/v1/posts', array() ) );
	}

	public function test_admin_configured_prefix_is_allowlisted() {
		$this->assertTrue( IS_Rest_API::route_is_allowlisted( '/wp/v2/oembed/1.0/embed', array( 'wp/v2/oembed' ) ) );
	}

	public function test_route_not_in_allowlist_is_rejected() {
		$this->assertFalse( IS_Rest_API::route_is_allowlisted( '/wp/v2/posts', array( 'wp/v2/oembed' ) ) );
	}

	public function test_parse_route_list_ignores_blank_lines() {
		$this->assertSame( array( 'wp/v2/oembed', 'contact-form-7/v1' ), IS_Rest_API::parse_route_list( "wp/v2/oembed\n\ncontact-form-7/v1\n" ) );
	}
}

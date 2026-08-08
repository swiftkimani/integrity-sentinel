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

	// ---- numeric_id_route_match (enumeration detection) --------------------

	public function test_matches_a_single_numeric_id_route() {
		$match = IS_Rest_API::numeric_id_route_match( '/wp/v2/posts/42' );
		$this->assertSame( array( 'type' => 'posts', 'id' => 42 ), $match );
	}

	public function test_matches_every_covered_collection() {
		foreach ( array( 'posts', 'pages', 'users', 'comments', 'media' ) as $type ) {
			$match = IS_Rest_API::numeric_id_route_match( "/wp/v2/{$type}/7" );
			$this->assertSame( $type, $match['type'] );
			$this->assertSame( 7, $match['id'] );
		}
	}

	public function test_does_not_match_a_collection_route_without_an_id() {
		$this->assertNull( IS_Rest_API::numeric_id_route_match( '/wp/v2/posts' ) );
	}

	public function test_does_not_match_a_non_numeric_slug() {
		$this->assertNull( IS_Rest_API::numeric_id_route_match( '/wp/v2/posts/my-post-slug' ) );
	}

	public function test_does_not_match_unrelated_namespaces() {
		$this->assertNull( IS_Rest_API::numeric_id_route_match( '/integrity-sentinel/v1/posts/1' ) );
	}

	// ---- route_methods (attack-surface audit) --------------------------------

	public function test_route_methods_from_assoc_shape() {
		$this->assertSame( array( 'GET', 'POST' ), IS_Rest_API::route_methods( array( 'methods' => array( 'GET' => true, 'POST' => true ) ) ) );
	}

	public function test_route_methods_from_comma_string_shape() {
		$this->assertSame( array( 'GET', 'POST' ), IS_Rest_API::route_methods( array( 'methods' => 'GET, POST' ) ) );
	}

	public function test_route_methods_from_flat_list_shape() {
		$this->assertSame( array( 'GET', 'POST' ), IS_Rest_API::route_methods( array( 'methods' => array( 'GET', 'POST' ) ) ) );
	}

	public function test_route_methods_missing_key_is_empty() {
		$this->assertSame( array(), IS_Rest_API::route_methods( array() ) );
	}

	// ---- is_route_unprotected --------------------------------------------------

	public function test_missing_permission_callback_is_unprotected() {
		$this->assertTrue( IS_Rest_API::is_route_unprotected( array() ) );
	}

	public function test_return_true_permission_callback_is_unprotected() {
		$this->assertTrue( IS_Rest_API::is_route_unprotected( array( 'permission_callback' => '__return_true' ) ) );
	}

	public function test_null_permission_callback_is_unprotected() {
		$this->assertTrue( IS_Rest_API::is_route_unprotected( array( 'permission_callback' => null ) ) );
	}

	public function test_real_permission_callback_is_protected() {
		$this->assertFalse( IS_Rest_API::is_route_unprotected( array( 'permission_callback' => 'is_user_logged_in' ) ) );
	}

	// ---- route_finding_severity --------------------------------------------

	public function test_unprotected_write_route_is_high() {
		$this->assertSame( 'high', IS_Rest_API::route_finding_severity( array( 'POST' ), true ) );
	}

	public function test_unprotected_read_only_route_is_info() {
		$this->assertSame( 'info', IS_Rest_API::route_finding_severity( array( 'GET' ), true ) );
	}

	public function test_protected_route_is_null_regardless_of_methods() {
		$this->assertNull( IS_Rest_API::route_finding_severity( array( 'POST' ), false ) );
	}

	public function test_mixed_methods_with_a_write_method_is_high() {
		$this->assertSame( 'high', IS_Rest_API::route_finding_severity( array( 'GET', 'DELETE' ), true ) );
	}

	// ---- classify_routes --------------------------------------------------------

	public function test_classify_routes_flattens_unprotected_handlers() {
		$routes = array(
			'/wp/v2/posts'         => array(
				array( 'methods' => array( 'GET' => true ), 'permission_callback' => '__return_true' ),
				array( 'methods' => array( 'POST' => true ), 'permission_callback' => 'is_user_logged_in' ),
			),
			'/my-plugin/v1/action' => array(
				array( 'methods' => array( 'POST' => true ), 'permission_callback' => '__return_true' ),
			),
		);
		$result = IS_Rest_API::classify_routes( $routes );
		$this->assertCount( 2, $result );
		$this->assertSame( '/wp/v2/posts', $result[0]['route'] );
		$this->assertSame( 'info', $result[0]['severity'] );
		$this->assertSame( '/my-plugin/v1/action', $result[1]['route'] );
		$this->assertSame( 'high', $result[1]['severity'] );
	}

	public function test_classify_routes_skips_protected_handlers_entirely() {
		$routes = array(
			'/wp/v2/settings' => array(
				array( 'methods' => array( 'GET' => true ), 'permission_callback' => 'is_user_logged_in' ),
			),
		);
		$this->assertSame( array(), IS_Rest_API::classify_routes( $routes ) );
	}

	public function test_classify_routes_excludes_core_batch_endpoint() {
		// Confirmed via live testing: WordPress core's own /batch/v1 has
		// no top-level permission_callback by design -- it re-checks each
		// sub-request against its own target route's real check.
		$routes = array(
			'/batch/v1' => array(
				array( 'methods' => array( 'POST' => true ), 'permission_callback' => '__return_true' ),
			),
		);
		$this->assertSame( array(), IS_Rest_API::classify_routes( $routes ) );
	}

	// ---- route_excluded_from_audit -----------------------------------------

	public function test_route_excluded_when_prefix_matches() {
		$this->assertTrue( IS_Rest_API::route_excluded_from_audit( '/wc/store/v1/cart', array( 'wc/store' ) ) );
	}

	public function test_route_not_excluded_when_no_prefix_matches() {
		$this->assertFalse( IS_Rest_API::route_excluded_from_audit( '/wp/v2/posts', array( 'wc/store' ) ) );
	}
}

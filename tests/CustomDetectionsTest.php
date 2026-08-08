<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure logic in IS_Custom_Detections. evaluate_rules()
 * itself needs get_option()/IS_Audit_Log/IS_Detections (WP-dependent)
 * and is exercised in a real WordPress, not here.
 */
class CustomDetectionsTest extends TestCase {

	const MINUTE = 60;

	// ---- cooldown_elapsed ----------------------------------------------

	public function test_never_fired_is_always_eligible() {
		$this->assertTrue( IS_Custom_Detections::cooldown_elapsed( 0, 1000000, 15 ) );
	}

	public function test_within_cooldown_is_not_eligible() {
		$last_fired = 1000000 - ( 5 * self::MINUTE );
		$this->assertFalse( IS_Custom_Detections::cooldown_elapsed( $last_fired, 1000000, 15 ) );
	}

	public function test_past_cooldown_is_eligible() {
		$last_fired = 1000000 - ( 20 * self::MINUTE );
		$this->assertTrue( IS_Custom_Detections::cooldown_elapsed( $last_fired, 1000000, 15 ) );
	}

	public function test_exactly_at_cooldown_boundary_is_eligible() {
		$last_fired = 1000000 - ( 15 * self::MINUTE );
		$this->assertTrue( IS_Custom_Detections::cooldown_elapsed( $last_fired, 1000000, 15 ) );
	}

	// ---- rule_triggered --------------------------------------------------

	public function test_below_threshold_is_not_triggered() {
		$this->assertFalse( IS_Custom_Detections::rule_triggered( 4, 5 ) );
	}

	public function test_at_threshold_is_triggered() {
		$this->assertTrue( IS_Custom_Detections::rule_triggered( 5, 5 ) );
	}

	public function test_above_threshold_is_triggered() {
		$this->assertTrue( IS_Custom_Detections::rule_triggered( 100, 5 ) );
	}

	// ---- rule_slug -----------------------------------------------------------

	public function test_generates_a_stable_slug_per_index() {
		$this->assertSame( 'custom_0', IS_Custom_Detections::rule_slug( 0 ) );
		$this->assertSame( 'custom_3', IS_Custom_Detections::rule_slug( 3 ) );
	}

	// ---- parse_rules_text ----------------------------------------------------

	public function test_parses_a_single_well_formed_rule() {
		$rules = IS_Custom_Detections::parse_rules_text( 'login_failed | 20 | 15 | high' );
		$this->assertCount( 1, $rules );
		$this->assertSame( 'login_failed', $rules[0]['action_substring'] );
		$this->assertSame( 20, $rules[0]['threshold'] );
		$this->assertSame( 15, $rules[0]['window_minutes'] );
		$this->assertSame( 'high', $rules[0]['severity'] );
		$this->assertSame( 0, $rules[0]['last_fired'] );
	}

	public function test_defaults_severity_to_medium_when_omitted() {
		$rules = IS_Custom_Detections::parse_rules_text( 'ip_blocked | 3 | 5' );
		$this->assertSame( 'medium', $rules[0]['severity'] );
	}

	public function test_invalid_severity_falls_back_to_medium() {
		$rules = IS_Custom_Detections::parse_rules_text( 'ip_blocked | 3 | 5 | not-a-real-severity' );
		$this->assertSame( 'medium', $rules[0]['severity'] );
	}

	public function test_ignores_blank_lines_and_comments() {
		$rules = IS_Custom_Detections::parse_rules_text( "\n# a comment\nlogin_failed | 20 | 15 | high\n" );
		$this->assertCount( 1, $rules );
	}

	public function test_skips_a_line_with_non_numeric_threshold() {
		$rules = IS_Custom_Detections::parse_rules_text( 'login_failed | abc | 15 | high' );
		$this->assertSame( array(), $rules );
	}

	public function test_skips_a_line_missing_required_fields() {
		$rules = IS_Custom_Detections::parse_rules_text( 'login_failed | 20' );
		$this->assertSame( array(), $rules );
	}

	public function test_parses_multiple_rules() {
		$rules = IS_Custom_Detections::parse_rules_text( "login_failed | 20 | 15 | high\nip_blocked | 3 | 5 | critical" );
		$this->assertCount( 2, $rules );
	}

	// ---- format_rules_text -----------------------------------------------------

	public function test_round_trips_through_parse_and_format() {
		$original = 'login_failed | 20 | 15 | high';
		$parsed   = IS_Custom_Detections::parse_rules_text( $original );
		$this->assertSame( $original, IS_Custom_Detections::format_rules_text( $parsed ) );
	}

	public function test_formats_an_empty_rule_set_as_empty_string() {
		$this->assertSame( '', IS_Custom_Detections::format_rules_text( array() ) );
	}
}

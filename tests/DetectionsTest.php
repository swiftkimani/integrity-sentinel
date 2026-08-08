<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure parts of IS_Detections (the rule registry and
 * detail-line formatting). fire() itself needs IS_Audit_Log/
 * IS_Notifications (wpdb, wp_mail) and is exercised in a real WordPress.
 */
class DetectionsTest extends TestCase {

	public function test_known_rule_has_the_expected_shape() {
		$rule = IS_Detections::rule( 'credential_stuffing_detected' );
		$this->assertSame( 'high', $rule['severity'] );
		$this->assertArrayHasKey( 'label', $rule );
		$this->assertArrayHasKey( 'category', $rule );
	}

	public function test_unregistered_rule_falls_back_to_info() {
		$rule = IS_Detections::rule( 'not_a_real_rule' );
		$this->assertSame( 'info', $rule['severity'] );
		$this->assertSame( 'not_a_real_rule', $rule['label'] );
	}

	public function test_every_registered_rule_has_a_valid_severity() {
		foreach ( IS_Detections::rules() as $rule_id => $rule ) {
			$this->assertArrayHasKey(
				$rule['severity'],
				IS_Detections::SEVERITY_ORDER,
				"Rule '$rule_id' has an unrecognized severity '{$rule['severity']}'"
			);
		}
	}

	public function test_format_detail_lines_renders_scalars() {
		$lines = IS_Detections::format_detail_lines(
			array(
				'ip'    => '203.0.113.5',
				'count' => 12,
			)
		);
		$this->assertSame( array( 'ip: 203.0.113.5', 'count: 12' ), $lines );
	}
}

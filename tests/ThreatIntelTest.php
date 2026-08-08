<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure response-parsing logic in IS_Threat_Intel. The
 * WP-dependent glue (wp_remote_get, transients) is exercised in a real
 * WordPress, not here.
 */
class ThreatIntelTest extends TestCase {

	// ---- severity banding ---------------------------------------------

	public function test_score_at_or_above_75_is_critical() {
		$this->assertSame( 'critical', IS_Threat_Intel::severity_for_abuse_score( 75 ) );
		$this->assertSame( 'critical', IS_Threat_Intel::severity_for_abuse_score( 100 ) );
	}

	public function test_score_at_or_above_40_is_high() {
		$this->assertSame( 'high', IS_Threat_Intel::severity_for_abuse_score( 40 ) );
		$this->assertSame( 'high', IS_Threat_Intel::severity_for_abuse_score( 74 ) );
	}

	public function test_score_at_or_above_10_is_medium() {
		$this->assertSame( 'medium', IS_Threat_Intel::severity_for_abuse_score( 10 ) );
		$this->assertSame( 'medium', IS_Threat_Intel::severity_for_abuse_score( 39 ) );
	}

	public function test_score_below_10_is_low() {
		$this->assertSame( 'low', IS_Threat_Intel::severity_for_abuse_score( 0 ) );
		$this->assertSame( 'low', IS_Threat_Intel::severity_for_abuse_score( 9 ) );
	}

	// ---- parse_ip_report ------------------------------------------------

	public function test_parses_a_well_formed_abuseipdb_response() {
		$body = array(
			'data' => array(
				'abuseConfidenceScore' => 80,
				'totalReports'         => 12,
				'countryCode'          => 'RU',
			),
		);
		$result = IS_Threat_Intel::parse_ip_report( $body );
		$this->assertSame( 80, $result['score'] );
		$this->assertSame( 'critical', $result['severity'] );
		$this->assertSame( 12, $result['total_reports'] );
		$this->assertSame( 'RU', $result['country'] );
	}

	public function test_parse_ip_report_returns_null_for_empty_body() {
		$this->assertNull( IS_Threat_Intel::parse_ip_report( array() ) );
		$this->assertNull( IS_Threat_Intel::parse_ip_report( null ) );
	}

	// ---- parse_hash_report ------------------------------------------------

	public function test_parses_a_malicious_virustotal_response() {
		$body = array(
			'data' => array(
				'attributes' => array(
					'last_analysis_stats' => array(
						'malicious'  => 5,
						'suspicious' => 1,
					),
				),
			),
		);
		$result = IS_Threat_Intel::parse_hash_report( $body );
		$this->assertSame( 5, $result['malicious'] );
		$this->assertSame( 1, $result['suspicious'] );
		$this->assertSame( 'critical', $result['severity'] );
	}

	public function test_parses_a_clean_virustotal_response() {
		$body = array(
			'data' => array(
				'attributes' => array(
					'last_analysis_stats' => array(
						'malicious'  => 0,
						'suspicious' => 0,
					),
				),
			),
		);
		$result = IS_Threat_Intel::parse_hash_report( $body );
		$this->assertSame( 'low', $result['severity'] );
	}

	public function test_suspicious_only_is_medium_severity() {
		$body = array(
			'data' => array(
				'attributes' => array(
					'last_analysis_stats' => array(
						'malicious'  => 0,
						'suspicious' => 2,
					),
				),
			),
		);
		$result = IS_Threat_Intel::parse_hash_report( $body );
		$this->assertSame( 'medium', $result['severity'] );
	}

	public function test_parse_hash_report_returns_null_for_empty_body() {
		$this->assertNull( IS_Threat_Intel::parse_hash_report( array() ) );
	}
}

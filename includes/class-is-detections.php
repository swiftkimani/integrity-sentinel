<?php
/**
 * Structured detection registry for behavioral/abuse signals.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A small structured-detection registry: every behavioral/abuse signal
 * raised anywhere in the plugin (rate limiting, credential stuffing,
 * enumeration, and later phases: honeypots, session anomalies, ...) fires
 * through here instead of calling IS_Audit_Log/IS_Notifications directly.
 * That gives every detection a consistent severity and category without
 * a database migration -- the audit log's `action`/`detail` columns are
 * unchanged, this just standardizes what goes into them.
 *
 * Categories are loose, human-readable labels (not formal ATT&CK
 * technique IDs) -- precise technique mapping would need per-case
 * judgement this registry can't make safely, so it sticks to a short,
 * honest tactic-level word instead of a specific ID that might be wrong.
 */
class IS_Detections {

	const SEVERITY_ORDER      = array(
		'critical' => 4,
		'high'     => 3,
		'medium'   => 2,
		'low'      => 1,
		'info'     => 0,
	);
	const NOTIFY_MIN_SEVERITY = 'high';

	/**
	 * Pure: the rule registry. New phases add entries here rather than
	 * inventing their own ad hoc severity/category at the call site.
	 */
	public static function rules() {
		return array(
			'rest_rate_limited'            => array(
				'label'    => __( 'REST API rate limit exceeded', 'integrity-sentinel' ),
				'severity' => 'medium',
				'category' => 'denial-of-service',
			),
			'rest_enumeration_suspected'   => array(
				'label'    => __( 'Suspicious sequential REST API ID access', 'integrity-sentinel' ),
				'severity' => 'medium',
				'category' => 'reconnaissance',
			),
			'credential_stuffing_detected' => array(
				'label'    => __( 'Credential stuffing attack detected', 'integrity-sentinel' ),
				'severity' => 'high',
				'category' => 'credential-access',
			),
			'sbom_changed'                 => array(
				'label'    => __( 'Software inventory changed', 'integrity-sentinel' ),
				'severity' => 'low',
				'category' => 'inventory-change',
			),
			'honeypot_triggered'           => array(
				'label'    => __( 'Honeypot path accessed', 'integrity-sentinel' ),
				'severity' => 'critical',
				'category' => 'deception',
			),
			'canary_token_used'            => array(
				'label'    => __( 'Canary token used', 'integrity-sentinel' ),
				'severity' => 'critical',
				'category' => 'deception',
			),
			'impossible_travel_suspected'  => array(
				'label'    => __( 'Impossible travel: rapid login from a very different network', 'integrity-sentinel' ),
				'severity' => 'high',
				'category' => 'anomalous-access',
			),
		);
	}

	/**
	 * Pure: looks up a rule, falling back to a generic 'info' shape for
	 * an unregistered rule_id rather than erroring -- a typo'd rule_id
	 * should still get logged, just without a wrong severity guess.
	 *
	 * @param string $rule_id Key into rules().
	 */
	public static function rule( $rule_id ) {
		$rules = self::rules();
		if ( isset( $rules[ $rule_id ] ) ) {
			return $rules[ $rule_id ];
		}
		return array(
			'label'    => $rule_id,
			'severity' => 'info',
			'category' => 'uncategorized',
		);
	}

	/**
	 * Pure: flattens a detail array into human-readable lines for email/webhook bodies.
	 *
	 * @param array $detail Context to flatten.
	 */
	public static function format_detail_lines( array $detail ) {
		$lines = array();
		foreach ( $detail as $key => $value ) {
			$lines[] = sprintf( '%s: %s', $key, is_scalar( $value ) ? (string) $value : wp_json_encode( $value ) );
		}
		return $lines;
	}

	/**
	 * Records the detection to the audit log and, for high/critical
	 * severity, alerts through IS_Notifications too.
	 *
	 * @param string $rule_id   Key into rules(), or an ad hoc identifier (e.g. an admin-defined custom detection rule) paired with $overrides.
	 * @param array  $detail    Extra context (ip, route, counts, ...).
	 * @param array  $overrides Optional {label,severity,category} overriding rule()'s lookup -- for callers (e.g. IS_Custom_Detections) whose rule isn't in the static registry() and whose severity is admin-chosen, not hardcoded here.
	 */
	public static function fire( $rule_id, array $detail = array(), array $overrides = array() ) {
		$rule = array_merge( self::rule( $rule_id ), $overrides );

		IS_Audit_Log::record(
			'detect_' . $rule_id,
			array_merge(
				array(
					'severity' => $rule['severity'],
					'category' => $rule['category'],
				),
				$detail
			)
		);

		$rank     = self::SEVERITY_ORDER[ $rule['severity'] ] ?? 0;
		$min_rank = self::SEVERITY_ORDER[ self::NOTIFY_MIN_SEVERITY ] ?? 0;
		if ( $rank >= $min_rank ) {
			IS_Notifications::instance()->send_event( $rule_id, $rule['label'], self::format_detail_lines( $detail ) );
		}
	}
}

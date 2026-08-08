<?php
/**
 * Admin-defined detection rules over the audit log ("if X happens Y
 * times in Z minutes, alert me").
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Every other detection in this plugin is hardcoded (rate limiting,
 * credential stuffing, honeypots, ...). This is the escape hatch: a
 * site owner can define their own lightweight, Sigma-flavored rules
 * ("alert if this action slug shows up N times in M minutes") without
 * touching code. Evaluated on the existing 5-minute cron tick
 * (IS_Cron's `is_five_minutes` schedule) rather than a new one.
 *
 * A per-rule cooldown (equal to the rule's own window) stops one
 * sustained burst from re-firing on every single tick -- once fired, a
 * rule won't fire again until a full window has passed since.
 */
class IS_Custom_Detections {

	/**
	 * Singleton instance.
	 *
	 * @var IS_Custom_Detections|null
	 */
	private static $instance = null;

	/**
	 * Gets (and lazily creates) the singleton instance, wiring up hooks the first time it is created.
	 *
	 * @return IS_Custom_Detections
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	/**
	 * Default settings for this module.
	 */
	public static function default_settings() {
		return array( 'rules' => array() );
	}

	/**
	 * Current settings, merged over the defaults.
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_custom_detections_settings', array() ), self::default_settings() );
	}

	/** A single rule's own default shape, used both for new-rule forms and to fill in gaps in stored rules. */
	public static function default_rule() {
		return array(
			'action_substring' => '',
			'threshold'        => 5,
			'window_minutes'   => 15,
			'severity'         => 'medium',
			'last_fired'       => 0,
		);
	}

	/**
	 * Registers the periodic evaluation tick.
	 */
	private function hooks() {
		add_action( IS_CRON_RESUME_SCAN, array( $this, 'evaluate_rules' ) ); // rides the existing 5-minute tick -- no new cron job needed.
	}

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: has this rule's cooldown elapsed (i.e. is it eligible to
	 * fire again)? A never-fired rule ($last_fired == 0) is always
	 * eligible.
	 *
	 * @param int $last_fired      Unix timestamp of the rule's last firing, 0 if never.
	 * @param int $now             Current unix timestamp.
	 * @param int $window_minutes  The rule's own window -- also used as its cooldown.
	 */
	public static function cooldown_elapsed( $last_fired, $now, $window_minutes ) {
		if ( 0 === (int) $last_fired ) {
			return true;
		}
		return ( (int) $now - (int) $last_fired ) >= ( max( 1, (int) $window_minutes ) * MINUTE_IN_SECONDS );
	}

	/**
	 * Pure: has this rule's match count reached its configured threshold?
	 *
	 * @param int $matching_count Number of matching audit-log entries found.
	 * @param int $threshold      The rule's configured threshold.
	 */
	public static function rule_triggered( $matching_count, $threshold ) {
		return (int) $matching_count >= max( 1, (int) $threshold );
	}

	/**
	 * Pure: a stable, human-readable identifier for a custom rule, used as the IS_Detections rule_id and audit-log action suffix.
	 *
	 * @param int $index The rule's position in the settings' `rules` array.
	 */
	public static function rule_slug( $index ) {
		return 'custom_' . (int) $index;
	}

	/**
	 * Pure: parses the bulk textarea format ("action_substring |
	 * threshold | window_minutes | severity", one rule per line) into
	 * the settings' `rules` array shape -- same "one entry per line"
	 * convention already used by IS_IP_List/IS_Bot_Block/IS_Signatures,
	 * rather than a dynamic JS row-adder. Malformed lines are skipped,
	 * not guessed at. last_fired always starts at 0: any edit to the
	 * rule set re-arms it from scratch rather than trying to fuzzy-match
	 * "is this the same rule as before" across an edit.
	 *
	 * @param string $text Bulk textarea contents, one rule per line.
	 * @return array<array{action_substring:string,threshold:int,window_minutes:int,severity:string}>
	 */
	public static function parse_rules_text( $text ) {
		$valid_severities = array_keys( IS_Detections::SEVERITY_ORDER );
		$out              = array();

		foreach ( preg_split( '/\r\n|\r|\n/', (string) $text ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			$parts = array_map( 'trim', explode( '|', $line ) );
			if ( count( $parts ) < 3 || '' === $parts[0] || ! is_numeric( $parts[1] ) || ! is_numeric( $parts[2] ) ) {
				continue;
			}
			$severity = isset( $parts[3] ) ? strtolower( $parts[3] ) : 'medium';
			$out[]    = array(
				'action_substring' => $parts[0],
				'threshold'        => max( 1, (int) $parts[1] ),
				'window_minutes'   => max( 1, (int) $parts[2] ),
				'severity'         => in_array( $severity, $valid_severities, true ) ? $severity : 'medium',
				'last_fired'       => 0,
			);
		}

		return $out;
	}

	/**
	 * Pure: the inverse of parse_rules_text() -- renders the current
	 * rules back into the bulk textarea format for display.
	 *
	 * @param array $rules Rules in settings() shape.
	 */
	public static function format_rules_text( array $rules ) {
		$defaults = self::default_rule();
		$lines    = array();
		foreach ( $rules as $rule ) {
			$rule    = array_merge( $defaults, is_array( $rule ) ? $rule : array() );
			$lines[] = sprintf( '%s | %d | %d | %s', $rule['action_substring'], $rule['threshold'], $rule['window_minutes'], $rule['severity'] );
		}
		return implode( "\n", $lines );
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * Evaluates every configured rule and fires IS_Detections for any
	 * that are both over-threshold and past their cooldown. Persists
	 * updated last_fired timestamps back to the option.
	 */
	public function evaluate_rules() {
		IS_Guard::run(
			'custom_detections',
			function () {
				$settings = self::settings();
				$rules    = $settings['rules'];
				if ( empty( $rules ) ) {
					return;
				}

				$now     = time();
				$changed = false;

				foreach ( $rules as $index => $rule ) {
					$rule = wp_parse_args( $rule, self::default_rule() );
					if ( '' === trim( (string) $rule['action_substring'] ) ) {
						continue;
					}
					if ( ! self::cooldown_elapsed( $rule['last_fired'], $now, $rule['window_minutes'] ) ) {
						continue;
					}

					$since = gmdate( 'Y-m-d H:i:s', $now - ( (int) $rule['window_minutes'] * MINUTE_IN_SECONDS ) );
					$count = IS_Audit_Log::count_matching( $rule['action_substring'], $since );

					if ( ! self::rule_triggered( $count, $rule['threshold'] ) ) {
						continue;
					}

					IS_Detections::fire(
						self::rule_slug( $index ),
						array(
							'action_substring' => $rule['action_substring'],
							'count'            => $count,
							'threshold'        => $rule['threshold'],
							'window_minutes'   => $rule['window_minutes'],
						),
						array(
							/* translators: 1: action-slug substring being watched, 2: how many times it matched, 3: window in minutes */
							'label'    => sprintf( __( 'Custom detection rule triggered: "%1$s" matched %2$d time(s) in %3$d minute(s)', 'integrity-sentinel' ), $rule['action_substring'], $count, $rule['window_minutes'] ),
							'severity' => in_array( $rule['severity'], array_keys( IS_Detections::SEVERITY_ORDER ), true ) ? $rule['severity'] : 'medium',
							'category' => 'custom-rule',
						)
					);

					$rules[ $index ]['last_fired'] = $now;
					$changed                       = true;
				}

				if ( $changed ) {
					$settings['rules'] = $rules;
					update_option( 'is_custom_detections_settings', $settings, false );
				}
			}
		);
	}
}

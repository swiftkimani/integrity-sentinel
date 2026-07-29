<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sends a single summary email when a completed scan has new findings at
 * or above the configured alert threshold. Deliberately one email per
 * run (not one per finding) so a bad scan doesn't spam the inbox.
 */
class IS_Notifications {

	private static $instance = null;
	const SEVERITY_ORDER = array( 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, 'info' => 0 );

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function settings() {
		return get_option( 'is_scan_settings', array() );
	}

	/**
	 * Posts a JSON payload to the configured webhook, if any. The point
	 * of the webhook is an OUT-OF-BAND copy of security events: alerts
	 * that land somewhere off this server can't be deleted by whoever
	 * compromised it.
	 */
	public function post_webhook( array $payload ) {
		$settings = $this->settings();
		$url      = $settings['webhook_url'] ?? '';
		if ( empty( $url ) ) {
			return;
		}
		wp_remote_post(
			$url,
			array(
				'timeout' => 5,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode(
					$payload + array(
						'site' => home_url(),
						'time' => current_time( 'mysql' ),
					)
				),
			)
		);
	}

	/**
	 * Sends a security event to the alert email AND the webhook. Used
	 * for events that aren't scan summaries: deactivation, dead-man's
	 * switch, new installs, failed update verification.
	 *
	 * @param string   $event      Machine-readable event slug (webhook payload).
	 * @param string   $subject    Human subject line (site name is prefixed).
	 * @param string[] $body_lines Plain-text body lines.
	 */
	public function send_event( $event, $subject, array $body_lines ) {
		$settings = $this->settings();
		$to       = $settings['alert_email'] ?? get_option( 'admin_email' );

		if ( ! empty( $to ) && is_email( $to ) ) {
			$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
			wp_mail( $to, '[' . $site_name . '] ' . $subject, implode( "\n", $body_lines ) . "\n" );
		}

		$this->post_webhook(
			array(
				'event'   => $event,
				'subject' => $subject,
				'detail'  => $body_lines,
			)
		);
	}

	public function maybe_send_alert( $run_id ) {
		$settings = get_option( 'is_scan_settings', array() );
		$to       = $settings['alert_email'] ?? get_option( 'admin_email' );
		$threshold = $settings['alert_on_severity'] ?? 'high';

		if ( empty( $to ) || ! is_email( $to ) ) {
			return;
		}

		$db  = IS_DB::instance();
		$run = $db->get_run( $run_id );
		if ( ! $run ) {
			return;
		}

		// Count only findings that first appeared during THIS run --
		// "found N new issue(s)" must not inflate itself with older
		// findings the admin already knows about but hasn't acknowledged.
		$counts   = $db->severity_counts_for_run( $run_id, $run['started_at'] );
		$min_rank = self::SEVERITY_ORDER[ $threshold ] ?? self::SEVERITY_ORDER['high'];

		$qualifying = 0;
		foreach ( $counts as $severity => $count ) {
			if ( ( self::SEVERITY_ORDER[ $severity ] ?? 0 ) >= $min_rank ) {
				$qualifying += $count;
			}
		}

		if ( 0 === $qualifying ) {
			return;
		}

		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$subject   = sprintf(
			/* translators: 1: site name, 2: number of findings */
			__( '[%1$s] Integrity Sentinel found %2$d new issue(s)', 'integrity-sentinel' ),
			$site_name,
			$qualifying
		);

		$body = sprintf(
			/* translators: %s: admin findings page URL */
			__( "A scan on %1\$s found %2\$d new issue(s) at or above your alert threshold.\n\nCritical: %3\$d\nHigh: %4\$d\nMedium: %5\$d\nLow: %6\$d\n\nReview the details here:\n%7\$s\n", 'integrity-sentinel' ),
			$site_name,
			$qualifying,
			$counts['critical'],
			$counts['high'],
			$counts['medium'],
			$counts['low'],
			admin_url( 'admin.php?page=integrity-sentinel-findings' )
		);

		wp_mail( $to, $subject, $body );

		$this->post_webhook(
			array(
				'event'  => 'scan_alert',
				'run_id' => (int) $run_id,
				'counts' => $counts,
			)
		);
	}
}

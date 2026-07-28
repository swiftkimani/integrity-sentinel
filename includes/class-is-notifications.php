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

	public function maybe_send_alert( $run_id ) {
		$settings = get_option( 'is_scan_settings', array() );
		$to       = $settings['alert_email'] ?? get_option( 'admin_email' );
		$threshold = $settings['alert_on_severity'] ?? 'high';

		if ( empty( $to ) || ! is_email( $to ) ) {
			return;
		}

		$db       = IS_DB::instance();
		$counts   = $db->severity_counts( 'new' );
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
	}
}

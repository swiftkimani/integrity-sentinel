<?php
/**
 * Generic fixed-window rate limiter, transient-backed, keyed by an
 * arbitrary (bucket, key) pair.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generic fixed-window rate limiter, transient-backed, keyed by an
 * arbitrary (bucket, key) pair -- the same shape IS_Rest_Posts already
 * used for its own per-user endpoint limiter, generalized so any module
 * (REST API throttling, enumeration-velocity tracking, future modules)
 * can share one implementation instead of re-deriving the transient
 * bookkeeping each time.
 */
class IS_Rate_Limiter {

	// -----------------------------------------------------------------
	// Pure logic
	// -----------------------------------------------------------------

	/**
	 * Pure: $record is shaped like {window_started_at, count}; a window
	 * that has expired is treated as zero regardless of its stored count.
	 *
	 * @param array $record         Rate-limit record with window_started_at and count.
	 * @param int   $now            Current timestamp.
	 * @param int   $window_seconds Window length in seconds.
	 */
	public static function current_window_count( array $record, $now, $window_seconds ) {
		if ( empty( $record['window_started_at'] ) || $record['window_started_at'] <= ( $now - $window_seconds ) ) {
			return 0;
		}
		return (int) ( $record['count'] ?? 0 );
	}

	/**
	 * Pure: true if the current window's count is already at or above the limit.
	 *
	 * @param array $record         Rate-limit record with window_started_at and count.
	 * @param int   $now            Current timestamp.
	 * @param int   $limit          Max hits allowed per window.
	 * @param int   $window_seconds Window length in seconds.
	 */
	public static function is_limited( array $record, $now, $limit, $window_seconds ) {
		return self::current_window_count( $record, $now, $window_seconds ) >= $limit;
	}

	/**
	 * Pure: returns a new record with the hit counted, starting a fresh
	 * window if the previous one has expired.
	 *
	 * @param array $record         Rate-limit record with window_started_at and count.
	 * @param int   $now            Current timestamp.
	 * @param int   $window_seconds Window length in seconds.
	 */
	public static function record_hit( array $record, $now, $window_seconds ) {
		$fresh = empty( $record['window_started_at'] ) || $record['window_started_at'] <= ( $now - $window_seconds );
		return array(
			'window_started_at' => $fresh ? $now : $record['window_started_at'],
			'count'             => $fresh ? 1 : ( (int) ( $record['count'] ?? 0 ) + 1 ),
		);
	}

	// -----------------------------------------------------------------
	// WP-dependent glue
	// -----------------------------------------------------------------

	/**
	 * Builds the transient key for a given (bucket, key) pair.
	 *
	 * @param string $bucket Short module identifier (e.g. 'rest_api').
	 * @param string $key    Per-subject key (e.g. an IP address).
	 */
	private static function transient_key( $bucket, $key ) {
		return 'is_rl_' . $bucket . '_' . md5( (string) $key );
	}

	/**
	 * Checks-and-records in one call: evaluates the limit against the
	 * count BEFORE this hit, then always records the hit regardless of
	 * outcome. Returns true if this hit was within the limit.
	 *
	 * @param string $bucket         Short module identifier (e.g. 'rest_api').
	 * @param string $key            Per-subject key (e.g. an IP address).
	 * @param int    $limit          Max hits allowed per window.
	 * @param int    $window_seconds Window length in seconds.
	 */
	public static function hit( $bucket, $key, $limit, $window_seconds ) {
		$transient_key = self::transient_key( $bucket, $key );
		$record        = get_transient( $transient_key );
		$record        = is_array( $record ) ? $record : array();
		$now           = time();

		$allowed = ! self::is_limited( $record, $now, max( 1, (int) $limit ), $window_seconds );

		$record = self::record_hit( $record, $now, $window_seconds );
		set_transient( $transient_key, $record, max( MINUTE_IN_SECONDS, (int) $window_seconds ) );

		return $allowed;
	}
}

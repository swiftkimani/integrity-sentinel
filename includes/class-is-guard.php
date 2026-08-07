<?php
/**
 * Per-module fault isolation: hardening/detection modules run through a
 * circuit breaker here so one module's failure can't take down the rest
 * of the site.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fault-isolation layer. Every hardening/detection module added from here
 * on wraps its actual work in IS_Guard::run() instead of executing
 * straight off a WordPress hook. One module throwing (a bad regex, an
 * unexpected null, a flaky remote call) must never be able to fatal the
 * whole site just because it happened to run on `init` -- it degrades
 * itself and leaves every other module standing.
 *
 * Two independent safety nets live here:
 *  - Per-module circuit breaker: a module that keeps throwing pauses
 *    itself for a cooldown period rather than retrying (and re-failing)
 *    on every single request.
 *  - IS_SAFE_MODE: a site owner locked out by a hardening feature (a
 *    broken login rename, an overzealous IP block) can define
 *    `IS_SAFE_MODE` truthy in wp-config.php to stop every guarded module
 *    at once, no database or admin access required.
 */
class IS_Guard {

	const HEALTH_OPTION     = 'is_module_health';
	const FAILURE_THRESHOLD = 5;
	const FAILURE_WINDOW    = HOUR_IN_SECONDS;
	const COOLDOWN          = HOUR_IN_SECONDS;

	/**
	 * Whether the wp-config.php kill switch is active.
	 */
	public static function is_safe_mode() {
		return defined( 'IS_SAFE_MODE' ) && IS_SAFE_MODE;
	}

	/**
	 * Run $fn under fault isolation, keyed by a short module identifier
	 * (e.g. 'ip_list', 'headers', 'login_rename'). Returns $fn()'s result
	 * on success, or $default if safe mode is active, the module is
	 * currently in its post-failure cooldown, or $fn() itself threw.
	 *
	 * @param string   $module  Short machine-readable module identifier.
	 * @param callable $fn      The module's actual work.
	 * @param mixed    $default Value to return when not run / on failure.
	 */
	public static function run( $module, callable $fn, $default = null ) {
		if ( self::is_safe_mode() ) {
			return $default;
		}
		if ( self::is_disabled( self::health( $module ), time() ) ) {
			return $default;
		}

		try {
			$result = $fn();
			self::persist( $module, self::success_state( self::health( $module ) ) );
			return $result;
		} catch ( Throwable $e ) {
			self::handle_failure( $module, $e );
			return $default;
		}
	}

	/**
	 * Whether a module's circuit breaker is currently tripped.
	 *
	 * @param array $health Health record shaped like default_health().
	 * @param int   $now    Current unix timestamp.
	 */
	public static function is_disabled( array $health, $now ) {
		return ! empty( $health['disabled_until'] ) && $health['disabled_until'] > $now;
	}

	/**
	 * The health shape a module has before it has ever failed.
	 */
	public static function default_health() {
		return array(
			'status'         => 'ok',
			'failures'       => array(),
			'last_error'     => '',
			'last_error_at'  => null,
			'disabled_until' => null,
		);
	}

	/**
	 * Health state to persist after a successful run: status/failures/
	 * disabled_until reset, but the last error is kept for the health
	 * panel's benefit even after recovery.
	 *
	 * @param array $health Current health record (used only for its last-error fields).
	 */
	public static function success_state( array $health ) {
		return array_merge(
			self::default_health(),
			array(
				'last_error'    => isset( $health['last_error'] ) ? $health['last_error'] : '',
				'last_error_at' => isset( $health['last_error_at'] ) ? $health['last_error_at'] : null,
			)
		);
	}

	/**
	 * Pure state transition: given a module's current health, the time
	 * and message of a new failure, and the tuning constants, compute its
	 * next health state and whether THIS failure is the one that trips
	 * the circuit breaker (as opposed to one more failure while it's
	 * already tripped). No WordPress calls -- fully unit-testable.
	 *
	 * @param array  $health    Module's current health record.
	 * @param int    $now       Current unix timestamp.
	 * @param string $message   The new failure's error message.
	 * @param int    $threshold Number of failures within $window that trips the breaker.
	 * @param int    $window    Rolling window, in seconds, that failures are counted over.
	 * @param int    $cooldown  Seconds the module stays disabled once tripped.
	 * @return array{state: array, tripped: bool}
	 */
	public static function failure_state( array $health, $now, $message, $threshold, $window, $cooldown ) {
		$was_disabled = self::is_disabled( $health, $now );

		$failures   = array_values(
			array_filter(
				isset( $health['failures'] ) ? (array) $health['failures'] : array(),
				function ( $t ) use ( $now, $window ) {
					return $t > ( $now - $window );
				}
			)
		);
		$failures[] = $now;

		$disabled_until = isset( $health['disabled_until'] ) ? $health['disabled_until'] : null;
		$tripped        = false;

		if ( count( $failures ) >= $threshold ) {
			$disabled_until = $now + $cooldown;
			$tripped        = ! $was_disabled;
			// Reset the window once tripped so it doesn't re-trip on
			// every remaining call for the rest of the cooldown.
			$failures = array();
		}

		return array(
			'state'   => array(
				'status'         => 'degraded',
				'failures'       => $failures,
				'last_error'     => $message,
				'last_error_at'  => $now,
				'disabled_until' => $disabled_until,
			),
			'tripped' => $tripped,
		);
	}

	/**
	 * Current health record for a module, filled in with defaults for any missing keys.
	 *
	 * @param string $module Short machine-readable module identifier.
	 */
	public static function health( $module ) {
		$all = get_option( self::HEALTH_OPTION, array() );
		return isset( $all[ $module ] ) ? wp_parse_args( $all[ $module ], self::default_health() ) : self::default_health();
	}

	/**
	 * Health records for every module that has ever recorded state, filled in with defaults.
	 */
	public static function all_health() {
		$all = get_option( self::HEALTH_OPTION, array() );
		$out = array();
		foreach ( $all as $module => $health ) {
			$out[ $module ] = wp_parse_args( $health, self::default_health() );
		}
		return $out;
	}

	/**
	 * Manually clear a module's degraded/disabled state (admin action).
	 *
	 * @param string $module Short machine-readable module identifier.
	 */
	public static function reset( $module ) {
		$all = get_option( self::HEALTH_OPTION, array() );
		unset( $all[ $module ] );
		update_option( self::HEALTH_OPTION, $all, false );
	}

	/**
	 * Persist a module's health record.
	 *
	 * @param string $module Short machine-readable module identifier.
	 * @param array  $state  Health record to store, shaped like default_health().
	 */
	private static function persist( $module, array $state ) {
		$all            = get_option( self::HEALTH_OPTION, array() );
		$all[ $module ] = $state;
		update_option( self::HEALTH_OPTION, $all, false );
	}

	/**
	 * Record a module's failure: log it, update its health record via
	 * failure_state(), write an audit-log entry, and notify if this
	 * failure is the one that tripped the circuit breaker.
	 *
	 * @param string    $module Short machine-readable module identifier.
	 * @param Throwable $e      The exception the module threw.
	 */
	private static function handle_failure( $module, Throwable $e ) {
		$message = $e->getMessage() . ' in ' . basename( $e->getFile() ) . ':' . $e->getLine();

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- deliberate last line of defense: this must not depend on our own DB layer, which may be part of what just failed.
		error_log( sprintf( '[Integrity Sentinel] module "%s" threw: %s', $module, $message ) );

		$now    = time();
		$result = self::failure_state( self::health( $module ), $now, $message, self::FAILURE_THRESHOLD, self::FAILURE_WINDOW, self::COOLDOWN );
		self::persist( $module, $result['state'] );

		if ( class_exists( 'IS_Audit_Log' ) ) {
			IS_Audit_Log::record(
				'module_fault',
				array(
					'module' => $module,
					'error'  => $message,
				)
			);
		}

		if ( $result['tripped'] && class_exists( 'IS_Notifications' ) ) {
			IS_Notifications::instance()->send_event(
				'module_disabled',
				sprintf(
					/* translators: %s: module identifier */
					__( 'Integrity Sentinel module "%s" paused itself after repeated errors', 'integrity-sentinel' ),
					$module
				),
				array(
					sprintf(
						/* translators: 1: module identifier, 2: failure threshold, 3: cooldown in minutes */
						__( 'The "%1$s" module hit %2$d errors within an hour and has paused itself for %3$d minutes to protect the rest of the site.', 'integrity-sentinel' ),
						$module,
						self::FAILURE_THRESHOLD,
						(int) ( self::COOLDOWN / MINUTE_IN_SECONDS )
					),
					sprintf(
						/* translators: %s: error message */
						__( 'Last error: %s', 'integrity-sentinel' ),
						$message
					),
					__( 'Every other Integrity Sentinel module keeps running normally; only this one is affected. Review it under Integrity Sentinel → Dashboard → Feature Health.', 'integrity-sentinel' ),
				)
			);
		}
	}
}

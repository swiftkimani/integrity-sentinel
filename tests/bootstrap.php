<?php
/**
 * Minimal bootstrap for unit tests that don't need a live WordPress:
 * defines just enough of the WP surface (constants, __(), WP_Error) for
 * the pure-logic classes under test to load. Anything needing wpdb or
 * HTTP is out of scope here and belongs in an integration suite.
 */

define( 'ABSPATH', sys_get_temp_dir() . '/' );

define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
define( 'WEEK_IN_SECONDS', 604800 );

if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) { // phpcs:ignore
		return $text;
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error { // phpcs:ignore
		private $code;
		private $message;

		public function __construct( $code = '', $message = '' ) {
			$this->code    = $code;
			$this->message = $message;
		}

		public function get_error_code() {
			return $this->code;
		}

		public function get_error_message() {
			return $this->message;
		}
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) { // phpcs:ignore
		return $thing instanceof WP_Error;
	}
}

require_once dirname( __DIR__ ) . '/includes/class-is-heuristics.php';
require_once dirname( __DIR__ ) . '/includes/class-is-plugin-checksums.php';
require_once dirname( __DIR__ ) . '/includes/class-is-file-walker.php';
require_once dirname( __DIR__ ) . '/includes/class-is-hardening.php';
require_once dirname( __DIR__ ) . '/includes/class-is-guard.php';
require_once dirname( __DIR__ ) . '/includes/class-is-headers.php';
require_once dirname( __DIR__ ) . '/includes/class-is-ip-list.php';
require_once dirname( __DIR__ ) . '/includes/class-is-login.php';
require_once dirname( __DIR__ ) . '/includes/class-is-upload-guard.php';
require_once dirname( __DIR__ ) . '/includes/class-is-db.php';
require_once dirname( __DIR__ ) . '/includes/class-is-hotlink.php';
require_once dirname( __DIR__ ) . '/includes/class-is-bot-block.php';
require_once dirname( __DIR__ ) . '/includes/class-is-rest-api.php';
require_once dirname( __DIR__ ) . '/includes/class-is-rest-posts.php';

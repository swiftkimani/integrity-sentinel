<?php
/**
 * Blocks a curated, admin-editable list of AI-crawler/scraper user agents.
 *
 * @package Integrity_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Blocks a curated, admin-editable list of AI-crawler/scraper user
 * agents: a 403 at plugins_loaded for the aggressive ones, plus a
 * matching Disallow entry in robots.txt for the well-behaved ones that
 * actually honor it (some AI crawlers, e.g. GPTBot, do). Defaults to
 * enabled -- unlike XML-RPC/feeds, blocking known crawler/scraper user
 * agents carries no real risk of breaking anything a human visitor does.
 */
class IS_Bot_Block {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Returns the singleton instance, creating and hooking it up on first call.
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

	/**
	 * The built-in list of AI-crawler/scraper user-agent substrings blocked
	 * by default.
	 */
	public static function default_bot_list() {
		return array(
			'GPTBot',
			'ChatGPT-User',
			'CCBot',
			'anthropic-ai',
			'ClaudeBot',
			'Claude-Web',
			'Bytespider',
			'PerplexityBot',
			'Google-Extended',
			'Applebot-Extended',
			'Diffbot',
			'ImagesiftBot',
			'Omgilibot',
			'FacebookBot',
			'Amazonbot',
			'Timpibot',
			'YouBot',
		);
	}

	/**
	 * Default settings, used to fill in anything missing from the stored option.
	 */
	public static function default_settings() {
		return array(
			'enabled'      => 1,
			'blocked_bots' => implode( "\n", self::default_bot_list() ),
		);
	}

	/**
	 * Stored settings, merged over default_settings().
	 */
	public static function settings() {
		return wp_parse_args( get_option( 'is_bot_block_settings', array() ), self::default_settings() );
	}

	/**
	 * Registers the WordPress hooks that enforce the block and extend robots.txt.
	 */
	private function hooks() {
		// 'init', not 'plugins_loaded': this class is instantiated from
		// is_init(), itself a 'plugins_loaded' callback -- a callback
		// registered for 'plugins_loaded' from inside another
		// 'plugins_loaded' callback is registered too late to ever run,
		// since that hook fires exactly once per request. 'init' fires
		// immediately after and hasn't happened yet at this point.
		add_action( 'init', array( $this, 'maybe_block' ), 1 );
		add_filter( 'robots_txt', array( $this, 'filter_robots_txt' ) );
	}

	/**
	 * Pure: parses a textarea's worth of user-agent substrings, one per
	 * line, blank lines ignored.
	 *
	 * @param string $text Raw textarea value, one blocklist entry per line.
	 * @return string[]
	 */
	public static function parse_bot_list( $text ) {
		return array_values( array_filter( array_map( 'trim', preg_split( '/\r\n|\r|\n/', (string) $text ) ) ) );
	}

	/**
	 * Pure: case-insensitive substring match against any entry.
	 *
	 * @param string   $user_agent The request's User-Agent header.
	 * @param string[] $entries    Parsed blocklist entries.
	 */
	public static function user_agent_is_blocked( $user_agent, array $entries ) {
		$user_agent = trim( (string) $user_agent );
		if ( '' === $user_agent ) {
			return false;
		}
		foreach ( $entries as $entry ) {
			if ( '' !== $entry && false !== stripos( $user_agent, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 'init' callback: 403s the request if its User-Agent matches an
	 * enabled, admin-configured blocklist entry.
	 */
	public function maybe_block() {
		IS_Guard::run(
			'bot_block',
			function () {
				$settings = self::settings();
				if ( empty( $settings['enabled'] ) ) {
					return;
				}
				$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only substring comparison, never echoed unescaped
				if ( self::user_agent_is_blocked( $ua, self::parse_bot_list( $settings['blocked_bots'] ) ) ) {
					IS_Audit_Log::record( 'bot_blocked', array( 'user_agent' => mb_substr( $ua, 0, 200 ) ) );
					wp_die( esc_html__( 'Access denied.', 'integrity-sentinel' ), '', array( 'response' => 403 ) );
				}
			}
		);
	}

	/**
	 * 'robots_txt' filter: appends a Disallow entry for each enabled
	 * blocklist entry.
	 *
	 * @param string $output Existing robots.txt contents.
	 * @return string
	 */
	public function filter_robots_txt( $output ) {
		return IS_Guard::run(
			'bot_block',
			function () use ( $output ) {
				$settings = self::settings();
				if ( empty( $settings['enabled'] ) ) {
					return $output;
				}
				$entries = self::parse_bot_list( $settings['blocked_bots'] );
				if ( empty( $entries ) ) {
					return $output;
				}
				$extra = "\n";
				foreach ( $entries as $entry ) {
					$extra .= "User-agent: {$entry}\nDisallow: /\n";
				}
				return rtrim( (string) $output ) . "\n" . $extra;
			},
			$output
		);
	}
}

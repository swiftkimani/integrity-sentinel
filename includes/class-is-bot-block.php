<?php
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

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->hooks();
		}
		return self::$instance;
	}

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

	public static function default_settings() {
		return array(
			'enabled'      => 1,
			'blocked_bots' => implode( "\n", self::default_bot_list() ),
		);
	}

	public static function settings() {
		return wp_parse_args( get_option( 'is_bot_block_settings', array() ), self::default_settings() );
	}

	private function hooks() {
		add_action( 'plugins_loaded', array( $this, 'maybe_block' ), 1 );
		add_filter( 'robots_txt', array( $this, 'filter_robots_txt' ) );
	}

	/**
	 * Pure: parses a textarea's worth of user-agent substrings, one per
	 * line, blank lines ignored.
	 *
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

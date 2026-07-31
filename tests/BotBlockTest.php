<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic pieces of IS_Bot_Block. The WP-dependent
 * parts (the actual plugins_loaded/robots_txt hooks) are exercised in a
 * real WordPress, not here.
 */
class BotBlockTest extends TestCase {

	public function test_parses_one_entry_per_line() {
		$this->assertSame( array( 'GPTBot', 'CCBot' ), IS_Bot_Block::parse_bot_list( "GPTBot\nCCBot" ) );
	}

	public function test_ignores_blank_lines() {
		$this->assertSame( array( 'GPTBot' ), IS_Bot_Block::parse_bot_list( "\nGPTBot\n\n" ) );
	}

	public function test_matches_known_bot_case_insensitively() {
		$this->assertTrue( IS_Bot_Block::user_agent_is_blocked( 'mozilla/5.0 gptbot/1.0', array( 'GPTBot' ) ) );
	}

	public function test_matches_as_a_substring_of_a_longer_user_agent() {
		$this->assertTrue( IS_Bot_Block::user_agent_is_blocked( 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://example.com)', array( 'ClaudeBot' ) ) );
	}

	public function test_does_not_match_an_unrelated_browser() {
		$this->assertFalse( IS_Bot_Block::user_agent_is_blocked( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0', IS_Bot_Block::default_bot_list() ) );
	}

	public function test_empty_user_agent_is_never_blocked() {
		$this->assertFalse( IS_Bot_Block::user_agent_is_blocked( '', array( 'GPTBot' ) ) );
	}

	public function test_empty_entry_list_never_blocks() {
		$this->assertFalse( IS_Bot_Block::user_agent_is_blocked( 'GPTBot/1.0', array() ) );
	}

	public function test_default_settings_enabled_by_default() {
		$this->assertSame( 1, IS_Bot_Block::default_settings()['enabled'] );
	}

	public function test_default_bot_list_includes_major_ai_crawlers() {
		$list = IS_Bot_Block::default_bot_list();
		foreach ( array( 'GPTBot', 'ClaudeBot', 'CCBot', 'Bytespider' ) as $bot ) {
			$this->assertContains( $bot, $list );
		}
	}
}

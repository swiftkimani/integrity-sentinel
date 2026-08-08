<?php
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure-logic piece of IS_Password_Policy
 * (password_issues). The WP-dependent glue (the validate_password_reset
 * and user_profile_update_errors hooks) is exercised in a real
 * WordPress, not here.
 */
class PasswordPolicyTest extends TestCase {

	private function settings( array $overrides = array() ) {
		return array_merge( IS_Password_Policy::default_settings(), $overrides );
	}

	public function test_strong_password_passes_every_rule() {
		$issues = IS_Password_Policy::password_issues( 'Tr0ub4dor&3xample', $this->settings( array( 'enabled' => 1, 'require_symbol' => 1 ) ) );
		$this->assertSame( array(), $issues );
	}

	public function test_flags_a_too_short_password() {
		$issues = IS_Password_Policy::password_issues( 'Ab1', $this->settings( array( 'min_length' => 12 ) ) );
		$this->assertNotEmpty( $issues );
		$this->assertStringContainsString( '12', $issues[0] );
	}

	public function test_flags_missing_mixed_case() {
		$issues = IS_Password_Policy::password_issues( 'alllowercase123', $this->settings( array( 'min_length' => 4, 'require_mixed_case' => 1 ) ) );
		$this->assertContains( 'Must include both uppercase and lowercase letters.', $issues );
	}

	public function test_does_not_flag_case_when_rule_is_off() {
		$issues = IS_Password_Policy::password_issues( 'alllowercase123', $this->settings( array( 'min_length' => 4, 'require_mixed_case' => 0, 'require_number' => 0 ) ) );
		$this->assertSame( array(), $issues );
	}

	public function test_flags_missing_number() {
		$issues = IS_Password_Policy::password_issues( 'NoNumbersHere', $this->settings( array( 'min_length' => 4, 'require_number' => 1, 'require_mixed_case' => 0 ) ) );
		$this->assertContains( 'Must include at least one number.', $issues );
	}

	public function test_flags_missing_symbol_only_when_required() {
		$settings_off = $this->settings( array( 'min_length' => 4, 'require_mixed_case' => 0, 'require_number' => 0, 'require_symbol' => 0 ) );
		$this->assertSame( array(), IS_Password_Policy::password_issues( 'NoSymbolsHere1', $settings_off ) );

		$settings_on = $this->settings( array( 'min_length' => 4, 'require_mixed_case' => 0, 'require_number' => 0, 'require_symbol' => 1 ) );
		$this->assertNotEmpty( IS_Password_Policy::password_issues( 'NoSymbolsHere1', $settings_on ) );
	}

	public function test_rejects_a_common_password_even_if_it_satisfies_every_rule() {
		// "Password1!" satisfies length/case/number/symbol rules but is
		// still one of the most-guessed passwords in every wordlist.
		$issues = IS_Password_Policy::password_issues(
			'Password1!',
			$this->settings( array( 'min_length' => 8, 'require_mixed_case' => 1, 'require_number' => 1, 'require_symbol' => 1 ) )
		);
		$this->assertNotEmpty( $issues );
	}

	public function test_common_password_check_is_case_insensitive() {
		$issues = IS_Password_Policy::password_issues( 'PASSWORD1', $this->settings( array( 'min_length' => 4, 'require_mixed_case' => 0, 'require_number' => 0 ) ) );
		$this->assertNotEmpty( $issues );
	}

	public function test_reports_every_violated_rule_at_once() {
		$issues = IS_Password_Policy::password_issues(
			'ab',
			$this->settings( array( 'min_length' => 12, 'require_mixed_case' => 1, 'require_number' => 1, 'require_symbol' => 1 ) )
		);
		$this->assertGreaterThanOrEqual( 4, count( $issues ) );
	}
}

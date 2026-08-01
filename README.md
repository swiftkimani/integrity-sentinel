# Integrity Sentinel — Malware & File Scanner

[![CI](https://github.com/swiftkimani/integrity-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/swiftkimani/integrity-sentinel/actions/workflows/ci.yml)
![Stable version](https://img.shields.io/badge/stable-1.2.0-blue)
![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759b)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4)
![License](https://img.shields.io/badge/license-GPLv2%20or%20later-green)

A WordPress plugin that answers one question well: **"is there anything on this site that shouldn't be here?"**

It verifies WordPress core and plugin files against the official WordPress.org checksum API, scans every PHP file for malware/webshell patterns, watches its own integrity, and audits your site's security configuration — all read-only, all with a live progress bar, a findings dashboard, and a WP-CLI command for real cron.

---

## Table of contents

- [What it checks](#what-it-checks)
- [Tamper-resistant by design](#tamper-resistant-by-design)
- [Active prevention (opt-in)](#active-prevention-opt-in)
- [How scanning works](#how-scanning-works)
- [Screenshots / admin screens](#screenshots--admin-screens)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [WP-CLI](#wp-cli)
- [Uploads hardening (`.htaccess` / nginx)](#uploads-hardening-htaccess--nginx)
- [Self-integrity manifest](#self-integrity-manifest)
- [Architecture](#architecture)
- [Development](#development)
- [What this is not](#what-this-is-not)
- [FAQ](#faq)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)

---

## What it checks

- **WordPress core files** against the official WordPress.org checksum API — the same data source WP-CLI's `wp core verify-checksums` uses. Modified files, missing files, **and** unexpected extra files inside `wp-admin/` and `wp-includes/` (a classic backdoor drop location) are all flagged.
- **Installed WordPress.org plugin files** against their published checksums (`wp plugin verify-checksums`'s data source), including unexpected extra files inside those plugins' directories. Premium or custom plugins with no published checksums are clearly listed as **"not checkable"** rather than silently skipped or falsely flagged.
- **Every PHP file on the site** for common malware/webshell code patterns: obfuscated `eval()` chains, request data piped into `shell_exec`/`system`, the deprecated `preg_replace` `/e` modifier, known public webshell name markers, and more.
- **PHP files hiding inside `wp-content/uploads/`** — uploads should only ever contain media, so executable PHP there is a strong signal on its own.
- **Itself.** Every scan verifies Integrity Sentinel's own files against its release manifest — a tampered scanner that reports "all clean" is worse than no scanner.
- **Site hardening.** Every scan also audits configuration: the built-in file editor, debug output, weak/placeholder auth salts, the default table prefix, `allow_url_include`, EOL PHP, world-writable paths, web-exposed `.git`/`.env`/`debug.log` files, backup archives sitting in the webroot, XML-RPC, an `admin` username, administrator accounts created since the last scan, and plugins that have been closed on WordPress.org.

Themes, mu-plugins, and premium/custom plugins have no published WordPress.org checksums, so they can't be checksum-verified — their PHP files are still fully covered by the malware-pattern scan.

## Tamper-resistant by design

Attackers switch off security plugins first, so Integrity Sentinel watches its own back:

| Mechanism | What it does |
|---|---|
| **Deactivation alarm** | Deactivating the plugin immediately emails the alert address with who did it and from which IP. |
| **Dead-man's switch** | If no scan completes for *N* days (default 2), you get an alert — a scanner that has silently stopped scanning protects nothing. |
| **Alert-redirection guard** | Changing the alert email notifies the *previous* address, so alerts can't be quietly pointed elsewhere. |
| **Append-only audit log** | Every scan, finding status change, settings change, and hardening action is recorded with user and IP (its own admin screen). |
| **Off-site webhook** | Optionally POST every security event as JSON to a webhook (Slack-compatible), putting a copy of the evidence where an attacker on this server can't delete it. |
| **Update monitoring** | New plugin/theme installs trigger an immediate alert, and WordPress.org plugin updates are checksum-verified seconds after they land, catching tampered packages. |

## Active prevention (opt-in)

The **Hardening** screen can write a clearly-marked rule block into the uploads `.htaccess` that denies PHP execution there — a dropped webshell in uploads becomes inert instead of merely detected (the nginx equivalent is shown for manual setup). One click to apply, one to remove, and it never touches rules it didn't write.

## How scanning works

Scans run in small batches (configurable, default 40 files per step) driven by a live AJAX progress bar, so a large site doesn't time out mid-scan. A background cron job runs a full scan daily, and a five-minute safety-net check resumes any scan that got interrupted (e.g. an admin closed the browser tab mid-scan) — reloading the dashboard mid-scan picks the progress bar back up where it left off. Only one process ever drives a scan at a time (an advisory lock), so the browser, cron, and WP-CLI can't trip over each other.

## Screenshots / admin screens

The plugin adds a top-level **Integrity Sentinel** menu with five screens:

- **Dashboard** — last scan status, live progress bar, "Scan now" button, at-a-glance summary of new findings.
- **Findings** — filterable list of every finding (new / acknowledged / ignored / resolved, by severity), with a details panel and status workflow.
- **Hardening** — the configuration audit results, plus the one-click uploads `.htaccess` PHP-execution block.
- **Audit Log** — the append-only record of scans, finding status changes, settings changes, and hardening actions.
- **Settings** — alert email, alert severity threshold, batch size, excluded paths, webhook URL, dead-man's-switch window.

## Requirements

- WordPress **6.0+**
- PHP **7.4+**
- No third-party runtime dependencies (no Composer required to run the plugin — it installs anywhere plain WordPress runs). Composer is only used for the **development** tooling (tests, linting).

## Installation

**From this repository (manual / GitHub):**

1. Download or clone this repository into `wp-content/plugins/integrity-sentinel`.
2. Activate **Integrity Sentinel** through the WordPress "Plugins" screen.
3. Go to **Integrity Sentinel → Settings** to set an alert email and (optionally) exclude paths like cache directories from scanning.
4. Click **"Scan now"** on the Dashboard, or wait for the daily background scan.

**From a release ZIP:**

1. Download the latest release from the [Releases](../../releases) page.
2. Upload the ZIP via **Plugins → Add New → Upload Plugin**.
3. Activate, then follow steps 3–4 above.

## Configuration

All settings live under **Integrity Sentinel → Settings** and are stored in the `is_scan_settings` option:

| Setting | Default | Description |
|---|---|---|
| `alert_email` | site admin email | Where scan alerts, deactivation alarms, and the dead-man's-switch notice are sent. Changing it notifies the *previous* address too. |
| `alert_on_severity` | `high` | Minimum severity (`critical`, `high`, `medium`, `low`) that triggers an email alert. |
| `batch_size` | `40` | Files scanned per AJAX/cron batch step. |
| `scan_uploads_for_php` | on | Whether to flag PHP files found inside `wp-content/uploads/`. |
| `max_file_size_kb` | `2048` | Files larger than this are still hashed for checksum verification but skipped for pattern-scanning. |
| `excluded_paths` | `wp-content/cache`, `wp-content/uploads/backup*`, `wp-content/ai1wm-backups` | Newline-separated glob-style paths excluded from scanning. |
| `webhook_url` | *(empty)* | Optional Slack-compatible webhook that receives a JSON POST for every security event. |
| `deadman_days` | `2` | Days without a completed scan before the dead-man's-switch alert fires. |

## WP-CLI

Because WP-Cron is only as reliable as your site's traffic, scanning is also available as a WP-CLI command — ideal for a real system crontab:

```bash
# Run a full scan (exits non-zero if new findings were recorded, so cron wrappers can alert)
wp integrity-sentinel scan

# Drive an already-running scan to completion instead of refusing to start
wp integrity-sentinel scan --resume

# Show the most recent scan run
wp integrity-sentinel status

# List findings (filterable, scriptable output)
wp integrity-sentinel findings
wp integrity-sentinel findings --status=new --severity=critical
wp integrity-sentinel findings --format=json
wp integrity-sentinel findings --format=csv --limit=500
```

`findings` supports `--status=<new|acknowledged|ignored|resolved>`, `--severity=<critical|high|medium|low|info>`, `--limit=<n>` (default 100), and `--format=<table|csv|json|yaml>`.

## Uploads hardening (`.htaccess` / nginx)

On the **Hardening** screen, "Apply the block" writes a clearly-delimited rule block into `wp-content/uploads/.htaccess` that denies execution of PHP files in that directory. "Remove the block" deletes only that block, leaving any other rules in the file untouched. For nginx (which ignores `.htaccess`), the screen shows the equivalent `location` block to add to your server config manually.

## Self-integrity manifest

`integrity-manifest.json` at the plugin root is a sha256 manifest of every runtime file (root PHP, `includes/`, `assets/js`, `assets/css`). Every scan compares the plugin's files on disk against this manifest and flags tampering, missing files, or unexpected files as **critical** findings.

If you change a runtime file, regenerate the manifest before committing/releasing:

```bash
composer manifest        # rewrite integrity-manifest.json
composer manifest:check  # exit 1 if the manifest is stale (used in CI)
```

Development files (`tests/`, `bin/`, `languages/`) are deliberately excluded from the manifest.

## Architecture

```
integrity-sentinel.php          Plugin bootstrap: autoloader, activation/deactivation, cron/CLI wiring
includes/
  class-is-admin.php            Admin UI: Dashboard, Findings, Hardening, Audit Log, Settings screens
  class-is-ajax.php             AJAX handlers driving the live scan progress bar
  class-is-audit-log.php        Append-only audit log recorder
  class-is-cli.php              WP-CLI commands (scan, status, findings)
  class-is-core-checksums.php   WordPress core checksum verification
  class-is-cron.php             Daily scan schedule + 5-minute resume safety net
  class-is-db.php               Custom DB tables (findings, runs) — schema and queries
  class-is-file-walker.php      Filesystem traversal respecting exclusions and size limits
  class-is-hardening.php        Hardening audit checks + uploads .htaccess toggle
  class-is-heuristics.php       Malware/webshell pattern rules
  class-is-notifications.php    Email and webhook alert delivery
  class-is-plugin-checksums.php WordPress.org plugin checksum verification
  class-is-scanner.php          Orchestrates a batched, resumable scan run
  class-is-update-monitor.php   Watches plugin/theme installs and updates
bin/make-manifest.php           Regenerates integrity-manifest.json
tests/                          PHPUnit test suite
```

The plugin has **zero third-party runtime dependencies** and uses a minimal `spl_autoload_register()` autoloader (no Composer autoload needed at runtime) — the same rationale as keeping it installable anywhere plain WordPress runs.

## Development

```bash
composer install          # install dev dependencies (PHPUnit, WPCS)
composer test             # run the PHPUnit suite
composer lint              # run PHPCS (WordPress Coding Standards)
composer lint:fix          # auto-fix what PHPCS can
composer manifest          # regenerate integrity-manifest.json after touching runtime files
composer manifest:check    # verify the manifest is current (CI-enforced)
```

**Continuous integration** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs on every push and pull request against `main`:

- **Syntax check** — `php -l` across PHP 7.4–8.3.
- **PHPUnit** — full test suite on PHP 7.4, 8.2, 8.3, plus a manifest-freshness check.
- **PHPCS** (WordPress Coding Standards) — advisory for now (`continue-on-error`), surfaced but not yet blocking merges.

## What this is not

This is a file-integrity and malware-pattern scanner — it does **not** include a web application firewall, login/brute-force protection, or a global real-time threat-intelligence network. It's meant to be run alongside whatever handles those (or as your first layer while you evaluate one).

## FAQ

**Does this modify or delete anything it finds?**
No. Every check is read-only: it hashes files, reads file contents to match patterns, and calls the WordPress.org checksum APIs. It never writes to, deletes, or executes anything it scans. Remediation (removing a confirmed backdoor, restoring a clean file) is left to you.

**Will this flag every plugin I have installed?**
Only plugins installed from the WordPress.org repository can be checksum-verified at all — premium and custom plugins are listed separately as "not checkable" rather than compared against nothing and falsely flagged.

**Why does the malware scan sometimes flag legitimate code?**
Heuristic pattern matching trades some false positives for not missing real backdoors. A minifier, a legitimate use of `eval()` in a build tool, or an old codebase using `create_function()` can all trigger a finding. Review each finding's context — that's what the "View details" panel and Acknowledge/Ignore workflow are for.

**Does it work on multisite?**
Yes, with one deliberate simplification: the filesystem is shared across every subsite, so the scanner runs once, from the main site. Subsites don't get their own scan schedules or dashboards — they'd all be scanning the same files.

**The daily scan doesn't seem to run reliably.**
WP-Cron only fires when your site gets visits, so low-traffic sites can miss schedules. Either configure a real system cron to hit `wp-cron.php`, or run `wp integrity-sentinel scan` directly from your server's crontab.

## Changelog

Full history is in [`readme.txt`](readme.txt#changelog) (WordPress.org format). Highlights:

- **1.2.0** — self-defense tier (deactivation alarm, dead-man's switch, alert-redirection guard, audit log, webhook delivery), self-integrity check, hardening audit, opt-in uploads hardening, update monitoring.
- **1.1.0** — unexpected extra-file detection in core/plugin directories, WP-CLI commands, resumable live progress, multisite awareness, several scan-correctness fixes.
- **1.0.0** — initial release: core/plugin checksum verification, heuristic PHP malware scanning, uploads-PHP detection, batched/resumable scans, findings dashboard, email alerts.

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. `composer install`
2. `composer test` and `composer lint` should pass.
3. If you touched any runtime file (root PHP, `includes/`, `assets/js`, `assets/css`), run `composer manifest` and commit the updated `integrity-manifest.json` — CI enforces this with `composer manifest:check`.

## License

GPLv2 or later. See [License URI](https://www.gnu.org/licenses/gpl-2.0.html).

## Credits

Built by Kefa Hamisi & Benard Kimani.

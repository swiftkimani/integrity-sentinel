# Integrity Sentinel — Malware Scanner & Hardening Suite

[![CI](https://github.com/swiftkimani/integrity-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/swiftkimani/integrity-sentinel/actions/workflows/ci.yml)
![Stable version](https://img.shields.io/badge/stable-1.25.0-blue)
![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759b)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4)
![License](https://img.shields.io/badge/license-GPLv2%20or%20later-green)

A WordPress plugin that answers one question well: **"is there anything on this site that shouldn't be here, or anything about how it's configured that makes an attack easier?"**

It started as a file-integrity/malware scanner and has grown into a full defensive suite — detection, active prevention, login/identity hardening, deception, and governance/reporting — while keeping the original scanner's core promise: every check is **read-only** unless a screen explicitly says otherwise, and every screen that writes anything (an `.htaccess` block, a quarantine action) does it reversibly and only on explicit human action.

---

## Table of contents

- [Feature overview](#feature-overview)
  - [Detection & scanning](#detection--scanning)
  - [Active prevention](#active-prevention)
  - [Login & identity](#login--identity)
  - [Deception & threat intelligence](#deception--threat-intelligence)
  - [Governance & reporting](#governance--reporting)
- [Tamper-resistant by design](#tamper-resistant-by-design)
- [Fault isolation & IS_SAFE_MODE](#fault-isolation--is_safe_mode)
- [How scanning works](#how-scanning-works)
- [Admin screens](#admin-screens)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [WP-CLI](#wp-cli)
- [Uploads / hotlink hardening (`.htaccess` / nginx)](#uploads--hotlink-hardening-htaccess--nginx)
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

## Feature overview

### Detection & scanning

Everything below runs as part of the same batched, resumable scan (see [How scanning works](#how-scanning-works)) and reports through one unified Findings pipeline (severity, acknowledge/ignore, auto-resolve, alerts).

| Check | What it catches |
|---|---|
| **Core checksum verification** | WordPress core files against the official WordPress.org checksum API (`wp core verify-checksums`'s own data source) — modified, missing, **and** unexpected extra files in `wp-admin/`/`wp-includes/` (a classic backdoor drop location). |
| **Plugin checksum verification** | Installed WordPress.org plugin files against their published checksums, including unexpected extra files. Premium/custom plugins with no published checksums are clearly listed as **"not checkable"**, never silently skipped or falsely flagged. |
| **Malware/webshell heuristics** | Every PHP file, scanned for common real-world compromise patterns: obfuscated `eval()` chains, request data piped into `shell_exec`/`system`, the deprecated `preg_replace` `/e` modifier, known public webshell name markers, `chr()`-built function names, variable-variable calls, hex-escape floods, and high-entropy string blobs (catches packed/encoded payloads a base64-only check would miss). |
| **Secrets-in-code scanner** | Hardcoded credentials accidentally committed into theme/plugin files: AWS access keys, PEM private-key blocks, GitHub/Slack/Stripe/Google tokens, and a generic high-entropy-value-in-a-credential-named-variable check. Ships always-on, like the heuristics scan. |
| **Exact-hash signature matching** | An admin-curated known-bad-hash list (deliberately **not** a bundled "malware database" — a fabricated or stale one would be actively misleading). Meant to be populated from hashes gathered during a real incident, a threat-intel feed, or a VirusTotal/MalwareBazaar report; zero false-positive risk since it's an exact match. |
| **Known-vulnerability scanning** | Installed plugins and the active theme checked against the WPScan Vulnerability Database on every scan — catches a completely untampered plugin with a known, published, unpatched CVE, which file-integrity checking structurally can't. Opt-in (needs a free WPScan API key), enriched with EPSS exploit-probability scores. |
| **Ransomware / mass-defacement canary** | Tracks a per-file hash for `uploads/`, `themes/`, and `mu-plugins/` — the one surface with **no** checksum-based drift detection at all — and flags an abrupt, large-scale change between two scans (most of the tree flipping content at once) as a strong ransomware/defacement signal. On by default. |
| **Domain-phishing intelligence** | Generates typosquat variants of the site's own domain (adjacent-swap, omission, duplication, homoglyph, TLD-swap) and checks each for DNS registration and, via free/keyless Certificate Transparency log monitoring (crt.sh), a recently-issued TLS certificate — an early signal of active phishing infrastructure. Opt-in, self-check only. |
| **SBOM inventory diffing** | A CycloneDX-lite software inventory (core + every plugin + the active theme, name/version/path) regenerated and diffed every scan — a plugin appearing, disappearing, or changing version between two scans is a signal file-hash checksums alone can miss. |
| **Self-integrity check** | Every scan verifies the plugin's own files against its release manifest (`integrity-manifest.json`) — a tampered scanner that reports "all clean" is worse than no scanner. |
| **Hardening/configuration audit** | Runs every scan alongside the file checks: built-in file editor enabled, debug output, weak/placeholder auth salts, duplicate auth salts, the default table prefix, `allow_url_include`, EOL PHP, world-writable paths, web-exposed `.git`/`.env`/`debug.log`, backup archives in the webroot, XML-RPC, an `admin` username, dormant/newly-created administrator accounts, `admin_email` domain mismatches, CAA/TLS certificate expiry, insecure REST routes, and plugins closed on WordPress.org. |

### Active prevention

Mostly opt-in and reversible — the plugin defaults to *detecting*, and asks before it *writes* anything.

- **Uploads/secondary-directory PHP-execution block** — one click writes (and cleanly removes) a marker-delimited `.htaccess` rule denying PHP execution in `wp-content/uploads/`, `wp-content/cache`, `wp-content/upgrade`, and `wp-content/temp` when present (nginx equivalent shown for manual setup).
- **Upload-time executable blocking** — rejects executable file types (`.php` and variants, `.cgi`, `.pl`, `.py`, `.sh`, `.asp(x)`, `.jsp`, `.exe`, `.phar`, ...) at the media uploader, plugin/theme install-by-upload, and any importer using `wp_handle_upload()`. Checks every dot-separated filename segment, so `shell.php.jpg` is caught too. Always on, never affects real media.
- **Hotlink protection** — denies cross-site embedding of images from `wp-content/uploads`, with an editable allowed-domains list.
- **AI-crawler/scraper blocking** — a curated, editable list of AI-training crawlers/scrapers (GPTBot, ClaudeBot, CCBot, Bytespider, ...) blocked with a 403, plus matching `robots.txt` entries for the ones that honor it.
- **IP allow/deny lists** — editable, CIDR-aware (IPv4 + IPv6), with safe reverse-proxy/CDN support (a forwarded-IP header is trusted only from an explicitly configured trusted proxy range).
- **REST API hardening** — blocks unauthenticated `/wp/v2/users` enumeration and the old `?author=N` redirect by default; optional full lockdown of unauthenticated REST access with an allowlist; a full REST attack-surface audit flags any registered route (core or any plugin) that accepts a write request with no real permission check.
- **HTTP response hardening** — security headers, clickjacking protection, a real configurable Content-Security-Policy (with report-only mode), WordPress-version hiding, optional XML-RPC/feed disabling.
- **Password strength policy** — actually rejects a weak password (not just WordPress core's advisory meter), on both the password-reset flow and profile/user-edit changes. Off by default.
- **Asset cloaking** *(opt-in, advanced)* — disguises `/wp-content/`/`/wp-includes/` URLs behind a chosen alias. The one feature `IS_SAFE_MODE` can't fully undo (see [Fault isolation](#fault-isolation--is_safe_mode)) — read its warnings before enabling.

### Login & identity

- **Login URL hiding** — a custom slug and/or a dedicated admin subdomain, both off by default; `/wp-admin/*` 404s the same way `wp-login.php` does once set (closes the "still redirects, confirming a hidden login exists" leak), including a PATH_INFO bypass (`/wp-login.php/x`).
- **Login rate limiting** — per-IP failure counter with cooldown lockout; whitelisted IPs always bypass it.
- **Login Design** — ten built-in templates (Minimal, Sunrise, Aurora Night, Bubblegum, Forest, Monochrome, Ocean, Carousel, Terminal, Polaroid), a full customizer (accent color, logo, corner radius, hero placement/heading/image/gallery), custom CSS, a sanitized custom-HTML banner, and a real unsaved-draft preview.
- **Two-factor authentication (TOTP)** — RFC 6238, self-service per-user setup with recovery codes, optional per-role enforcement that nudges rather than locks out an unset-up user.
- **FIDO2/WebAuthn passwordless 2FA** *(PHP 8.2+)* — a second 2FA method alongside TOTP, built on the vendored [`web-auth/webauthn-lib`](https://github.com/web-auth/webauthn-framework) (this plugin's only runtime dependency). A user can register a hardware key or platform authenticator (Touch ID, Windows Hello, ...) and use either method to complete login. On PHP 7.4–8.1 this feature simply doesn't appear; TOTP is unaffected.
- **Session security** — every admin sees their own active sessions (device, IP, sign-in time) and can revoke individually or all-at-once; a `manage_options` user can force-logout any account's sessions from the Users list; an optional alert fires on a genuinely new login IP.
- **Application Password hygiene** — a read-only staleness view (created/last-used/last-IP) over WordPress core's own Application Passwords, surfacing credentials worth revoking.

### Deception & threat intelligence

- **Honeypots & a canary token** — decoy sensitive paths (a fake `.env`, a fake backup archive) and one canary-token REST route that no legitimate visitor has any reason to touch. Triggering either fires an immediate temporary IP ban plus a critical detection.
- **Opt-in threat-intel reputation lookups** — on-demand (never in a live request path) IP reputation via AbuseIPDB and file-hash reputation via VirusTotal.
- **Self-service custom detection rules** — Sigma-style, admin-defined rules over the audit log ("alert if action X happens N times in M minutes"), evaluated on the existing 5-minute cron tick — the escape hatch for anything the built-in detections don't cover.
- **REST/credential-stuffing/enumeration detection** — general REST API rate limiting, request-velocity enumeration detection, and credential-stuffing detection (distinct usernames per IP, separate from single-account brute-force lockout).
- **Impossible-travel session anomaly detection** — a subnet-distance heuristic (no bundled GeoIP data, IPv4-only by design) flags a login from a location inconsistent with recent activity.
- **Breach & Attack Simulation (BAS) self-test** — an admin-triggered, zero-live-traffic self-test that feeds synthetic adversarial input into this plugin's own detection logic and asserts the expected verdict — "does the control that's supposed to catch this actually catch it, and is it even turned on." No external target, no real data touched.

### Governance & reporting

- **Human-in-the-loop quarantine** — suspends (never deletes) a flagged extra/unexpected file into a locked-down directory; a human explicitly restores or permanently deletes it later. Deliberately excludes modified-core/modified-plugin findings, since removing those would break the site rather than protect it.
- **Append-only audit log** — every scan, finding status change, settings change, and hardening action, with its own retention/pruning controls.
- **Reports & Compliance** — a self-audit page (security-headers score, local SPF/DMARC/DKIM check) with a one-click Markdown compliance export, plus a per-finding Markdown incident-bundle export.
- **Update monitoring** — new plugin/theme installs alert immediately; WordPress.org plugin updates are checksum-verified within seconds of landing.

---

## Tamper-resistant by design

Attackers switch off security plugins first, so Integrity Sentinel watches its own back:

| Mechanism | What it does |
|---|---|
| **Deactivation alarm** | Deactivating the plugin immediately emails the alert address with who did it and from which IP. |
| **Dead-man's switch** | If no scan completes for *N* days (default 2), you get an alert — a scanner that has silently stopped scanning protects nothing. |
| **Alert-redirection guard** | Changing the alert email notifies the *previous* address, so alerts can't be quietly pointed elsewhere. |
| **Append-only audit log** | Every scan, finding status change, settings change, and hardening action is recorded with user and IP (its own admin screen, with configurable retention). |
| **Off-site webhook** | Optionally POST every security event as JSON to a webhook (Slack-compatible), putting a copy of the evidence where an attacker on this server can't delete it. |
| **Update monitoring** | New plugin/theme installs trigger an immediate alert, and WordPress.org plugin updates are checksum-verified seconds after they land, catching tampered packages. |
| **Self-integrity manifest** | Every scan verifies this plugin's own files against its release manifest; tampering, missing, or unknown files show up as **critical** findings. |

## Fault isolation & IS_SAFE_MODE

Every hardening/detection module runs through `IS_Guard::run()` instead of directly off a WordPress hook — a per-module circuit breaker means one module throwing (a bad regex, a flaky remote call) can't fatal the site; it pauses itself for a cooldown and every other module keeps running.

If a hardening feature ever locks you out (a broken login rename, an overzealous IP block), define this in `wp-config.php` to instantly pause every guarded module, no database or admin access required:

```php
define( 'IS_SAFE_MODE', true );
```

One deliberate exception: **asset cloaking**'s root `.htaccess` rewrite rule is a static file the web server reads independently of whether WordPress can even boot, so `IS_SAFE_MODE` stops the WordPress-side URL rewriting but not the `.htaccess` rule itself — use the "Remove" button on that screen (undoes both halves), or a manual FTP/SSH edit as the true last resort.

## How scanning works

Scans run in small batches (configurable, default 40 files per step) driven by a live AJAX progress bar, so a large site doesn't time out mid-scan. Each batch does more than just pattern-match: it hashes in-scope files for the ransomware canary, runs the secrets scanner alongside the malware heuristics, and verifies checksums against WordPress.org. A background cron job runs a full scan on your configured schedule (hourly/twice-daily/daily/weekly), and a five-minute safety-net check resumes any scan that got interrupted (e.g. an admin closed the browser tab mid-scan) — reloading the dashboard mid-scan picks the progress bar back up where it left off. Only one process ever drives a scan at a time (an advisory lock), so the browser, cron, and WP-CLI can't trip over each other.

## Admin screens

The plugin adds a single top-level **Integrity Sentinel** menu (one clean entry in WordPress's own admin sidebar) with its own internal navigation across twelve screens:

- **Dashboard** — last scan status, live progress bar, "Scan now" button, a Security Status panel summarizing every hardening module's state.
- **Findings** — filterable list of every finding (new / acknowledged / ignored / resolved, by severity), with a details panel and status workflow.
- **Quarantine** — the human-in-the-loop quarantine engine: suspend, restore, or permanently delete an eligible flagged file.
- **Hardening** — the configuration/exposure/account audit results, plus the one-click PHP-execution blocks, domain intel, and ransomware-canary settings.
- **Access Control** — IP allow/deny lists, hotlink protection, AI-bot blocking.
- **Login Security** — login URL rename/subdomain, rate limiting, two-factor (TOTP + WebAuthn) setup and enforcement.
- **Login Design** — templates, customizer, custom CSS/HTML, live/real preview.
- **REST API** — enumeration protection, optional full lockdown, the live registered-route audit table.
- **Audit Log** — the append-only record of scans, finding status changes, settings changes, and hardening actions.
- **Reports & Compliance** — security-headers score, SPF/DMARC/DKIM check, Markdown compliance export.
- **Attack Simulation** — the Breach & Attack Simulation self-test, run on demand.
- **Settings** — alert email, alert severity threshold, batch size, excluded paths, webhook URL, dead-man's-switch window, scan frequency.

## Requirements

- WordPress **6.0+**
- PHP **7.4+** for the whole plugin; **PHP 8.2+** additionally unlocks FIDO2/WebAuthn passwordless 2FA (gated behind a runtime version check — on 7.4–8.1 the feature is simply absent, everything else is unaffected).
- No third-party runtime dependencies for PHP 7.4–8.1 (no Composer required to run the plugin). On PHP 8.2+, one vendored dependency (`web-auth/webauthn-lib`) ships committed inside the plugin — like any other WordPress plugin, no separate install step. Composer is otherwise only used for **development** tooling (tests, linting).

## Installation

**From this repository (manual / GitHub):**

1. Download or clone this repository into `wp-content/plugins/integrity-sentinel`.
2. Activate **Integrity Sentinel** through the WordPress "Plugins" screen.
3. Go to **Integrity Sentinel → Settings** to set an alert email and (optionally) exclude paths like cache directories from scanning.
4. Click **"Scan now"** on the Dashboard, or wait for the scheduled background scan.

**From a release ZIP:**

1. Download the latest release from the [Releases](../../releases) page.
2. Upload the ZIP via **Plugins → Add New → Upload Plugin**.
3. Activate, then follow steps 3–4 above.

## Configuration

Every module's settings live on its own admin screen (see [Admin screens](#admin-screens)) rather than one giant options page — the same pattern most mature WordPress security plugins use. The core scan behavior lives under **Settings**, stored in the `is_scan_settings` option:

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
| `scan_frequency` | `daily` | `hourly`, `twicedaily`, `daily`, or `weekly` background scan cadence. |

Every other module (Access Control, Login Security, Login Design, REST API, Hardening's opt-in checks, Deception, Threat Intel, Custom Detections, ...) has its own settings section on its own screen, each defaulting to the safest posture (off if it could break a real integration, on if it can't) — see the [Feature overview](#feature-overview) above for what each defaults to.

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

## Uploads / hotlink hardening (`.htaccess` / nginx)

On the **Hardening** screen, "Apply the block" writes a clearly-delimited rule block into `wp-content/uploads/.htaccess` (and the other writable secondary directories, when present) that denies execution of PHP files there. "Remove the block" deletes only that block, leaving any other rules in the file untouched. On the **Access Control** screen, hotlink protection writes an independent, separately-marked block denying cross-site image embedding. For nginx (which ignores `.htaccess`), both screens show the equivalent `location` block to add to your server config manually.

## Self-integrity manifest

`integrity-manifest.json` at the plugin root is a sha256 manifest of every runtime file (root PHP, `includes/`, `assets/js`, `assets/css`). Every scan compares the plugin's files on disk against this manifest and flags tampering, missing files, or unexpected files as **critical** findings.

If you change a runtime file, regenerate the manifest before committing/releasing:

```bash
composer manifest        # rewrite integrity-manifest.json
composer manifest:check  # exit 1 if the manifest is stale (used in CI)
```

Development files (`tests/`, `bin/`, `languages/`, and the vendored `vendor/` dependency) are deliberately excluded from the manifest and from the malware-heuristic file walk.

## Architecture

```
integrity-sentinel.php              Plugin bootstrap: autoloader, activation/deactivation, cron/CLI wiring
includes/
  Core scan engine
    class-is-scanner.php              Orchestrates a batched, resumable scan run
    class-is-file-walker.php          Filesystem traversal respecting exclusions and size limits
    class-is-db.php                   Custom DB tables (runs, findings, audit log, quarantine, file hashes)
    class-is-core-checksums.php       WordPress core checksum verification
    class-is-plugin-checksums.php     WordPress.org plugin checksum verification
    class-is-heuristics.php           Malware/webshell pattern rules
    class-is-secrets.php              Hardcoded-credential detection
    class-is-signatures.php           Admin-curated known-bad hash matching
    class-is-vulnerability-scanner.php  WPScan CVE lookups + EPSS enrichment
    class-is-ransomware-canary.php    Mass file-change velocity detection
    class-is-domain-intel.php         Typosquat DNS + Certificate Transparency monitoring
    class-is-sbom.php                 CycloneDX-lite inventory + diff
    class-is-cron.php                 Scan scheduling + resume safety net
  Hardening & prevention
    class-is-hardening.php            PHP-exec blocking + config/exposure/account audit
    class-is-headers.php              Security headers, CSP, XML-RPC, feeds
    class-is-hotlink.php              Hotlink protection
    class-is-bot-block.php            AI-crawler/scraper blocking
    class-is-ip-list.php              IP allow/deny lists, CIDR-aware
    class-is-upload-guard.php         Upload-time executable blocking
    class-is-password-policy.php      Server-side password strength enforcement
    class-is-asset-cloak.php          wp-content/wp-includes URL disguising
    class-is-tls-check.php            CAA + TLS certificate expiry check
    class-is-email-auth.php           SPF/DMARC/DKIM presence check
    class-is-rest-api.php             REST enumeration protection + route audit
    class-is-rest-posts.php           Application-Password-authenticated post-creation endpoint
  Login & identity
    class-is-login.php                Login URL hiding + rate limiting
    class-is-login-design.php         Login page templates/customizer
    class-is-2fa.php                  TOTP two-factor auth + login-challenge flow
    class-is-totp.php                 Pure RFC 6238 TOTP implementation
    class-is-webauthn.php             FIDO2/WebAuthn passwordless 2FA (PHP 8.2+)
    class-is-sessions.php             Session visibility, revocation, new-IP alerts
    class-is-api-key-hygiene.php      Application Password staleness view
  Deception & threat intel
    class-is-deception.php            Honeypots + canary token
    class-is-threat-intel.php         AbuseIPDB / VirusTotal reputation lookups
    class-is-custom-detections.php    Self-service Sigma-style detection rules
    class-is-detections.php           Structured behavioral-detection registry
    class-is-rate-limiter.php         Generic fixed-window rate limiter
    class-is-bas.php                  Breach & Attack Simulation self-test
  Governance & reporting
    class-is-quarantine.php           Human-in-the-loop file quarantine
    class-is-audit-log.php            Append-only audit trail
    class-is-notifications.php        Email/webhook alert delivery
    class-is-update-monitor.php       Plugin/theme install & update watcher
  Platform
    class-is-admin.php                Admin UI: all settings pages + dashboard
    class-is-ajax.php                 AJAX endpoints (scan progress, finding actions)
    class-is-cli.php                  WP-CLI commands
    class-is-guard.php                Per-module fault isolation + IS_SAFE_MODE
assets/js/is-admin.js               Admin UI behavior (scan progress, previews, pickers)
assets/js/is-webauthn.js            Browser-side WebAuthn registration/login ceremony
assets/css/is-admin.css             Admin UI styling
vendor/                             Vendored web-auth/webauthn-lib (PHP 8.2+ only, committed)
bin/make-manifest.php               Regenerates integrity-manifest.json
tests/                              PHPUnit test suite (pure-logic layer)
```

The plugin has **zero third-party runtime dependencies for PHP 7.4–8.1** and uses a minimal `spl_autoload_register()` autoloader for its own `IS_*` classes (no Composer autoload needed at runtime on that range). PHP 8.2+ additionally loads a vendored Composer autoloader for the one WebAuthn dependency — see [Requirements](#requirements).

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
- **PHPUnit** — full test suite (500+ tests) on PHP 7.4, 8.2, and 8.3, plus a manifest-freshness check.
- **WordPress Coding Standards** — `vendor/bin/phpcs`, enforced at 0 errors / 0 warnings.

`vendor/` and `composer.lock` are committed (the plugin's WebAuthn dependency ships the same way any other plugin file does), so CI runs `composer install` — testing exactly what's shipped, not whatever's newest that day.

## What this is not

Integrity Sentinel does not include a full web-application firewall (request-body payload inspection, SQL-injection filtering) or a managed, always-on real-time threat-intelligence network — the reputation/vulnerability lookups it does make (WPScan, AbuseIPDB, VirusTotal) are opt-in, on-demand, and never sit in a live request path. It's meant to be run as a strong first/only layer, or alongside a dedicated WAF for sites that need one.

## FAQ

**Does this modify or delete anything it finds?**
Almost everything is read-only: it hashes files, reads file contents to match patterns, and calls external checksum/reputation APIs. The exceptions are all explicit, reversible, and opt-in: the uploads/hotlink `.htaccess` blocks, asset cloaking's root `.htaccess` rule, and quarantine (which *moves*, never deletes, until a human explicitly confirms permanent deletion). Nothing is ever removed automatically or on a schedule.

**Will this flag every plugin I have installed?**
Only plugins installed from the WordPress.org repository can be checksum-verified at all — premium and custom plugins are listed separately as "not checkable" rather than compared against nothing and falsely flagged.

**Why does the malware or secrets scan sometimes flag legitimate code?**
Heuristic pattern matching trades some false positives for not missing real backdoors — a minifier, a legitimate `eval()` in a build tool, or a placeholder-looking-but-real API key can all trigger a finding. Review each finding's context; that's what the "View details" panel and Acknowledge/Ignore workflow are for. An Ignored finding tied to a specific file's content won't reappear unless that file actually changes afterward.

**What does FIDO2/WebAuthn need, and what happens on older PHP?**
Nothing beyond PHP 8.2+ and a browser/authenticator that supports WebAuthn (virtually all current ones). On PHP 7.4–8.1 the vendored library is never loaded and the feature doesn't appear anywhere in the UI — TOTP two-factor auth works identically either way.

**Does the domain-phishing intel or threat-intel lookups send my data anywhere?**
Domain intel only ever queries this site's own domain (never configurable) against public DNS and crt.sh's free Certificate Transparency log API — no site content is sent. Threat-intel lookups (AbuseIPDB, VirusTotal) are opt-in, need your own API key, and only ever run when you explicitly click "check reputation" on a specific IP or file hash — never automatically.

**Does it work on multisite?**
Yes, with one deliberate simplification: the filesystem is shared across every subsite, so the scanner runs once, from the main site. Subsites don't get their own scan schedules or dashboards — they'd all be scanning the same files.

**The daily scan doesn't seem to run reliably.**
WP-Cron only fires when your site gets visits, so low-traffic sites can miss schedules. Either configure a real system cron to hit `wp-cron.php`, or run `wp integrity-sentinel scan` directly from your server's crontab.

## Changelog

Full history is in [`readme.txt`](readme.txt#changelog) (WordPress.org format). Highlights of the more recent releases:

- **1.25.0** — domain-phishing intelligence (typosquat + Certificate Transparency), ransomware/mass-defacement canary, a secrets-in-code scanner, a REST API attack-surface audit, and FIDO2/WebAuthn passwordless 2FA.
- **1.16.0–1.24.0** — a single-page app-shell admin UI, ten Login Design templates with a full customizer and real preview, session security, WordPress fingerprint reduction, and optional asset cloaking.
- **1.13.0–1.15.1** — configurable scan frequency, human-in-the-loop quarantine, a Security Status dashboard overview, and a hook-timing fix that had silently disabled IP blacklisting/login rename/bot blocking.
- **1.5.0–1.12.0** — the original hardening suite: access control, login rename/rate limiting, HTTP/REST hardening, upload/shell-execution prevention, and TOTP two-factor authentication.
- **1.2.0** — self-defense tier (deactivation alarm, dead-man's switch, alert-redirection guard, audit log, webhook delivery), self-integrity check, hardening audit, opt-in uploads hardening, update monitoring.
- **1.0.0–1.1.0** — initial release: core/plugin checksum verification, heuristic PHP malware scanning, uploads-PHP detection, batched/resumable scans, findings dashboard, email alerts.

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. `composer install`
2. `composer test` and `composer lint` should pass.
3. If you touched any runtime file (root PHP, `includes/`, `assets/js`, `assets/css`), run `composer manifest` and commit the updated `integrity-manifest.json` — CI enforces this with `composer manifest:check`.

## License

GPLv2 or later. See [License URI](https://www.gnu.org/licenses/gpl-2.0.html).

## Credits

Built by Kefa Hamisi & Benard Kimani.

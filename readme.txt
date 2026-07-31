=== Integrity Sentinel — Malware & File Scanner ===
Contributors: Kefa Hamisi & Benard Kimani
Tags: security, malware, scanner, file integrity, checksums
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.12.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Finds what's already on your site: verifies core & plugin files against official WordPress.org checksums and scans every PHP file for malware/webshell patterns.

== Description ==

Integrity Sentinel answers one question well: **"is there anything on
this site that shouldn't be here?"**

**What it checks**

* **WordPress core files** against the official WordPress.org checksum
  API — the same data source WP-CLI's `wp core verify-checksums` uses.
  Modified files, missing files, AND unexpected extra files inside
  `wp-admin/` and `wp-includes/` (a classic backdoor drop location) are
  all flagged.
* **Installed WordPress.org plugin files** against their published
  checksums (`wp plugin verify-checksums`'s data source), including
  unexpected extra files inside those plugins' directories. Premium or
  custom plugins with no published checksums are clearly listed as
  "not checkable" rather than silently skipped or falsely flagged.
* **Every PHP file on the site** for common malware/webshell code
  patterns: obfuscated `eval()` chains, request data piped into
  `shell_exec`/`system`, the deprecated `preg_replace` `/e` modifier,
  known public webshell name markers, and more.
* **PHP files hiding inside `wp-content/uploads/`** — uploads should
  only ever contain media, so executable PHP there is a strong signal
  on its own.

* **Itself.** Every scan verifies Integrity Sentinel's own files
  against its release manifest — a tampered scanner that reports "all
  clean" is worse than no scanner.
* **Site hardening.** Each scan audits configuration too: the built-in
  file editor, debug output, weak auth salts, world-writable paths,
  web-exposed `.git`/`.env`/`debug.log` files, backup archives sitting
  in the webroot, rogue or newly-created administrator accounts, and
  plugins that have been closed on WordPress.org.

Themes, mu-plugins, and premium/custom plugins have no published
WordPress.org checksums, so they can't be checksum-verified — their PHP
files are still fully covered by the malware-pattern scan.

**Tamper-resistant by design**

Attackers switch off security plugins first, so Integrity Sentinel
watches its own back:

* **Deactivation alarm** — deactivating the plugin immediately emails
  the alert address with who did it and from which IP.
* **Dead-man's switch** — if no scan completes for N days (default 2),
  you get an alert: a scanner that has silently stopped scanning
  protects nothing.
* **Alert-redirection guard** — changing the alert email notifies the
  *previous* address, so alerts can't be quietly pointed elsewhere.
* **Append-only audit log** — every scan, finding status change,
  settings change, and hardening action is recorded with user and IP.
* **Off-site webhook** — optionally POST every security event as JSON
  to a webhook (Slack-compatible), putting a copy of the evidence
  where an attacker on this server can't delete it.
* **Update monitoring** — new plugin/theme installs trigger an
  immediate alert, and WordPress.org plugin updates are checksum-
  verified seconds after they land, catching tampered packages.

**Active prevention (opt-in)**

The Hardening screen can write a clearly-marked rule block into the
uploads `.htaccess` that denies PHP execution there — a dropped
webshell in uploads becomes inert instead of merely detected (nginx
equivalent shown for manual setup). One click to apply, one to remove,
and it never touches rules it didn't write.

**How scanning works**

Scans run in small batches (configurable, default 40 files per step)
driven by a live AJAX progress bar, so a large site doesn't time out
mid-scan. A background cron job runs a full scan daily, and a
five-minute safety-net check resumes any scan that got interrupted
(e.g. an admin closed the browser tab mid-scan) — reloading the
dashboard mid-scan picks the progress bar back up where it left off.
Only one process ever drives a scan at a time, so the browser, cron,
and WP-CLI can't trip over each other.

**WP-CLI**

Because WP-Cron is only as reliable as your site's traffic, the scan is
also available as a WP-CLI command — ideal for a real system crontab:

* `wp integrity-sentinel scan` — run a full scan (exits non-zero if new
  findings were recorded, so cron wrappers can alert).
* `wp integrity-sentinel status` — show the most recent run.
* `wp integrity-sentinel findings [--status=…] [--severity=…] [--format=json]`
  — list findings, scriptable output formats included.

**What this is not**

This is a file-integrity and malware-pattern scanner — it does not
include a web application firewall, login/brute-force protection, or a
global real-time threat-intelligence network. It's meant to be run
alongside whatever handles those (or as your first layer while you
evaluate one).

== Installation ==

1. Upload the `integrity-sentinel` folder to `/wp-content/plugins/`.
2. Activate the plugin through the "Plugins" screen.
3. Go to Integrity Sentinel → Settings to set an alert email and
   (optionally) exclude paths like cache directories from scanning.
4. Click "Scan now" on the Dashboard, or wait for the daily background
   scan.

== Frequently Asked Questions ==

= Does this modify or delete anything it finds? =

No. Every check in this plugin is read-only: it hashes files, reads
file contents to match patterns, and calls the WordPress.org checksum
APIs. It never writes to, deletes, or executes anything it scans.
Remediation (removing a confirmed backdoor, restoring a clean file) is
left to you, since that's exactly the kind of destructive action a
security tool shouldn't take unattended.

= Will this flag every plugin I have installed? =

Only plugins installed from the WordPress.org repository can be
checksum-verified at all — premium and custom plugins are listed
separately as "not checkable" rather than compared against nothing and
falsely flagged.

= Why does the malware scan sometimes flag legitimate code? =

Heuristic pattern matching trades some false positives for not missing
real backdoors. A minifier, a legitimate use of `eval()` in a build
tool, or an old codebase using `create_function()` can all trigger a
finding. Review each finding's context before acting on it — that's
exactly what the "View details" panel and Acknowledge/Ignore workflow
are for.

= Does it work on multisite? =

Yes, with one deliberate simplification: the filesystem is shared
across every subsite, so the scanner runs once, from the main site.
Subsites don't get their own scan schedules or dashboards — they'd all
be scanning the same files.

= The daily scan doesn't seem to run reliably. =

WP-Cron only fires when your site gets visits, so low-traffic sites can
miss schedules. Either configure a real system cron to hit
`wp-cron.php`, or run `wp integrity-sentinel scan` directly from your
server's crontab.

== Changelog ==

= 1.12.0 =
* New: two-factor authentication (TOTP, RFC 6238) — self-service setup
  from each user's own profile page, requiring one valid code before
  it's actually enabled so a mistyped/unsynced authenticator app can
  never lock a user out. Eight single-use recovery codes (SHA-256
  hashed, shown once) for lost-device recovery. Optional per-role
  enforcement on the Login Security screen — enforcement never blocks
  login itself, it redirects an unset-up user to their profile instead,
  which is what makes it safe to turn on without warning everyone
  first. No QR code image is rendered (would need either a bundled
  third-party JS library or an external service call that would leak
  the secret); the manual-entry key and otpauth:// link work with
  every authenticator app as the standard "can't scan a code" fallback.

= 1.11.0 =
* New: REST API screen. Blocks unauthenticated /wp/v2/users access and
  the old ?author=N enumeration redirect by default (safe for any
  site). Optional full lockdown of unauthenticated REST access with an
  allowed-route allowlist, off by default since many themes/plugins
  depend on public REST routes.
* New: integrity-sentinel/v1/posts REST endpoint for creating blog
  posts from an external tool, authenticated with WordPress's own
  Application Passwords (no bespoke secret store), scoped by ordinary
  edit_posts/publish_posts capabilities, and rate-limited per user.

= 1.10.0 =
* New: hotlink protection (Hardening screen) — writes a marker-delimited
  .htaccess rule block denying cross-site embedding of images from
  wp-content/uploads, with an editable allowed-domains list (your own
  domain is always allowed automatically) and an nginx snippet for
  manual setup. Direct access and no-referer requests (feed readers,
  social-share previews) always still work.
* New: AI-crawler/scraper bot blocking (Access Control screen) — a
  curated, editable list of AI-training crawlers and scrapers (GPTBot,
  ClaudeBot, CCBot, Bytespider, and others) is blocked with a 403, and
  the same names are added as Disallow entries in robots.txt for the
  crawlers that honor it. Enabled by default — blocking known bot user
  agents carries no risk to human visitors.

= 1.9.0 =
* New: five additional obfuscation-detection heuristics — a function
  name built from concatenated chr() calls, a variable-variable used
  as a function call, a flood of \xHH hex-escape sequences, a
  dangerous function name spelled via concatenated string literals
  (e.g. two short fragments joined by a dot), and a charset-independent
  entropy check that flags long, high-randomness string literals even
  when they aren't base64 (catching hex/XOR/custom-encoded payloads
  the existing base64-charset check would miss).

= 1.8.0 =
* Fix: "Ignore" on a finding is now durable — an ignored finding no
  longer silently reappears as a brand-new "new" finding on the very
  next scan when the underlying file is unchanged. If the file's
  content actually changes afterward, it's correctly flagged again.
* Change: two of the noisiest heuristic rules (error-suppressed
  variable includes, long base64-looking string literals) are now
  'low' severity instead of 'medium' — both are common in legitimate
  WordPress code on their own; the genuinely dangerous combinations
  already have their own dedicated, higher-severity rules.

= 1.7.0 =
* New: upload-time blocking of executable file types (.php and
  variants, .cgi, .pl, .py, .sh, .asp/.aspx, .jsp, .exe, .phar, ...) —
  applies to the media uploader, plugin/theme install-by-upload, and
  any importer using wp_handle_upload(). Catches double-extension
  disguises (e.g. shell.php.jpg) too. Always on; never affects
  legitimate media.
* New: the PHP-execution .htaccess block (previously uploads-only) now
  also covers wp-content/cache, wp-content/upgrade, and
  wp-content/temp when present — other writable, commonly-abused
  secondary drop locations for a webshell. Same one-click apply/remove
  as uploads, per directory, on the Hardening screen.
* New: hardening check reporting which PHP shell-execution functions
  (exec, shell_exec, system, passthru, popen, proc_open, pcntl_exec)
  are still enabled, with the exact disable_functions value to set if
  your hosting plan allows it.

= 1.6.0 =
* New: Login Security screen with two independent, off-by-default-safe
  features:
  * Login URL rename — hides wp-login.php behind a custom slug of your
    choice. Off by default (blank slug = stock behavior unchanged).
    Covered by the IS_SAFE_MODE kill switch if it ever needs a fast
    undo.
  * Login rate limiting — locks an IP out of authentication after
    repeated failed logins (default: 5 within 15 minutes, 15-minute
    lockout). Whitelisted IPs (Access Control) always bypass it.

= 1.5.0 =
* New: Access Control screen — editable, CIDR-aware IP whitelist and
  blacklist (IPv4 and IPv6). Blacklisted visitors get a 403 before most
  of WordPress loads; the whitelist always wins over the blacklist, and
  the admin saving the page always has their own current IP kept in the
  whitelist automatically, so a blacklist mistake can't lock them out.
* New: optional reverse-proxy/CDN support for the above — a forwarded-IP
  header (X-Forwarded-For, CF-Connecting-IP, X-Real-IP) is trusted only
  when the direct connection itself comes from an explicitly configured
  trusted proxy range, so it can't be spoofed by a direct attacker.

= 1.4.0 =
* New: HTTP hardening bundle on the Hardening screen — security headers
  (X-Content-Type-Options, Referrer-Policy, Permissions-Policy),
  clickjacking protection (X-Frame-Options + frame-ancestors CSP), and
  WordPress-version hiding (generator tag + asset ?ver= stripping) are
  all on by default. Disabling XML-RPC and disabling RSS/Atom feeds are
  available as opt-in toggles (off by default — both can break a real
  integration) since they can break Jetpack/mobile-app/feed-subscriber
  use cases some sites rely on.

= 1.3.0 =
* New: fault-isolation layer (IS_Guard) — every hardening/detection
  module now runs inside a per-module circuit breaker instead of
  directly off a WordPress hook. A module that keeps throwing pauses
  itself for a cooldown period (with an audit-log entry and an alert
  if configured) instead of risking a site fatal; every other module
  keeps running unaffected.
* New: IS_SAFE_MODE kill switch — define `IS_SAFE_MODE` truthy in
  wp-config.php to pause every guarded hardening module at once. The
  last-resort escape hatch for a site owner locked out by a hardening
  feature, no database or admin access required.
* New: Feature health panel on the Dashboard, showing each module's
  status and a one-click reset for a paused module.

= 1.2.0 =
* New: self-defense tier — deactivation alarm, dead-man's switch
  (configurable, default 2 days), alert-redirection guard, append-only
  audit log with its own admin screen, and optional off-site webhook
  delivery of all security events.
* New: self-integrity check — every scan verifies the plugin's own
  files against its release manifest and flags tampering, missing
  files, or unknown files in its directory as critical findings.
* New: hardening audit on every scan — file editor enabled, debug
  display, weak/placeholder auth salts, default table prefix,
  allow_url_include, EOL PHP, world-writable paths, web-exposed
  .git/.env/debug.log, backup archives in the webroot, XML-RPC,
  "admin" username, administrators created since the last scan, and
  plugins closed on WordPress.org.
* New: opt-in uploads hardening — one click writes (and cleanly
  removes) an .htaccess block denying PHP execution in uploads, with
  the nginx equivalent shown for manual setup.
* New: update monitoring — alerts on new plugin/theme installs, and
  verifies WordPress.org plugin updates against published checksums
  immediately after they complete.

= 1.1.0 =
* New: unexpected extra files inside `wp-admin/`, `wp-includes/`, and
  checksum-verified plugin directories are now flagged (classic malware
  drop locations that checksum comparison alone can never see).
* New: `wp integrity-sentinel scan | status | findings` WP-CLI commands.
* New: reloading the dashboard mid-scan resumes the live progress bar.
* New: multisite-aware — runs once from the main site instead of
  duplicating scans per subsite.
* Fixed: the scanner no longer flags its own heuristics file as a
  webshell (rule literals are now self-match-proof, with a regression
  test).
* Fixed: core/plugin checksum verification now runs *before* stale
  findings are auto-resolved and the alert email is sent, so persistent
  checksum findings no longer duplicate every scan and alerts include
  them.
* Fixed: interrupted scans resumed by cron now include the checksum
  verification passes.
* Fixed: scans are single-driver — an advisory lock stops the browser
  loop and the cron safety-net from processing the same batch twice
  (stall detection is now based on last activity, not start time).
* Fixed: alert emails count only findings from the completed scan, not
  every unacknowledged finding on record.
* Fixed: every occurrence of a heuristic match in a file is reported
  (previously only the first), and two different rules matching one
  file no longer overwrite each other's findings.
* Improved: scan cursor no longer rewrites the full file list after
  every batch; progress persists per file, and each batch respects a
  time budget so high batch sizes can't hit PHP's execution limit.
* Improved: plugins without published checksums (premium/custom) are
  remembered for a week instead of being re-requested every scan.

= 1.0.0 =
* Initial release: core checksum verification, plugin checksum
  verification, heuristic PHP malware scanning, uploads-PHP detection,
  batched/resumable live scans, findings dashboard, email alerts.

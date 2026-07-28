=== Integrity Sentinel — Malware & File Scanner ===
Contributors: Kefa Hamisi & Benard Kimani
Tags: security, malware, scanner, file integrity, checksums
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Finds what's already on your site: verifies core & plugin files against official WordPress.org checksums and scans every PHP file for malware/webshell patterns.

== Description ==

Integrity Sentinel answers one question well: **"is there anything on
this site that shouldn't be here?"**

**What it checks**

* **WordPress core files** against the official WordPress.org checksum
  API — the same data source WP-CLI's `wp core verify-checksums` uses.
* **Installed WordPress.org plugin files** against their published
  checksums (`wp plugin verify-checksums`'s data source). Premium or
  custom plugins with no published checksums are clearly listed as
  "not checkable" rather than silently skipped or falsely flagged.
* **Every PHP file on the site** for common malware/webshell code
  patterns: obfuscated `eval()` chains, request data piped into
  `shell_exec`/`system`, the deprecated `preg_replace` `/e` modifier,
  known public webshell name markers, and more.
* **PHP files hiding inside `wp-content/uploads/`** — uploads should
  only ever contain media, so executable PHP there is a strong signal
  on its own.

**How scanning works**

Scans run in small batches (configurable, default 40 files per step)
driven by a live AJAX progress bar, so a large site doesn't time out
mid-scan. A background cron job runs a full scan daily, and a
five-minute safety-net check resumes any scan that got interrupted
(e.g. an admin closed the browser tab mid-scan).

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

== Changelog ==

= 1.0.0 =
* Initial release: core checksum verification, plugin checksum
  verification, heuristic PHP malware scanning, uploads-PHP detection,
  batched/resumable live scans, findings dashboard, email alerts.

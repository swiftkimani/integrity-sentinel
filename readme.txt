=== Integrity Sentinel — Malware Scanner & Hardening Suite ===
Contributors: Kefa Hamisi & Benard Kimani
Tags: security, malware, hardening, two-factor, firewall
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.22.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

File-integrity scanning against official WordPress.org checksums, plus a full hardening suite: access control, login/2FA, HTTP/REST hardening, bot blocking, and human-in-the-loop quarantine.

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

**The full hardening suite**

Everything below runs through a fault-isolation layer (a module that
keeps erroring pauses itself instead of risking the site), and every
feature that could conceivably break a real integration if misconfigured
(XML-RPC, feeds, login rename, full REST lockdown) ships off by default
— the Dashboard's Security Status panel shows the state of all of it
at a glance, each linking to where it's configured:

* **Access control** — editable, CIDR-aware IP allow/deny lists;
  hotlink protection; a curated, editable AI-crawler/scraper blocklist.
* **Login security** — hide wp-login.php behind a custom slug; per-IP
  login rate limiting; TOTP two-factor authentication with recovery
  codes and optional per-role enforcement.
* **HTTP/REST hardening** — security headers, clickjacking protection,
  WordPress-version hiding, REST user-enumeration blocking, and an
  optional full REST lockdown for unauthenticated requests.
* **Integration endpoint** — a dedicated `integrity-sentinel/v1/posts`
  REST endpoint for creating blog posts from an external tool,
  authenticated with WordPress's own Application Passwords.
* **Shell-execution prevention** — blocks executable file types at
  upload time, extends the PHP-execution block to other writable
  directories, and audits which dangerous PHP functions are still
  enabled.
* **Quarantine** — suspends a flagged file into a locked-down
  directory instead of deleting it; a human explicitly restores or
  permanently deletes it later. Nothing is ever removed automatically.
* **IS_SAFE_MODE** — a `wp-config.php` kill switch that instantly
  pauses every hardening module, for recovering from a misconfiguration
  without database access.

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

= 1.22.0 =
* New: known-vulnerability scanning — checks installed plugins and the
  active theme against the WPScan Vulnerability Database on every scan,
  reporting matches with severity, CVE references, and the fixed
  version. Catches what file-integrity checking structurally can't: a
  completely untampered plugin with a known, published, unpatched CVE.
  Opt-in (needs a free WPScan API key), off by default.
* New: password strength policy — WordPress core's own strength meter
  is advisory only and still accepts a weak password; this actually
  rejects one, on both the "forgot password" reset flow and profile/
  user-edit password changes. Configurable minimum length and
  character-class requirements, plus a always-on common-password
  blocklist once enabled. Off by default.
* New: a real, configurable Content-Security-Policy header, alongside
  the existing minimal clickjacking-only one (which still works exactly
  as before if this isn't touched). Off by default, with a report-only
  mode to test safely before enforcing, and a suggested starting policy
  that closes off the classic object-embed and base-tag-hijack vectors
  without breaking a typical theme/plugin's inline scripts/styles.

= 1.21.0 =
* Fixed: a real bug where an uploaded login logo never actually
  rendered — the "hide WordPress branding" rule (on by default) and the
  logo-override rule used selectors of different CSS specificity, so
  the branding rule always won regardless of which came later in the
  stylesheet. Both now match exactly, with a regression test.
* Fixed: every settings page's field table (form-table) had a glass
  background and rounded corners but no interior padding or border at
  all, so fields sat flush against the rounded edges — the container
  had nothing containing it. Every settings page now gets proper
  padding, border, and shadow, matching the rest of the UI.
* New: Session Security — every admin can see their own active login
  sessions (device, IP, sign-in time) and revoke individual ones or
  all-others-at-once; a manage_options user can force-logout any
  account's sessions entirely from the Users list (incident response);
  an optional alert fires the first time an account logs in from an IP
  it hasn't used before. Built entirely on WordPress core's own session
  API, no custom session storage.
* New: WordPress fingerprint reduction — removes the wlwmanifest,
  shortlink, and REST-API-discovery head links/header that advertise
  WordPress-specific endpoints on every page. Safe for any site, on by
  default; purely stops advertising these URLs, doesn't disable them.
* New (opt-in, off by default): disguises /wp-content/ and
  /wp-includes/ asset URLs behind a chosen alias, reducing what a
  visitor sees in page source or a browser's Sources panel. The
  riskiest thing this plugin writes to disk — a root .htaccess rewrite
  rule — so it ships with heavy warnings, an Nginx snippet for non-
  Apache servers, and a one-click removal. Verified the generated rule
  syntax directly against Apache's own config parser before shipping.

= 1.20.0 =
* Fixed: the Media Library picker (logo and hero image) could silently
  fail to respond to clicks if its script hadn't finished loading yet
  when the page first rendered. It now checks at click time instead of
  page-load time, so it always works regardless of load order.
* Improved: the real-preview button now surfaces the actual failure
  reason (in the browser console and on-screen) instead of a generic
  message if something goes wrong, making any future issue diagnosable.
* New: three more split-screen templates — Forest, Monochrome, and
  Ocean — alongside Sunrise, Aurora Night, Bubblegum, and Minimal (7
  total).
* New: hero panel placement — left or right — so the artwork and the
  sign-in form can trade sides.
* New: an explicit "Hide WordPress branding" checkbox (on by default)
  instead of the behavior being silent/automatic — turn it off to
  restore the stock WordPress logo and page title.
* Improved: a finer responsive breakpoint for small phones, tightening
  card padding instead of just inheriting the tablet layout.

= 1.19.0 =
* New: Login Design templates reworked as "split-screen" layouts —
  three built-in designs (Sunrise, Aurora Night, Bubblegum) with a
  decorative hero panel (heading, subheading, and either a generated
  pattern or your own uploaded photo/illustration) beside the sign-in
  card, plus a plain Minimal option. Colors, logo, corner roundness,
  custom CSS, and a custom HTML banner all still apply on top.
* Changed: the login page no longer mentions WordPress anywhere —
  the default logo mark, its link target, and the browser tab title
  are always replaced with your site's own name/homepage, not just
  when a custom logo is set.
* New: a real, unsaved-changes preview. "Open real preview" saves your
  in-progress edits to a short-lived per-admin draft and opens the
  actual login page rendering them — no need to save first, and
  nothing is written to the live settings until you click Save. A
  smaller instant mockup on the settings page also updates as you type
  for quick, no-network feedback.
* Fixed: the old wp-login.php/wp-admin block returned WordPress's bare
  `wp_die()` "Not Found" text. It's now a proper themed 404 page (matches
  what a real 404 on the site would look like, no hint that it's a
  security block) with a link back to the homepage and an automatic
  redirect there after a few seconds.

= 1.18.0 =
* Fixed: hiding the login page previously only blocked wp-login.php —
  the old default `/wp-admin/` route still worked for anyone not
  logged in, quietly redirecting to the new login URL and confirming
  it was hidden in the first place. It now 404s the same way
  wp-login.php does (admin-ajax.php/admin-post.php and already
  logged-in users are unaffected).
* New: optional admin subdomain (e.g. `admin.example.com`) as a second
  login entry point once DNS/your web server routes it to the same
  site — the login form loads at that host's root, no slug in the
  URL. Requires a custom login slug to already be set; the settings
  page documents the `COOKIE_DOMAIN` change this needs in
  wp-config.php.
* New: Login Design — replaces the stock wp-login.php look with four
  built-in templates (Refined Default, Midnight Glass, Minimal, Aurora
  Gradient), a customizer (accent color, logo, corner roundness), a
  custom-CSS box, and a sanitized custom-HTML banner above the form,
  with a live preview on the settings page.

= 1.17.0 =
* New: "liquid glass" visual refresh for the app shell — frosted
  glass panels (backdrop-filter blur) on the sidebar, cards, status
  tiles, tables, buttons, and modal, layered over a soft multi-colour
  gradient backdrop (indigo/violet/fuchsia/cyan). Gradient-text page
  headings, glowing gradient active-nav state and primary buttons.
* Fix: the sidebar's `position: sticky` was silently broken by
  `.is-shell`'s `overflow: hidden` (added earlier purely for rounded
  corners) — an overflow-hidden ancestor becomes the sticky element's
  containing block, which isn't the viewport, so it never actually
  stuck while scrolling. Fixed by dropping `overflow: hidden` from the
  shell and giving the sidebar/content panes their own split
  `border-radius` instead; the sidebar now genuinely stays put while
  the content column scrolls, with its own internal scroll if the nav
  list is ever taller than the viewport.

= 1.16.0 =
* New: single-page "app shell" UI — every Integrity Sentinel screen now
  shares one left sidebar (Dashboard, Findings, Quarantine, Hardening,
  Access Control, Login Security, REST API, Audit Log, Settings) inside
  the plugin's own page, instead of a flyout submenu under WP's admin
  menu. WordPress's admin sidebar now shows a single clean "Integrity
  Sentinel" entry. Restyled with a modern, cohesive design system
  (dark sidebar, indigo accents, card-based content, refined
  typography) across every screen, verified in a live browser.
* Fix (found during that verification): registering pages with
  remove_submenu_page() to hide them from WP's flyout also deletes the
  bookkeeping WordPress's own access-control check depends on, so
  every hidden page except the first started returning "Sorry, you are
  not allowed to access this page." Fixed by keeping every page fully
  registered and hiding only the visible flyout via CSS instead.

= 1.15.1 =
* Fix: IP blacklisting, login URL rename, and AI-bot blocking were
  registering their enforcement on the 'plugins_loaded' hook from
  inside another 'plugins_loaded' callback (is_init()) — a hook that
  fires exactly once per request, so a callback registered for it from
  within another callback of the same hook is registered too late to
  ever run. All three features silently never enforced anything.
  Caught via a live end-to-end test against a real WordPress install
  (unit tests only cover pure logic and couldn't catch this — it's a
  WordPress hook-timing integration issue). Fixed by moving all three
  to the 'init' hook, which fires immediately after 'plugins_loaded'
  and is unaffected by the same problem. Verified live: IP
  blacklisting, AI-bot blocking, and login URL rename now all
  correctly block/redirect as designed.

= 1.15.0 =
* New: "Security status" overview on the Dashboard — one glance at
  every hardening feature this plugin ships (headers, XML-RPC/feeds,
  hotlink protection, IP access control, AI bot blocking, login
  rename/rate limiting, two-factor enforcement, REST restriction, the
  blog-post endpoint, and quarantine), each linking straight to where
  it's configured. Settings stay on their existing WP-admin-convention
  submenu pages rather than being physically merged into one giant
  page — same organizing pattern every other security plugin uses —
  but now there's one place to see the state of all of them together.
* New: responsive design pass across every admin screen — data tables
  scroll horizontally instead of squeezing unreadably narrow on phones
  and tablets (same 782px breakpoint WP admin's own menu collapses
  at), the dashboard's card grids reflow from four columns down to one
  as the screen narrows, and checkboxes get a small dependency-free
  visual upgrade (accent-color) instead of the bare browser default.
* Updated the plugin's own description to reflect what it actually
  does now — it grew well past "scanner" over the last several
  releases.

= 1.14.0 =
* New: Quarantine screen — a human-in-the-loop quarantine engine, the
  same principle Wordfence itself uses under the hood: suspend, never
  destroy. A flagged file is moved (not copied, not deleted) into a
  locked-down directory outside its original location and stays there
  until you explicitly restore it or permanently delete it — nothing
  quarantines or deletes anything automatically or on a schedule.
  Available for findings that point at genuinely extra/unexpected
  files (heuristic hits, PHP hiding in uploads, unknown files inside
  core/plugin directories) — deliberately NOT for modified-core or
  modified-plugin findings, since removing those would break the site
  rather than protect it. Permanent deletion requires an explicit
  confirmation checkbox — the one genuinely irreversible action in the
  whole plugin.
* Implemented entirely in PHP — works on every host with zero setup,
  consistent with this plugin's zero-runtime-dependency design. An
  optional Rust-based accelerator for hashing/scanning speed on
  capable hosts remains a possible future addition, never a
  requirement for quarantine to work.

= 1.13.0 =
* New: configurable automatic scan frequency (hourly, twice daily,
  daily, weekly) on the Settings screen, on top of the existing
  batched/resumable/cron-driven scan engine. Both the Settings and
  Dashboard screens now show when the next scheduled scan will run.
* New: self-tuning pace guidance — the scanner tracks its own observed
  milliseconds-per-file on this site (a rolling average) and shows an
  estimate of how long the current batch size takes, so you can tell
  if it's likely to exceed your host's PHP execution time limit before
  finding out the hard way.

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

=== PureScan ===
Contributors: evjaj
Tags: security, malware scanner, wordpress security, scanner, malware
Requires at least: 5.6
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.2.25
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced real-time malware scanner with deep inspection, live search, safe quarantine, and optional AI analysis.

== Description ==

PureScan is a powerful and modern WordPress malware scanner built for speed, accuracy, and safety. It scans your entire WordPress installation in real time, detecting suspicious files, modified core/plugin files, injected spam links, weak passwords, and hidden threats.

### Free Version Features
* **Deep Scan** – Comprehensive site-wide scanning with live progress tracking
* **Live Search** – Instant file search by name, path, or code pattern (results appear as you type)
* **Safe Quarantine** – Neutralize threats without deleting files (automatic dated backups + one-click restore)
* **Ignored Files** – Permanently exclude confirmed safe items from future scans
* **Integrity Checks** – Detects modified WordPress core and PureScan plugin files
* **Spamvertising Detection** – Scans posts and comments for injected links
* **User & Password Audit** – Flags weak passwords and suspicious users
* **Professional Interface** – Clean admin UI with real-time badges, file viewer, and diff comparison
* **Shared Hosting Friendly** – No timeouts, background-safe execution
* **Smart Pattern Detection** – Multi-source patterns (fresh remote, cached remote, fresh local, cached local) with automatic fallback and offline reliability

### Pro Features (Activated via License)
* AI-powered verification for near-perfect accuracy (optional – controlled via “Enable AI Features” toggle in Settings)
* AI Scan tab – paste suspicious71 code for instant AI-powered analysis **or** ultra-fast local scan without AI (no data leaves your server – uses current pattern source)
* Automatic scheduled scans with email reports
* Database deep scan
* External file scanning
* Priority support

PureScan never deletes files automatically. Quarantine is completely safe and fully reversible.

== Installation ==
1. Upload the `purescan` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Visit the new "PureScan" menu in your admin dashboard
4. Run your first Deep Scan

For Pro features: Purchase a license and refresh status in the "Upgrade to Pro" tab.

== Frequently Asked Questions ==
= Is PureScan safe? =
Yes. No automatic file deletion or modification. Quarantine creates mandatory backups and is fully reversible.

= Does it affect site performance? =
No. All scans run in the background with no frontend impact.

= How do Pro features work? =
Pro features are unlocked via secure license verification after purchase.

= Can it handle large sites? =
Yes. Optimized chunked execution scales to millions of files.

== Privacy Notice ==
PureScan respects your privacy and does not collect any personal or sensitive data.

The plugin only connects to our server in these limited cases:
- **Detection Patterns Update**: At the start of each scan, PureScan securely fetches the latest malware signatures. The request includes only a temporary token and a base64-encoded list of PureScan plugin file hashes (used solely for integrity verification). No file contents, site data, user information, or any other details are sent.
  - Smart 4-layer caching is used: fresh remote patterns → cached remote → fresh local bundled → cached local.
  - If the server is unreachable, PureScan instantly falls back through the cache layers to bundled local patterns with zero interruption.
- When “Enable AI Features” is turned on and External API mode is selected: to retrieve secure fallback OpenRouter API keys (only your site domain is sent for verification – no other data).
- For plugin integrity checks: to verify PureScan’s own files have not been tampered with (checksum comparison only).

All scanning and analysis runs locally on your server. When AI analysis is used, only the suspicious code snippet is sent anonymously to OpenRouter – no identifiers, site content, or personal information is included.

**“Scan without AI” mode in the AI Scan tab and all non-AI scans send no data whatsoever** – everything stays on your server and uses the current pattern source (which may be remote-cached, local-cached, or bundled local).

No usage data, analytics, or tracking is performed.

== Screenshots ==
1. Deep Scan tab – real-time step-by-step progress bar, live counters, and current folder indicator
2. Deep Scan tab – Results section with filter buttons, collapsible threat cards, AI verdict, and one-click actions
3. Live Search tab – lightning-fast real-time search with instant single-file scan and AI analysis
4. AI Scan tab – paste suspicious code for instant AI-powered analysis or fast “Scan without AI” (no data sent – uses current pattern source)
5. Quarantine tab – safe neutralization list with automatic backups and restore options
6. Ignored tab – manage permanently excluded files and database entries
7. Settings tab – scan configuration, path management, and performance options
8. Settings tab – OpenRouter AI integration with master toggle, API source selection, and connection testing
9. Upgrade to Pro tab – license status, Pro-exclusive features overview, and activation instructions

== Changelog ==
= 1.2.25 =
* Added “Scan without AI” button in AI Scan tab (fast pattern scan using current source – no data leaves server)
* Enhanced pattern detection with smart 4-layer source system (fresh remote, cached remote, fresh local, cached local) for maximum reliability
* Updated documentation, screenshots description, and privacy notice to reflect new pattern system and local scan option
* Minor UI tweaks for button colors (purple for AI, green for local scan)

= 1.2.24 =
* Added detailed screenshots for all tabs including separate Deep Scan results and AI integration settings
* Minor UI improvements and documentation updates

= 1.2.23 =
* Updated Stable tag and Tested up to for WordPress.org compatibility
* Minor improvements and bug fixes

= 1.2.22 =
* Initial public release on WordPress.org
* Full Deep Scan with professional real-time UI
* Live Search with instant single-file scanning
* Safe quarantine system with automatic backups
* Ignored files management
* Dynamic admin menu badges

== Upgrade Notice ==
= 1.2.25 =
New “Scan without AI” option and enhanced 4-layer pattern detection system added for better privacy, speed, and reliability. Update recommended for all users.
<?php
/**
 * PureScan Help & Documentation Tab
 *
 * @package PureScan\Help
 */
namespace PureScan\Help;

if (!defined('ABSPATH')) {
    exit;
}

class Help_UI {
    public static function render() {
        ?>
        <div class="purescan-card">
            <h2 class="purescan-section-title">
                <span class="dashicons dashicons-book" style="font-size: 26px; vertical-align: middle; margin-right: 10px;"></span>
                Help & Documentation
            </h2>
            <p class="purescan-description">
                Complete guide to using PureScan – Advanced WordPress Malware Scanner
            </p>

            <!-- Accordion Sections -->
            <div id="purescan-help-accordion">
                <!-- Deep Scan Tab – Complete & Detailed Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">Deep Scan Tab</div>
                    <div class="purescan-help-content">
                
                        <p style="margin-bottom:24px;">
                            <strong>Deep Scan</strong> is PureScan’s flagship feature — the fastest, most accurate, and most advanced WordPress malware scanner available.<br>
                            It combines industrial-grade pattern detection with optional AI verification to detect even the most sophisticated backdoors and threats.
                        </p>
                
                        <h4>Key Elements of the Deep Scan Tab</h4>
                
                        <div style="display:grid; gap:20px; margin:28px 0;">
                
                            <!-- Step Progress Bar -->
                            <div style="padding:20px; background:#f8fafc; border-radius:12px; border-left:5px solid #6366f1;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#6366f1;">1</span>
                                    <strong style="font-size:18px;">Step-by-Step Progress Bar</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e293b;">
                                    At the top, a modern horizontal progress bar shows every phase of the scan in real time.<br><br>
                                    • <strong>Plugin Integrity Check</strong> → Verifies PureScan plugin files<br>
                                    • <strong>WordPress Core Check</strong> → Checks for modified core files<br>
                                    • <strong>Spamvertising Checks</strong> → Scans posts/comments for injected links<br>
                                    • <strong>Password Strength Check</strong> → Audits weak administrator passwords<br>
                                    • <strong>User & Option Audit</strong> → Looks for suspicious users and database options<br>
                                    • <strong>Database Deep Scan</strong> (Pro) → Ultra-industrial scan of all database fields<br>
                                    • <strong>Server Files Discovery</strong> (Pro) → Collects files outside WordPress root<br>
                                    • <strong>Root Files Discovery</strong> → Collects all files inside WordPress installation<br>
                                    • <strong>Malware Analysis</strong> → Deep inspection of every file<br><br>
                                    Completed steps turn green (or red if threats found). The active step is highlighted in purple with a pulsing animation.
                                </p>
                            </div>
                
                            <!-- Live Progress Box -->
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">2</span>
                                    <strong style="font-size:18px;">Live Progress Box</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#166534;">
                                    Below the step bar, a clean progress box updates in real time with:<br><br>
                                    • Smooth animated progress bar showing exact percentage<br>
                                    • Live counters: e.g., “Scanned: 48,521 / 125,000 | Suspicious: 7”<br>
                                    • <strong>Pattern source indicator</strong>: Shows which detection patterns are currently in use (e.g., “Using Server Patterns” or “Using Local Cache Patterns”)<br>
                                    • Instant alerts if WordPress core files are modified<br><br>
                                    All updates happen smoothly without requiring page reloads.
                                </p>
                            </div>
                
                            <!-- Current Folder Indicator -->
                            <div style="padding:20px; background:#ecfdf5; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">3</span>
                                    <strong style="font-size:18px;">Current Folder Indicator</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#065f46;">
                                    A stylish card displays exactly what is being scanned right now:<br><br>
                                    • Relevant icon (WooCommerce, Elementor, calendar for dated uploads, wp-admin dashboard, etc.)<br>
                                    • Short, friendly name (e.g., “WooCommerce”, “November 2025”, “Media Uploads”)<br>
                                    • Full server path below for clarity<br>
                                    • Subtle pulsing green dot while actively scanning<br><br>
                                    When the scan finishes, this card shows the final summary (“Your site is clean!” or threat count) in green or red.
                                </p>
                            </div>

                            <!-- Malware Analysis Phase – Detailed Explanation -->
                            <div style="padding:20px; background:#fdf4ff; border-radius:12px; border-left:5px solid #7c3aed;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#7c3aed;">★</span>
                                    <strong style="font-size:18px;">Malware Analysis Phase – Smart 4-Layer Pattern Detection</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#4c1d95;">
                                    This is the core detection phase where every discovered file is deeply inspected using PureScan’s industrial-grade pattern engine.<br><br>
                                    PureScan uses a smart 4-layer system to load detection patterns, ensuring maximum accuracy and reliability:<br><br>
                                    <strong>The 4 possible pattern sources (in priority order):</strong><br>
                                    &nbsp;&nbsp;1. <strong>Server Patterns</strong> → Fresh patterns fetched securely from PureScan server (green badge)<br>
                                    &nbsp;&nbsp;2. <strong>Server Cache Patterns</strong> → Previously fetched server patterns from cache (blue badge, 24-hour cache)<br>
                                    &nbsp;&nbsp;3. <strong>Local Cache Patterns</strong> → Previously loaded bundled patterns from local cache (amber badge, 30-day cache)<br>
                                    &nbsp;&nbsp;4. <strong>Local Patterns</strong> → Fresh bundled patterns loaded directly from plugin files (orange badge)<br><br>
                                    • The current source is displayed in the <strong>Live Progress Box</strong> stats line (e.g., “Using Server Patterns”).<br>
                                    • Remote fetch happens only when needed (max 2 secure HTTPS requests: token + patterns).<br>
                                    • Automatic seamless fallback through all layers if connection fails — scan never stops.<br>
                                    • Server badges appear only during active scan; local badges remain until a successful remote fetch.<br><br>
                                    This system guarantees the latest detection rules when online, while working perfectly offline with long-term caching.
                                </p>
                            </div>
                
                            <!-- Results Section -->
                            <div style="padding:20px; background:#fefce8; border-radius:12px; border-left:5px solid #f59e0b;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#f59e0b;">4</span>
                                    <strong style="font-size:18px;">Results – Only Real Threats Shown</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#92400e;">
                                    Results appear live during the scan — no need to wait until the end.<br><br>
                                    • Filter buttons at the top: All, Plugin Integrity, WordPress Core, Spamvertising, Password Strength, User & Option Audit, Database Deep Scan, Malware Analysis<br>
                                    • Each finding shows: file path, size, modification date, status badge, AI explanation (if enabled), and action buttons<br><br>
                                    Only genuine threats are displayed — zero false positives or noise.
                                </p>
                            </div>
                
                            <!-- Controls & Safety -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">5</span>
                                    <strong style="font-size:18px;">Controls & Safety Features</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    • <strong>Start Deep Scan</strong> → Begins a full site scan<br>
                                    • <strong>Cancel Scan</strong> → Stops instantly and keeps all partial results<br>
                                    • <strong>Clear Results</strong> → Removes current findings (after scan completion)<br><br>
                                    Fully background-safe → works perfectly on shared hosting<br>
                                    Never times out → intelligent chunked execution<br>
                                    Scales seamlessly from tiny sites to installations with millions of files<br><br>
                                    <strong>Pro Tip:</strong> Enable AI verification in Settings for near-perfect accuracy with virtually no false positives.
                                </p>
                            </div>
                
                        </div>
                    </div>
                </div>
                
                <!-- Deep Scan Tab – Results Subsection: Complete & Detailed Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">Deep Scan Tab → Results Section</div>
                    <div class="purescan-help-content">
                
                        <p style="margin-bottom:24px;">
                            <strong>The Results section</strong> appears below the progress indicators and updates live during the scan.<br>
                            Only genuine threats are shown — PureScan eliminates noise and false positives completely. Each finding is presented in a clean, collapsible card with full context, AI verdict (when enabled), and one-click actions.
                        </p>
                
                        <h4>Key Elements of the Results Section</h4>
                
                        <div style="display:grid; gap:20px; margin:28px 0;">
                
                            <!-- Filter Buttons -->
                            <div style="padding:20px; background:#f8fafc; border-radius:12px; border-left:5px solid #6366f1;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#6366f1;">1</span>
                                    <strong style="font-size:18px;">Filter Buttons</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e293b;">
                                    At the top of the results area, filter buttons let you view specific categories instantly:<br><br>
                                    • All • Plugin Integrity • WordPress Core • Spamvertising • Password Strength • User & Option Audit • Database Deep Scan • Malware Analysis<br><br>
                                    Active filter is highlighted in purple. Results update instantly with smooth animation — no page reload needed.
                                </p>
                            </div>
                
                            <!-- Finding Cards Overview -->
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">2</span>
                                    <strong style="font-size:18px;">Finding Cards – Clean & Professional Layout</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#166534;">
                                    Each threat appears as a collapsible card with:<br><br>
                                    • Full file/database path (clickable for quick recognition)<br>
                                    • File size and last modified date<br>
                                    • Status badge (Infected, Modified, Clean, Suspicious) with color coding<br>
                                    • “Details” toggle button (arrow icon) to expand/collapse<br><br>
                                    Cards are bordered in matching color (red for Infected/Modified, green for Clean, yellow for Suspicious).
                                </p>
                            </div>
                
                            <!-- Details Panel Content -->
                            <div style="padding:20px; background:#ecfdf5; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">3</span>
                                    <strong style="font-size:18px;">Expanded Details Panel</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#065f46;">
                                    When expanded, the panel shows:<br><br>
                                    • <strong>AI Verdict</strong> (if enabled): Full AI explanation with color-coded border (red = Malicious, green = Clean, yellow = Suspicious)<br>
                                    • AI notice if analysis failed or was skipped<br>
                                    • Special warnings for:<br>
                                      – External files (outside WordPress root)<br>
                                      – Modified WordPress core files<br>
                                      – Modified PureScan plugin files<br>
                                    • Database entry warnings (no direct edit links)<br><br>
                                    All text is professionally formatted with clear headings and line breaks.
                                </p>
                            </div>
                
                            <!-- Action Buttons – Files -->
                            <div style="padding:20px; background:#fefce8; border-radius:12px; border-left:5px solid #f59e0b;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#f59e0b;">4</span>
                                    <strong style="font-size:18px;">Action Buttons – Regular Files</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#92400e;">
                                    For standard file findings:<br><br>
                                    • <strong>View Full File</strong> → Opens complete file content in new tab (with line numbers and highlighting)<br>
                                    • <strong>View Differences</strong> → Side-by-side comparison with official version (core/plugin files only)<br>
                                    • <strong>Ignore File</strong> → Permanently hides this finding<br>
                                    • <strong>Disable File (Safe Quarantine)</strong> → Neutralizes threat instantly with automatic backup<br>
                                    • <strong>Re-Analyze with AI</strong> → Forces fresh AI analysis (appears if previous analysis failed or AI was disabled)<br><br>
                                    Buttons are disabled when inappropriate (e.g., no quarantine for core/external files).
                                </p>
                            </div>
                
                            <!-- Action Buttons – Database/Content -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">5</span>
                                    <strong style="font-size:18px;">Action Buttons – Database & Content Findings</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    For posts, comments, users, and database entries:<br><br>
                                    • <strong>Edit in Admin</strong> → Direct link to WordPress editor (posts/comments/users)<br>
                                    • <strong>View Full Content</strong> → Opens complete content in secure viewer (posts/comments)<br>
                                    • <strong>Ignore Entry</strong> → Hides this database finding permanently<br><br>
                                    No quarantine option (safety) — manual cleanup via phpMyAdmin recommended for options/deep entries.
                                </p>
                            </div>
                
                            <!-- Best Practices & Tips -->
                            <div style="padding:20px; background:#fdf4ff; border-radius:12px; border-left:5px solid #c084fc;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#c084fc;">6</span>
                                    <strong style="font-size:18px;">Best Practices & Pro Tips</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#6b21a8;">
                                    • Always expand cards to read the AI explanation — it provides exact reasoning.<br>
                                    • Use “View Differences” for core/plugin files to see exactly what changed.<br>
                                    • Enable AI Deep Scan in Settings for 99.9% accurate verdicts.<br>
                                    • Quarantine is completely safe — automatic dated backups are created and restorable.<br>
                                    • Ignored items can be managed/reviewed in the Ignored tab.<br><br>
                                    <strong>Result:</strong> Professional, enterprise-grade threat response with zero guesswork.
                                </p>
                            </div>
                
                        </div>
                    </div>
                </div>                

                <!-- Live Search Tab – Complete & Detailed Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">Live Search Tab</div>
                    <div class="purescan-help-content">
                
                        <p style="margin-bottom:24px;">
                            <strong>Live Search</strong> is PureScan’s lightning-fast file finder — search by filename, folder, plugin name, or even suspicious code patterns and see matching files appear instantly as you type.<br>
                            No waiting, no page reloads — results update in real time.
                        </p>
                
                        <h4>Key Elements of the Live Search Tab</h4>
                
                        <div style="display:grid; gap:20px; margin:28px 0;">
                
                            <!-- Real-Time Search Input -->
                            <div style="padding:20px; background:#f8fafc; border-radius:12px; border-left:5px solid #6366f1;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#6366f1;">1</span>
                                    <strong style="font-size:18px;">Real-Time Search Input</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e293b;">
                                    At the top is a clean search box.<br><br>
                                    • Results appear instantly after typing just <strong>2 characters</strong><br>
                                    • Maximum <strong>50 results</strong> shown for fastest performance<br>
                                    • Search respects your Settings → Include/Exclude Paths<br>
                                    • Case-insensitive and partial matches (e.g., “login” finds wp-login.php, custom-login.php, etc.)<br>
                                    • Smart sorting: exact matches and shorter paths appear first<br><br>
                                    A spinner briefly appears during search (usually under 300ms).
                                </p>
                            </div>
                
                            <!-- Search Tips & Examples -->
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">2</span>
                                    <strong style="font-size:18px;">Search Tips & Pro Examples</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#166534;">
                                    Type any part of a filename, folder, plugin/theme name, or suspicious code:<br><br>
                                    • <code>login</code> → finds wp-login.php, admin-login.php, etc.<br>
                                    • <code>xmlrpc</code> → instantly finds xmlrpc.php (common attack target)<br>
                                    • <code>backup</code> → finds backup plugins and folders<br>
                                    • <code>cache</code> → finds all cache plugin files<br>
                                    • <code>woocommerce</code> or <code>elementor</code> → finds all files for that plugin/theme<br>
                                    • <code>eval(</code>, <code>base64_decode</code>, <code>shell</code> → finds files containing dangerous functions<br><br>
                                    <strong>Pro Tip (Pro only):</strong> Start with <code>/</code> to search absolute external paths (e.g., <code>/.cagefs</code> or <code>/tmp/evil.php</code>).
                                </p>
                            </div>
                
                            <!-- Instant Single-File Scan -->
                            <div style="padding:20px; background:#ecfdf5; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">3</span>
                                    <strong style="font-size:18px;">Instant Single-File Scan</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#065f46;">
                                    Click any result → a <strong>“Scan This File”</strong> button appears immediately.<br><br>
                                    • Click it → PureScan runs a full Deep Scan + optional AI analysis on just that file<br>
                                    • Result appears inline below in seconds with:<br>
                                    &nbsp;&nbsp;• Status badge: Clean / Suspicious / Infected / Modified<br>
                                    &nbsp;&nbsp;• Full AI explanation (if AI enabled)<br>
                                    &nbsp;&nbsp;• Highlighted dangerous code lines<br>
                                    &nbsp;&nbsp;• Pattern source indicator in the result title (e.g., “Scanned using Server Patterns”)<br>
                                    &nbsp;&nbsp;• Action buttons: View Full File, View Differences, Re-Analyze with AI, Ignore, Disable File (Quarantine)<br><br>
                                    Exactly the same detailed result format as Deep Scan findings.
                                </p>
                            </div>
                
                            <!-- Real-World Use Cases -->
                            <div style="padding:20px; background:#fefce8; border-radius:12px; border-left:5px solid #f59e0b;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#f59e0b;">4</span>
                                    <strong style="font-size:18px;">Real-World Use Cases</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#92400e;">
                                    Live Search shines when you need to quickly locate and verify a specific file:<br><br>
                                    • Security alert about xmlrpc attacks → type <code>xmlrpc</code> → scan xmlrpc.php instantly<br>
                                    • Client reports hack after installing a plugin → type the plugin name → scan all its files one by one<br>
                                    • Suspicious traffic to /wp-content/uploads/2026/evil.php → type <code>evil</code> or <code>2026</code> → find and scan it<br>
                                    • Checking a nulled theme for backdoors → type the theme name → scan every file in seconds<br>
                                    • (Pro) Suspicious external file in /.cagefs → type the full path starting with / → scan immediately
                                </p>
                            </div>
                
                            <!-- Performance & Details -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">5</span>
                                    <strong style="font-size:18px;">Performance & Safety Details</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    • Searches only files included in Deep Scan (respects your path settings)<br>
                                    • Automatically excludes binary files (images, videos, archives, fonts)<br>
                                    • Shows “(Showing first 50 results)” warning when more matches exist<br>
                                    • Extremely fast — even on sites with millions of files<br>
                                    • Full support for external/server files when External Scan is enabled (Pro)<br><br>
                                    <strong>Pro Tip:</strong> Combine with AI Deep Scan enabled for instant, highly accurate single-file verification.
                                </p>
                            </div>
                
                        </div>
                    </div>
                </div>

                <!-- AI Scan Tab – Complete & Detailed Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">AI Scan Tab - Pro</div>
                    <div class="purescan-help-content">
                  
                        <p style="margin-bottom:24px;">
                            <strong>AI Scan</strong> is one of PureScan’s most powerful Pro features — paste any suspicious PHP, JavaScript, HTML, or mixed code and get an instant, expert-level malware analysis powered by the same advanced OpenRouter AI engine used in Deep Scan.<br><br>
                            <strong>Note:</strong> This tab is only available when “Enable AI Features” is turned on in the Settings tab. If disabled, AI analysis will not work here or in Deep Scan results.
                        </p>
                  
                        <h4>Key Elements of the AI Scan Tab</h4>
                  
                        <div style="display:grid; gap:20px; margin:28px 0;">
                  
                            <!-- Code Input Area -->
                            <div style="padding:20px; background:#f8fafc; border-radius:12px; border-left:5px solid #6366f1;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#6366f1;">1</span>
                                    <strong style="font-size:18px;">Code Input Area</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e293b;">
                                    A large, clean textarea where you paste or drag & drop code.<br><br>
                                    • Supports PHP, JavaScript, HTML, CSS, mixed, or heavily encoded/obfuscated code<br>
                                    • Drag & drop any .php, .js, .html, or text file directly into the box<br>
                                    • Maximum length: <strong>8,000 characters</strong> (about 150–200 lines)<br>
                                    • Real-time character counter with warning when nearing the limit<br><br>
                                    Perfect for analyzing suspicious snippets from emails, forums, logs, or hacked files.
                                </p>
                            </div>
                  
                            <!-- Scan Button & Process -->
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">2</span>
                                    <strong style="font-size:18px;">Scan Buttons & Analysis Process</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#166534;">
                                    Click the purple <strong>“Scan with AI”</strong> button to start AI-powered analysis.<br><br>
                                    • Code is sent anonymously to OpenRouter AI (no personal data included)<br>
                                    • The AI expertly checks for obfuscation, backdoors, webshells, dangerous functions, encoded payloads, and WordPress-specific threats<br>
                                    • Analysis usually completes in seconds (fast models used)<br>
                                    • A spinner appears while processing — results replace the input area<br><br>
                                    Requires “Enable AI Features” + OpenRouter connection (configured in Settings).
                                </p>
                            </div>
                           
                            <!-- Scan without AI Option -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">3</span>
                                    <strong style="font-size:18px;">Scan without AI</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    Next to the purple <strong>“Scan with AI”</strong> button, a green button labeled <strong>“Scan without AI”</strong> is available.<br><br>
                                    • This option scans the pasted code using only PureScan’s powerful internal industrial pattern engine — no data leaves your server.<br>
                                    • It is extremely fast (instant results) and applies exactly the same advanced detection patterns used during Deep Scan file analysis.<br>
                                    • The result title dynamically shows the current pattern source (e.g., “Non-AI Scan Result (Scanned using Server Patterns)”, “(Scanned using Server Cache Patterns)”, “(Scanned using Local Cache Patterns)”, or “(Scanned using Local Patterns)”).<br>
                                    • Results are shown in a full code viewer: suspicious lines are highlighted in red, line numbers are displayed, and a clear summary message appears at the top.<br>
                                    • If no threats are detected, a green message <strong>“No Threats Found — Excellent!”</strong> is shown.<br>
                                    • Perfect for situations where you want maximum privacy, the AI connection is unavailable, or you simply need a quick local check.<br><br>
                                    <strong>Pro Tip:</strong> Use this option for rapid verification of suspicious code without sending anything to AI — it delivers the ideal combination of high speed and industrial-grade accuracy.
                                </p>
                            </div>
                  
                            <!-- AI Result Display -->
                            <div style="padding:20px; background:#ecfdf5; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">4</span>
                                    <strong style="font-size:18px;">AI Analysis Result</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#065f46;">
                                    The result appears instantly with:<br><br>
                                    • Clear status badge: <span class="purescan-status-badge purescan-clean">Clean</span>, <span class="purescan-status-badge purescan-suspicious">Suspicious</span>, or <span class="purescan-status-badge purescan-infected">Malicious</span><br>
                                    • Short one-line verdict summary<br>
                                    • Full detailed AI explanation (expandable/collapsible)<br>
                                    • “Clear All” button to reset and scan new code<br><br>
                                    The AI provides professional-level insights — exactly the same quality as Deep Scan verification.
                                </p>
                            </div>
                  
                            <!-- Real-World Use Cases -->
                            <div style="padding:20px; background:#fefce8; border-radius:12px; border-left:5px solid #f59e0b;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#f59e0b;">5</span>
                                    <strong style="font-size:18px;">Real-World Use Cases</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#92400e;">
                                    • Received a “plugin update” ZIP with suspicious code → paste it → AI says “Malicious webshell (C99 variant)”<br>
                                    • Client sends a modified functions.php snippet → paste it → AI confirms “Clean – normal theme code”<br>
                                    • Found base64 garbage in a file → paste it → AI decodes and explains multiple obfuscation layers<br>
                                    • Need a second opinion on a “Suspicious” file from Deep Scan → paste its code here for detailed AI verdict<br>
                                    • Testing code before uploading to your site
                                </p>
                            </div>
                  
                            <!-- Requirements & Troubleshooting -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">6</span>
                                    <strong style="font-size:18px;">Requirements & Troubleshooting</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    • Available only in <strong>PureScan Pro</strong><br>
                                    • Requires <strong>“Enable AI Features”</strong> turned on in Settings<br>
                                    • Requires OpenRouter connection (External fallback keys or your own Manual key in Settings)<br><br>
                                    Common messages:<br>
                                    • “AI Features are disabled” → Go to Settings → turn on “Enable AI Features”<br>
                                    • “OpenRouter API is not connected” → Go to Settings → connect or add your key<br>
                                    • “Rate limit exceeded” → Wait 1–2 minutes (temporary)<br>
                                    • “Out of credits” → Only in Manual mode if your OpenRouter account needs funding<br>
                                    • “Model not available” → Choose a different model in Settings<br><br>
                                    <strong>Pro Tip:</strong> Use this tab for quick verification of any suspicious code — instant results with no full scan required.
                                </p>
                            </div>
                  
                        </div>
                    </div>
                </div>
                
                <!-- Quarantine Tab – Complete & Detailed Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">Quarantine Tab</div>
                    <div class="purescan-help-content">
                
                        <p style="margin-bottom:24px;">
                            <strong>Quarantine</strong> is PureScan’s ultra-safe neutralization system — malicious files are instantly disabled without deleting them or breaking your site.<br>
                            An automatic dated backup is always created before neutralization, so you can restore the original at any time.
                        </p>
                
                        <h4>Key Elements of the Quarantine Tab</h4>
                
                        <div style="display:grid; gap:20px; margin:28px 0;">
                
                            <!-- Overview & Safety Notice -->
                            <div style="padding:20px; background:#f8fafc; border-radius:12px; border-left:5px solid #6366f1;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#6366f1;">1</span>
                                    <strong style="font-size:18px;">Overview & Safety Guarantee</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e293b;">
                                    This tab shows all files that have been <strong>safely neutralized</strong>.<br><br>
                                    • A secure guard header is injected → all malicious code is blocked in the frontend<br>
                                    • Your site remains 100% functional — no downtime, no broken features<br>
                                    • Automatic dated backup created before every neutralization<br>
                                    • Critical core files are never auto-neutralized (manual review required)<br><br>
                                    If no files are listed → your site has no active neutralized threats — excellent!
                                </p>
                            </div>
                
                            <!-- Neutralized Files List -->
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">2</span>
                                    <strong style="font-size:18px;">Neutralized Files List</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#166534;">
                                    Files appear in the same clean, collapsible format as Deep Scan findings.<br><br>
                                    • Badge shows <strong>“Neutralized”</strong> (red border, safe status)<br>
                                    • File path, size, and neutralization date displayed<br>
                                    • Count badge in tab title and header (e.g., “Quarantine Files (7)”)<br>
                                    • Green success notice when files are present confirming active protection<br><br>
                                    Exactly the same professional layout as scan results for consistency.
                                </p>
                            </div>
                
                            <!-- File Details Section -->
                            <div style="padding:20px; background:#ecfdf5; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">3</span>
                                    <strong style="font-size:18px;">Detailed File Information</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#065f46;">
                                    Click “Details” on any file to see:<br><br>
                                    • AI analysis result (if performed) with full explanation<br>
                                    • Neutralization details in a clean grid:<br>
                                    &nbsp;&nbsp;→ Neutralization Mode (e.g., Procedural Guard, Class Stub)<br>
                                    &nbsp;&nbsp;→ Original Risk Score (Critical / High / Medium)<br>
                                    &nbsp;&nbsp;→ File Type (PHP, JS, HTML, etc.)<br>
                                    • Latest automatic backup path and timestamp<br><br>
                                    All information clearly presented for quick review.
                                </p>
                            </div>
                
                            <!-- Action Buttons -->
                            <div style="padding:20px; background:#fefce8; border-radius:12px; border-left:5px solid #f59e0b;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#f59e0b;">4</span>
                                    <strong style="font-size:18px;">Available Actions</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#92400e;">
                                    For each neutralized file:<br><br>
                                    • <strong>View Current File</strong> → opens the safely neutralized version<br>
                                    • <strong>Analyze with AI</strong> → run/re-run AI verification on the current file<br>
                                    • <strong>Remove from Quarantine</strong> → restores the original from latest backup<br><br>
                                    Confirmation dialog appears before restore for safety.
                                </p>
                            </div>
                
                            <!-- Backup & Restore Features -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">5</span>
                                    <strong style="font-size:18px;">Backup & Safety Features</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    • <strong>Mandatory backups:</strong> Neutralization aborts if backup fails<br>
                                    • Backups stored securely in <code>wp-content/purescan-backups/</code> with dated filenames<br>
                                    • Only the <strong>latest 3 backups</strong> kept per file (oldest auto-deleted)<br>
                                    • Restore instantly returns the exact original file from backup<br>
                                    • File automatically removed from quarantine list after restore<br><br>
                                    <strong>Pro Tip:</strong> Neutralization is the safest way to handle confirmed malware — blocks threats immediately while preserving the ability to investigate or restore.
                                </p>
                            </div>
                
                        </div>
                    </div>
                </div>
                
                <!-- Ignored Tab – Complete & Detailed Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">Ignored Tab</div>
                    <div class="purescan-help-content">
                
                        <p style="margin-bottom:24px;">
                            <strong>Ignored</strong> tab displays all files and database entries you have manually chosen to ignore.<br>
                            Ignored items are permanently excluded from future Deep Scan results — useful for confirmed false positives or legitimate custom code.
                        </p>
                
                        <h4>Key Elements of the Ignored Tab</h4>
                
                        <div style="display:grid; gap:20px; margin:28px 0;">
                
                            <!-- Overview & Purpose -->
                            <div style="padding:20px; background:#f8fafc; border-radius:12px; border-left:5px solid #6366f1;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#6366f1;">1</span>
                                    <strong style="font-size:18px;">Overview & Purpose</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e293b;">
                                    This tab keeps track of everything you’ve ignored.<br><br>
                                    • Ignored files/database entries will <strong>never appear</strong> in scan results again<br>
                                    • Perfect for legitimate custom code, modified core files you trust, or confirmed false positives<br>
                                    • Orange count badge in tab title and header (e.g., “Ignored Files (12)”)<br>
                                    • If empty → “No ignored files — excellent! All suspicious items are being monitored.”<br><br>
                                    Use wisely — only ignore files you are 100% sure are safe.
                                </p>
                            </div>
                
                            <!-- Ignored Items List -->
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">2</span>
                                    <strong style="font-size:18px;">Ignored Items List</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#166534;">
                                    Items appear in the exact same clean, collapsible format as Deep Scan findings.<br><br>
                                    • Original status badge preserved (Clean / Suspicious / Infected / Modified)<br>
                                    • File path, size, and last modified date shown<br>
                                    • Supports both regular files and database entries (posts, comments, options)<br>
                                    • External files (outside WordPress root) correctly identified with badge<br><br>
                                    Full details from the original scan are retained.
                                </p>
                            </div>
                
                            <!-- Detailed View -->
                            <div style="padding:20px; background:#ecfdf5; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">3</span>
                                    <strong style="font-size:18px;">Detailed Information</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#065f46;">
                                    Click “Details” to expand and see:<br><br>
                                    • Full AI analysis (if performed) with original explanation<br>
                                    • Warnings for external files or modified core/plugin files<br>
                                    • Database-specific warnings (for option/deep entries)<br>
                                    • All original scan context preserved exactly as it was when ignored<br><br>
                                    Helps you review why you ignored it or decide to unignore.
                                </p>
                            </div>
                
                            <!-- Action Buttons -->
                            <div style="padding:20px; background:#fefce8; border-radius:12px; border-left:5px solid #f59e0b;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#f59e0b;">4</span>
                                    <strong style="font-size:18px;">Available Actions</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#92400e;">
                                    Primary action: <strong>Remove from Ignored</strong> (prominent button)<br><br>
                                    • Confirmation dialog before removal<br>
                                    • Item smoothly fades out and page reloads<br>
                                    • File will reappear in next Deep Scan<br><br>
                                    Additional actions (same as scan results):<br>
                                    • View Full File / View Differences<br>
                                    • Analyze with AI (if not already done)<br>
                                    • For database entries: Edit in Admin / View Full Content
                                </p>
                            </div>
                
                            <!-- Tips & Best Practices -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">5</span>
                                    <strong style="font-size:18px;">Tips & Best Practices</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    • Only ignore files you fully understand and trust<br>
                                    • Regularly review this list — especially after updates<br>
                                    • Use AI analysis before ignoring to confirm legitimacy<br>
                                    • Removing from ignored immediately makes it scannable again<br><br>
                                    <strong>Pro Tip:</strong> The Ignored tab is your “safe list” — keep it minimal for maximum security coverage.
                                </p>
                            </div>
                
                        </div>
                    </div>
                </div>    
                
                <!-- Settings Tab – Complete & Detailed Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">Settings Tab</div>
                    <div class="purescan-help-content">
                
                        <p style="margin-bottom:24px;">
                            <strong>The Settings tab is PureScan’s complete control center.</strong><br>
                            Here you manage all performance, speed, accuracy, and automatic protection settings — from scan limits to AI integration and scheduled scans.
                        </p>
                
                        <h4>Key Elements of the Settings Tab</h4>
                
                        <div style="display:grid; gap:20px; margin:28px 0;">
                
                            <!-- Scan Configuration Basics -->
                                <div style="padding:20px; background:#f8fafc; border-radius:12px; border-left:5px solid #6366f1;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#6366f1;">1</span>
                                    <strong style="font-size:18px;">Scan Configuration – Speed & Depth</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e293b;">
                                    • <strong>Limit Maximum Files to Scan</strong>: When off → all server files are scanned (recommended for maximum security).<br>
                                    When on → hard limit (minimum 100 files) — default: 500,000 files.<br><br>
                                    • <strong>Max File Size to Read (MB)</strong>: Larger files scanned partially (head + tail) — recommended: 5–10 MB.<br><br>
                                    • <strong>Database Deep Scan (Pro)</strong>: Deep scan of database tables for hidden payloads — extremely powerful but resource-intensive.<br><br>
                                    <strong>Tip:</strong> For large sites, enable file limit and exclude paths to speed up scans.
                                </p>
                            </div>
                
                            <!-- Path Management -->
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">2</span>
                                    <strong style="font-size:18px;">Path Management – Include & Exclude</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#166534;">
                                    • <strong>Include Paths</strong>: Only these folders will be scanned (empty = entire site).<br>
                                    Common examples: wp-content/themes, wp-content/plugins, wp-content/uploads<br><br>
                                    • <strong>Exclude Paths</strong>: These folders are completely skipped (up to 10× faster).<br>
                                    Default: uploads, cache, backups, upgrade, and similar.<br><br>
                                    You can delete any line to include that folder in scans.<br><br>
                                    <strong>Best Practice:</strong> On shared hosting, exclude uploads and cache.
                                </p>
                            </div>
                
                            <!-- AI Integration -->
                            <div style="padding:20px; background:#ecfdf5; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">3</span>
                                    <strong style="font-size:18px;">OpenRouter AI Integration</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#065f46;">
                                    • <strong>External API (default & free)</strong>: Secure rotating keys from our server — no registration required.<br>
                                    • <strong>Manual API</strong>: Your own key and model from OpenRouter (full control).<br>
                                    • <strong>Test Connection</strong>: Always test after changes — green = ready.<br>
                                    • <strong>Enable AI in Deep Scan (Pro)</strong>: Every suspicious file sent to AI — eliminates 99.9% false positives.<br><br>
                                    <strong>Tip:</strong> Keep AI always enabled — exceptional detection accuracy.
                                </p>
                            </div>
                
                            <!-- Scheduled Scans -->
                            <div style="padding:20px; background:#fefce8; border-radius:12px; border-left:5px solid #f59e0b;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#f59e0b;">4</span>
                                    <strong style="font-size:18px;">Automatic Scheduled Scans (Pro)</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#92400e;">
                                    • Turn on → PureScan automatically scans 24/7.<br>
                                    • Frequency: Daily (recommended), weekly, or monthly.<br>
                                    • Start time: 02:00–04:00 (server time).<br>
                                    • Email report: After every automatic scan (Clean or Threats Found).<br>
                                    • Live display: Countdown box for next scan + status badge on all admin pages.<br><br>
                                    <strong>Tip:</strong> With email reports, get notified of hacks immediately even if you don’t log in for months.
                                </p>
                            </div>
                
                            <!-- Advanced Features & Tips -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">5</span>
                                    <strong style="font-size:18px;">Advanced Pro Features & Best Practices</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    • <strong>External Host Config Scan (Pro)</strong>: Scan files outside WordPress root (htaccess, php.ini, etc.).<br><br>
                                    <strong>Recommended Professional Setup (2026):</strong><br>
                                    • AI in Deep Scan: ON<br>
                                    • Scheduled Scan: Daily at 02:00–04:00 + Email Report<br>
                                    • Exclude: uploads + cache + backups<br>
                                    • Database Deep Scan: Only on important sites and strong servers<br><br>
                                    <strong>Pro Tip:</strong> These settings = fully automatic and professional protection with no manual intervention needed.
                                </p>
                            </div>
                
                        </div>
                    </div>
                </div>
                
                <!-- Upgrade to Pro Tab – Complete & Detailed Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">Upgrade to Pro Tab - Pro</div>
                    <div class="purescan-help-content">
                       
                        <p style="margin-bottom:24px;">
                            <strong>The Upgrade to Pro tab is your gateway to unlocking PureScan’s full power.</strong><br>
                            Here you can check your current license status, view Pro-exclusive features, and contact the team to purchase and activate your Pro license.
                        </p>
                       
                        <h4>Key Elements of the Upgrade to Pro Tab</h4>
                       
                        <div style="display:grid; gap:20px; margin:28px 0;">
                       
                            <!-- License Status -->
                            <div style="padding:20px; background:#f8fafc; border-radius:12px; border-left:5px solid #6366f1;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#6366f1;">1</span>
                                    <strong style="font-size:18px;">License Status & Refresh</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e293b;">
                                    • Displays current status: <strong>Pro Version Active</strong> (with plan and expiry) or <strong>Lite Version Active</strong>.<br>
                                    • Shows “Last checked” timestamp.<br>
                                    • <strong>Refresh License Status Now</strong> button: Instantly re-checks your license (ideal right after purchase).<br><br>
                                    <strong>Tip:</strong> If you just purchased a license, click Refresh to activate Pro features.
                                </p>
                            </div>
                       
                            <!-- Tampered Warning -->
                            <div style="padding:20px; background:#fee2e2; border-radius:12px; border-left:5px solid #dc2626;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#dc2626;">2</span>
                                    <strong style="font-size:18px;">Plugin Tampering Warning</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#991b1b;">
                                    • Appears only if PureScan plugin files have been modified/tampered.<br>
                                    • All Pro features are automatically disabled for security.<br>
                                    • Solution: Restore original plugin files and run a new scan.<br><br>
                                    <strong>Important:</strong> This protects you from compromised versions of PureScan itself.
                                </p>
                            </div>
                       
                            <!-- Pro Features -->
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#10b981;">3</span>
                                    <strong style="font-size:18px;">PureScan Pro Exclusive Features</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#166534;">
                                    • Advanced AI-powered malware detection<br>
                                    • Automatic scheduled scans with email reports<br>
                                    • External server file scanning (outside WordPress root)<br>
                                    • Deep database payload scanning<br>
                                    • Priority support<br><br>
                                    <strong>Result:</strong> Complete autopilot security with near-perfect accuracy.
                                </p>
                            </div>
                       
                            <!-- Contact & Activation -->
                            <div style="padding:20px; background:#f0f9ff; border-radius:12px; border-left:5px solid #3b82f6;">
                                <div style="display:flex; align-items:center; gap:14px; margin-bottom:12px;">
                                    <span style="font-size:28px; font-weight:bold; color:#3b82f6;">4</span>
                                    <strong style="font-size:18px;">Contact for Purchase & Activation</strong>
                                </div>
                                <p style="margin:0; line-height:1.7; color:#1e40af;">
                                    • Contact channels:<br>
                                      – Telegram: @EvjajSales<br>
                                      – Email: info.evjaj@gmail.com<br><br>
                                    • After purchase confirmation, your Pro license will be activated manually.<br>
                                    • Refresh the page or click “Refresh License Status” to unlock Pro features instantly.<br><br>
                                    <strong>Pro Tip:</strong> Upgrade today — get full AI protection, automatic scans, and peace of mind with zero effort.
                                </p>
                            </div>
                       
                        </div>
                    </div>
                </div>
                <!-- PureScan Pro Features – Informational Guide -->
                <div class="purescan-help-section">
                    <div class="purescan-help-title">PureScan Pro – Advanced Features</div>
                    <div class="purescan-help-content">
                
                        <p style="margin-bottom:24px;">
                            <strong>PureScan Pro</strong> unlocks powerful enterprise-grade features for complete autopilot security and maximum detection accuracy.
                        </p>
                
                        <h4>Exclusive Pro Features</h4>
                
                        <div style="display:grid; gap:20px; margin:28px 0;">
                
                            <div style="padding:20px; background:#f0fdf4; border-radius:12px; border-left:5px solid #10b981;">
                                <strong style="font-size:18px; color:#166534;">AI-Powered Malware Detection</strong>
                                <p style="margin:8px 0 0; line-height:1.7; color:#166534;">
                                    • Dedicated AI Scan tab for instant code analysis<br>
                                    • Automatic AI verification (Layer 2) in Deep Scan results<br>
                                    • Near-perfect accuracy with virtually zero false positives
                                </p>
                            </div>
                
                            <div style="padding:20px; background:#ecfdf5; border-radius:12px; border-left:5px solid #10b981;">
                                <strong style="font-size:18px; color:#065f46;">Automatic Protection</strong>
                                <p style="margin:8px 0 0; line-height:1.7; color:#065f46;">
                                    • Fully automatic scheduled scans (daily/weekly/monthly)<br>
                                    • Beautiful HTML email reports when threats found<br>
                                    • Background execution – works perfectly on shared hosting
                                </p>
                            </div>
                
                            <div style="padding:20px; background:#fefce8; border-radius:12px; border-left:5px solid #f59e0b;">
                                <strong style="font-size:18px; color:#92400e;">Maximum Coverage</strong>
                                <p style="margin:8px 0 0; line-height:1.7; color:#92400e;">
                                    • Deep database scanning (postmeta, usermeta, options, etc.)<br>
                                    • External host configuration scan (files outside WordPress root)<br>
                                    • Priority support and future Pro updates
                                </p>
                            </div>
                
                        </div>
                
                        <p style="margin-top:32px; font-size:15px; color:#4b5563;">
                            Interested in these advanced features? PureScan Pro is available on our official website.
                        </p>
                
                    </div>
                </div>
            <!-- Feedback & Support -->
            <div class="purescan-feedback-box">
                <div class="purescan-feedback-inner">
                    <h3>
                        <span class="dashicons dashicons-heart" style="color:#ec4899;"></span>
                        Feedback & Support
                    </h3>
                    <p>We'd love to hear your feedback, suggestions, or bug reports!</p>
                    
                    <!-- false positive -->
                    <p style="margin:20px 0; padding:16px; background:#fffbeb; border-radius:8px; border-left:4px solid #f59e0b; font-size:14.5px; line-height:1.7; color:#92400e;">
                        <strong>Help us improve detection accuracy:</strong><br>
                        If you encounter any <strong>false positives</strong> — legitimate code incorrectly flagged as malicious — please send us a screenshot or copy of the <strong>highlighted red sections</strong> (the suspicious lines shown in the file viewer).<br><br>
                        This greatly helps us refine our patterns and eliminate false alarms in future updates.
                    </p>
                    
                    <div class="purescan-contact-links">
                        <a href="mailto:info.evjaj@gmail.com" class="purescan-contact-link">
                            <span class="dashicons dashicons-email-alt"></span>
                            info.evjaj@gmail.com
                        </a>
                        <a href="https://t.me/EvjajSales" target="_blank" class="purescan-contact-link">
                            <span class="dashicons dashicons-admin-comments"></span>
                            @EvjajSales
                        </a>
                    </div>
                    
                    <p class="purescan-feedback-footer">
                        Your input helps us make PureScan even better
                    </p>
                </div>
            </div>
        </div>
        <?php
    }
}
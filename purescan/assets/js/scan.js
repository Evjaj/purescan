/**
 * PureScan Deep Scan Tab JavaScript — Simplified & Optimized Version
 * Live results are shown during scan with restricted "Details" panel.
 * During active scan: Only a clean English warning message is displayed in Details.
 * All advanced features (AI analysis, actions, diff view, re-analyze, etc.) are hidden in live mode.
 * Full details and actions are available only after scan completion (automatic page reload).
 * Analyze with AI button fully functional in final results, Quarantine tab, and Live Search tab.
 */
document.addEventListener('DOMContentLoaded', function () {
    const $ = document.querySelector.bind(document);
    const $$ = document.querySelectorAll.bind(document);
    // Core elements
    const startBtn = $('#purescan-start-scan');
    const cancelBtn = $('#purescan-cancel-scan');
    const clearBtn = $('#purescan-clear-results');
    const progressContainer = $('#purescan-progress-container');
    const progressBar = $('#purescan-progress-bar');
    const progressPct = $('#purescan-progress-percent');
    const progressStats = $('#purescan-progress-stats');
    // Polling state
    let pollRequest = null;
    let lastPollTime = 0;
    const MIN_POLL_INTERVAL = 2000;
    const MAX_POLL_INTERVAL = 5000;
    let currentInterval = MIN_POLL_INTERVAL;
    // Utility: format file size
    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    // Utility: simple md5 for unique IDs
    function md5(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash).toString(16);
    }
    // Utility: escape HTML
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    // Utility: trim leading slash
    function ltrim(str, char = '/') {
        return str.startsWith(char) ? str.slice(1) : str;
    }
    // === Start Scan ===
    if (startBtn) {
        startBtn.addEventListener('click', function () {
            this.disabled = true;
            this.textContent = PureScanAjax.i18n.starting || 'Starting...';
            fetch(PureScanAjax.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=purescan_scan_start&nonce=${PureScanAjax.nonce}`
            }).then(() => location.reload());
        });
    }
    // === Cancel Scan ===
    if (cancelBtn) {
        cancelBtn.addEventListener('click', function () {
            if (!confirm(PureScanAjax.i18n.cancel_confirm || 'Cancel the current scan?')) return;
            cancelSmartPoll();
            this.disabled = true;
            this.textContent = PureScanAjax.i18n.cancelling || 'Cancelling...';
            fetch(PureScanAjax.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=purescan_scan_cancel&nonce=${PureScanAjax.nonce}`
            })
            .then(response => response.json())
            .then(res => {
                if (res.success) {
                    setTimeout(() => location.reload(), 1500);
                } else {
                    alert('Cancel failed: ' + (res.data?.message || 'Unknown error.'));
                    this.disabled = false;
                    this.textContent = PureScanAjax.i18n.cancel || 'Cancel Scan';
                }
            })
            .catch(() => {
                alert('Connection error while cancelling.');
                this.disabled = false;
                this.textContent = PureScanAjax.i18n.cancel || 'Cancel Scan';
            });
        });
    }
    // === Clear Results ===
    if (clearBtn) {
        clearBtn.addEventListener('click', function () {
            if (!confirm(PureScanAjax.i18n.clear_confirm || 'Clear all scan results?')) return;
            this.disabled = true;
            fetch(PureScanAjax.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=purescan_scan_clear&nonce=${PureScanAjax.nonce}`
            }).then(() => location.reload());
        });
    }
    // === Smart Progress Polling ===
    function smartPoll() {
        const now = Date.now();
        if (now - lastPollTime < currentInterval) {
            pollRequest = requestAnimationFrame(smartPoll);
            return;
        }
        const folderEl = $('#purescan-current-folder');
        if (folderEl && folderEl.dataset.freezeUntil && now < parseInt(folderEl.dataset.freezeUntil)) {
            pollRequest = requestAnimationFrame(smartPoll);
            return;
        }
        if (document.hidden) {
            currentInterval = Math.min(currentInterval + 1000, MAX_POLL_INTERVAL);
            pollRequest = requestAnimationFrame(smartPoll);
            return;
        }
        lastPollTime = now;
        fetch(PureScanAjax.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `action=purescan_scan_progress&nonce=${PureScanAjax.nonce}`
        })
        .then(r => r.json())
        .then(res => {
            if (!res.success || !res.data) return;
            const s = res.data;
    
            if (s.status === 'completed' || s.status === 'cancelled') {
                if (progressBar) progressBar.style.width = '100%';
                if (progressPct) progressPct.textContent = '100%';
    
                // Final stats with patterns source
                let finalStats = `Scanned: ${s.scanned.toLocaleString()} | Suspicious: ${s.suspicious}`;
                if (s.patterns_source) {
                    finalStats += ` | Using ${s.patterns_source}`;
                }
                if (progressStats) progressStats.innerHTML = finalStats;
    
                if (s.current_folder) {
                    const folderEl = $('#purescan-current-folder');
                    if (folderEl) {
                        const shortEl = folderEl.querySelector('.purescan-current-folder-short');
                        const labelEl = folderEl.querySelector('.purescan-current-folder-label');
                        const iconEl = folderEl.querySelector('.dashicons');
                        if (shortEl) shortEl.textContent = s.current_folder.short || 'Scan Completed';
                        if (labelEl) labelEl.textContent = s.current_folder.label || 'Scan completed successfully';
                        if (iconEl) {
                            iconEl.className = `dashicons dashicons-${s.current_folder.icon || 'yes-alt'}`;
                            iconEl.style.color = s.current_folder.color || '#10b981';
                        }
                    }
                }
                setTimeout(() => location.reload(), 1000);
                cancelSmartPoll();
                return;
            }
    
            // Progress bar
            if (progressBar && progressPct) {
                progressBar.style.width = s.progress + '%';
                progressPct.textContent = s.progress + '%';
            }
    
            // Stats with patterns source
            if (progressStats) {
                let statsText = s.total_files_for_display > 0
                    ? `Scanned: ${s.scanned.toLocaleString()} / ${s.total_files_for_display.toLocaleString()} | Suspicious: ${s.suspicious}`
                    : `Scanned: ${s.scanned.toLocaleString()} | Suspicious: ${s.suspicious}`;
    
                if (s.patterns_source) {
                    statsText += ` | Using ${s.patterns_source}`;
                }
    
                progressStats.innerHTML = statsText;
            }
    
            // Current folder
            if (s.current_folder && typeof s.current_folder === 'object') {
                const folderEl = $('#purescan-current-folder');
                if (folderEl) {
                    const short = s.current_folder.short || 'Scanning files...';
                    const label = s.current_folder.label || short;
                    const icon = s.current_folder.icon || 'admin-home';
                    const color = s.current_folder.color || '#6366f1';
                    const iconEl = folderEl.querySelector('.dashicons');
                    const shortEl = folderEl.querySelector('.purescan-current-folder-short');
                    const labelEl = folderEl.querySelector('.purescan-current-folder-label');
                    if (iconEl && shortEl && labelEl) {
                        iconEl.className = `dashicons dashicons-${icon}`;
                        shortEl.textContent = short;
                        labelEl.textContent = label;
                        iconEl.style.color = color;
                        shortEl.style.color = color;
                        if (folderEl.dataset.last !== short) {
                            folderEl.style.transform = 'translateX(-12px)';
                            folderEl.style.opacity = '0.6';
                            folderEl.offsetHeight;
                            folderEl.style.transition = 'all 0.35s cubic-bezier(0.4, 0, 0.2, 1)';
                            folderEl.style.transform = 'translateX(0)';
                            folderEl.style.opacity = '1';
                            folderEl.dataset.last = short;
                        }
                        const isCounter = /\d+ files discovered|\d+ server files discovered|\d+ total files/.test(label);
                        if (!isCounter) {
                            folderEl.dataset.freezeUntil = Date.now() + 3000;
                        } else {
                            delete folderEl.dataset.freezeUntil;
                        }
                    }
                }
            }
    
            // Step progress
            if (s.current_step !== undefined || s.progress_frozen) {
                const stepsList = document.querySelector('.purescan-scanner-progress');
                if (stepsList) {
                    const steps = Array.from(stepsList.querySelectorAll('.purescan-scan-step'));
                    const current = s.current_step || '';
                    const isFrozen = !!s.progress_frozen;
                    const isCancelled = s.status === 'cancelled';
                    const normalizedCurrentId = 'ps-step-' + current
                        .replace('server', 'server-discovery')
                        .replace('root', 'root-discovery');
                    const currentIndex = steps.findIndex(step => step.id === normalizedCurrentId);
    
                    steps.forEach((li, index) => {
                        li.className = 'purescan-scan-step pending';
    
                        let subtextEl = li.querySelector('.purescan-step-subtext');
                        const key = li.id.replace('ps-step-', '').replace('-discovery', '');
                        const counts = s.step_counts?.[key];
                        const error = s.step_error?.[key];
                        const isNonFile = ['spamvertising', 'password', 'audit', 'database'].includes(key);
    
                        let hasWarning = !!error || (counts && counts.found > 0);
    
                        if (error) {
                            if (!subtextEl) {
                                const div = document.createElement('div');
                                div.className = 'purescan-step-subtext warning';
                                li.querySelector('.purescan-scan-step-title').after(div);
                                subtextEl = div;
                            }
                            subtextEl.textContent = error;
                            subtextEl.className = 'purescan-step-subtext warning';
                        } else {
                            let text = '';
                            let cls = 'success';
    
                            if (counts && counts.checked > 0) {
                                let unit = 'files';
                                if (['spamvertising', 'password', 'audit'].includes(key)) unit = 'entries';
                                if (key === 'database') unit = 'rows';
    
                                if (counts.found > 0) {
                                    text = `${counts.found.toLocaleString()} / ${counts.checked.toLocaleString()} ${unit}`;
                                    cls = 'warning';
                                } else {
                                    text = `${counts.checked.toLocaleString()} ${unit}`;
                                }
                            } else if (isNonFile && li.classList.contains('active')) {
                                let unit = key === 'database' ? 'rows' : 'entries';
                                text = `Scanning ${unit}...`;
                            }
    
                            if (text) {
                                if (!subtextEl) {
                                    const div = document.createElement('div');
                                    div.className = `purescan-step-subtext ${cls}`;
                                    li.querySelector('.purescan-scan-step-title').after(div);
                                    subtextEl = div;
                                }
                                subtextEl.textContent = text;
                                subtextEl.className = `purescan-step-subtext ${cls}`;
                            } else if (subtextEl) {
                                subtextEl.remove();
                            }
                        }
    
                        if (isFrozen) {
                            if (!isCancelled) {
                                li.classList.add(hasWarning ? 'complete-warning' : 'complete-success');
                            } else {
                                if (index < currentIndex) {
                                    li.classList.add(hasWarning ? 'complete-warning' : 'complete-success');
                                } else if (index === currentIndex) {
                                    li.classList.add('complete-success', 'cancelled-current');
                                    if (hasWarning) {
                                        li.classList.remove('complete-success');
                                        li.classList.add('complete-warning');
                                    }
                                }
                            }
                        } else {
                            if (currentIndex !== -1) {
                                if (index < currentIndex) {
                                    li.classList.add(hasWarning ? 'complete-warning' : 'complete-success');
                                } else if (index === currentIndex) {
                                    li.classList.add('active');
                                }
                            }
                        }
                    });
                }
            }
    
            // Live results
            if (Array.isArray(s.findings) && s.findings.length > 0) {
                updateLiveResults(s.findings);
            }
    
            // Adaptive polling
            const lastProgress = parseInt(progressBar?.dataset.lastProgress || '0', 10);
            const diff = s.progress - lastProgress;
            if (progressBar) progressBar.dataset.lastProgress = s.progress;
            currentInterval = diff > 4
                ? Math.max(MIN_POLL_INTERVAL, currentInterval - 400)
                : Math.min(MAX_POLL_INTERVAL, currentInterval + 600);
        })
        .catch(err => console.warn('PureScan polling error:', err))
        .finally(() => {
            pollRequest = requestAnimationFrame(smartPoll);
        });
    }
    function startSmartPoll() {
        if (pollRequest) return;
        if (progressBar) progressBar.dataset.lastProgress = '0';
        pollRequest = requestAnimationFrame(smartPoll);
    }
    function cancelSmartPoll() {
        if (pollRequest) cancelAnimationFrame(pollRequest);
        pollRequest = null;
    }
    // Start polling if scan is running
    if (progressContainer && progressContainer.offsetParent !== null) {
        fetch(PureScanAjax.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `action=purescan_scan_progress&nonce=${PureScanAjax.nonce}`
        })
        .then(r => r.json())
        .then(res => {
            if (res.success && res.data?.status === 'running') {
                startSmartPoll();
            }
        })
        .catch(() => startSmartPoll());
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && progressContainer?.offsetParent !== null && !pollRequest) {
                startSmartPoll();
            } else if (document.hidden) {
                cancelSmartPoll();
            }
        });
    }
    // === Live Results Update ===
    function updateLiveResults(findings) {
        const container = $('#purescan-results-container');
        if (!container) return;
        if (findings.length > 0 && container.style.display !== 'block') {
            container.style.display = 'block';
        }
        const list = $('#purescan-tree-container');
        if (!list) return;
        const badge = container.querySelector('.purescan-count-badge');
        if (badge) badge.textContent = `(${findings.length})`;
        const h3 = container.querySelector('h3');
        if (h3) {
            h3.innerHTML = findings.length === 0
                ? 'No Results Found'
                : `Results Found <span class="purescan-count-badge">(${findings.length})</span>`;
        }
        const existingIds = new Set(Array.from(list.querySelectorAll('.purescan-finding')).map(el => el.id));
        findings.forEach(f => {
            const id = 'finding-' + md5(f.path);
            if (existingIds.has(id)) return;
            const element = createFindingElement(f);
            list.appendChild(element);
            existingIds.add(id);
        });
    }
    // === Create Simplified Live Finding Element ===
    function createFindingElement(f) {
        const div = document.createElement('div');
        div.id = 'finding-' + md5(f.path);
        div.dataset.path = f.path;
        const path = ltrim(f.path, '/');
        const is_external = !!f.is_external;
        const external_badge = is_external ? ' <span class="purescan-external-badge">External Config</span>' : '';
        div.className = 'purescan-finding purescan-finding-collapsible purescan-infected-border';
        div.innerHTML = `
            <div class="purescan-finding-summary" role="button" tabindex="0">
                <div class="purescan-finding-header">
                    <code class="purescan-file-name-full">
                        ${escapeHtml(path)}${external_badge}
                    </code>
                    <span class="purescan-finding-meta">
                        ${formatBytes(f.size)} • ${escapeHtml(f.mtime)}
                    </span>
                </div>
                <div class="purescan-finding-status">
                    <span class="purescan-status-badge purescan-infected">Suspicious</span>
                    <button type="button" class="ps-btn ps-btn-toggle">
                        <span class="text">Details</span>
                        <span class="dashicons dashicons-arrow-down-alt2"></span>
                    </button>
                </div>
            </div>
            <div class="purescan-finding-content">
                <div style="padding: 10px 20px; border-radius: 12px; margin-top: 20px; background: #fffbeb; border: 1px dashed #fcd34d; color: #92400e;">
                    <p style="font-size: 16px; margin: 0 0 8px 0; font-weight: 600;">
                        Scan in progress
                    </p>
                    <p style="font-size: 15px; margin: 0;">
                        To view full details, please cancel the scan or wait until the scan is complete.
                    </p>
                </div>
            </div>
        `;
        return div;
    }

    // === Analyze with AI (works in final results, Quarantine tab) ===
    document.addEventListener('click', e => {
        if (!e.target.matches('.ps-btn-analyze')) return;
        const btn = e.target;
        const path = btn.dataset.path?.trim();
        if (!path) return;
        const finding = btn.closest('.purescan-finding-collapsible');
        if (!finding) return;
        const content = finding.querySelector('.purescan-finding-content');
        // Block during active deep scan
        const isDeepScanRunning = progressContainer && progressContainer.offsetParent !== null;
        if (isDeepScanRunning) {
            let msg = btn.parentNode.querySelector('.purescan-inline-ai-msg');
            if (!msg) {
                msg = document.createElement('span');
                msg.className = 'purescan-inline-ai-msg';
                msg.textContent = 'Deep scan in progress — please wait or cancel first';
                msg.style.cssText = 'margin-left:12px;padding:4px 10px;background:#fee2e2;color:#991b1b;border:1px solid #fecaca;border-radius:4px;font-size:13px;';
                btn.parentNode.appendChild(msg);
                setTimeout(() => msg.remove(), 5000);
            }
            return;
        }
        btn.disabled = true;
        const originalText = btn.textContent.trim();
        btn.textContent = 'Analyzing...';
        // Clear temporary messages
        btn.parentNode.querySelectorAll('.purescan-inline-ai-msg').forEach(el => el.remove());
        content.querySelectorAll('.purescan-ai-notice-warning, .purescan-ai-details').forEach(el => el.remove());
        fetch(PureScanAjax.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                action: 'purescan_force_ai_analysis',
                nonce: PureScanAjax.nonce,
                path: path,
                prompt: ''
            })
        })
        .then(r => r.ok ? r.json() : Promise.reject('Network error'))
        .then(data => {
            if (!data.success) {
                const err = data.data?.message || 'AI analysis failed.';
                const box = document.createElement('div');
                box.className = 'purescan-ai-notice purescan-ai-notice-warning';
                box.innerHTML = `<strong>AI Analysis Failed</strong><br>${escapeHtml(err)}`;
                content.insertBefore(box, content.firstChild);
                btn.textContent = originalText;
                return;
            }
            if (data.data?.html) {
                const temp = document.createElement('div');
                temp.innerHTML = data.data.html;
                const newEl = temp.querySelector('.purescan-ai-details') || temp.querySelector('.purescan-ai-notice');
                if (newEl) content.insertBefore(newEl, content.firstChild);
            }
            if (data.data?.new_status) {
                const statusLower = data.data.new_status.toLowerCase();
                const badge = finding.querySelector('.purescan-status-badge');
                if (badge) {
                    badge.className = `purescan-status-badge purescan-${statusLower}`;
                    badge.textContent = data.data.new_status;
                }
                finding.className = finding.className.replace(/purescan-\w+-border/g, `purescan-${statusLower}-border`);
            }
            btn.textContent = 'Re-Analyze with AI';
        })
        .catch(() => {
            const box = document.createElement('div');
            box.className = 'purescan-ai-notice purescan-ai-notice-warning';
            box.innerHTML = '<strong>Connection Failed</strong><br>Could not reach AI server.';
            content.insertBefore(box, content.firstChild);
            btn.textContent = originalText;
        })
        .finally(() => {
            btn.disabled = false;
        });
    });
    // === Quarantine / Restore / Ignore Actions ===
    document.addEventListener('click', function (e) {
        if (e.target.matches('.ps-btn-quarantine')) {
            const btn = e.target;
            const path = btn.dataset.path?.trim();
            if (!path) return;
            if (!confirm(`Neutralize this file?\n\nFile: ${path}\n\nAll malicious behavior will be instantly blocked with zero downtime and full site functionality preserved.`)) return;
            quarantineFile(path, btn);
        }
        if (e.target.matches('.ps-btn-restore')) {
            const btn = e.target;
            const path = btn.dataset.path?.trim();
            if (!path) return;
            if (!confirm('Restore this file?\n\nThis will remove the neutralization guard and re-enable the original code.')) return;
            btn.disabled = true;
            btn.textContent = 'Restoring...';
            fetch(PureScanAjax.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    action: 'purescan_restore_file',
                    nonce: PureScanAjax.nonce,
                    path: path
                })
            })
            .then(r => r.json())
            .then(res => {
                if (res.success) {
                    alert('File successfully restored — neutralization guard removed.');
                    location.reload();
                } else {
                    alert(res.data?.message || 'Restore failed.');
                    btn.disabled = false;
                    btn.textContent = 'Remove from Quarantine';
                }
            })
            .catch(() => {
                alert('Connection error.');
                btn.disabled = false;
                btn.textContent = 'Remove from Quarantine';
            });
        }
        if (e.target.matches('.ps-btn-ignore')) {
            const btn = e.target;
            const path = btn.dataset.path?.trim();
            if (!path) return;
            if (!confirm('Ignore this file?\n\nIt will no longer appear in scan results.')) return;
            btn.disabled = true;
            btn.textContent = 'Ignoring...';
            fetch(PureScanAjax.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=purescan_ignore_file&nonce=${PureScanAjax.nonce}&path=${encodeURIComponent(path)}`
            })
            .then(r => r.json())
            .then(res => {
                if (res.success) {
                    const finding = btn.closest('.purescan-finding');
                    if (finding) {
                        finding.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
                        finding.style.opacity = '0';
                        finding.style.transform = 'translateY(-20px)';
                        setTimeout(() => {
                            finding.remove();
                            setTimeout(() => location.reload(), 800);
                        }, 600);
                    } else {
                        location.reload();
                    }
                }
            })
            .catch(() => {
                alert('Connection error.');
                btn.disabled = false;
                btn.textContent = 'Ignore File';
            });
        }
    });
    function quarantineFile(path, btn) {
        btn.disabled = true;
        btn.textContent = 'Neutralizing...';
        fetch(PureScanAjax.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                action: 'purescan_quarantine_file',
                nonce: PureScanAjax.nonce,
                path: path
            })
        })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                let message = 'File successfully neutralized.\n\nAll malicious behavior blocked — site remains fully functional.';
                if (res.data?.backup_info) message += '\n\n' + res.data.backup_info;
                alert(message);
                const finding = btn.closest('.purescan-finding');
                if (finding) {
                    finding.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
                    finding.style.opacity = '0';
                    finding.style.transform = 'translateY(-20px)';
                    setTimeout(() => location.reload(), 600);
                } else {
                    location.reload();
                }
            } else {
                alert(res.data?.message || 'Neutralization failed.');
                btn.disabled = false;
                btn.textContent = 'Disable File (Safe Quarantine)';
            }
        })
        .catch(() => {
            alert('Connection error.');
            btn.disabled = false;
            btn.textContent = 'Disable File (Safe Quarantine)';
        });
    }
    // === Collapsible Details Toggle ===
    document.addEventListener('click', e => {
        if (e.target.closest('.ps-btn-toggle')) {
            const button = e.target.closest('.ps-btn-toggle');
            const finding = button.closest('.purescan-finding-collapsible');
            finding.classList.toggle('open');
        }
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') {
            const button = e.target.closest('.ps-btn-toggle');
            if (button) {
                e.preventDefault();
                button.click();
            }
        }
    });
});
/**
 * PureScan Live Search Tab JavaScript
 * Real-time file search + AI analysis button exactly like scan.js
 *
 * @package PureScan
 */
document.addEventListener('DOMContentLoaded', function () {
    const $ = document.querySelector.bind(document);
    const $$ = document.querySelectorAll.bind(document);
    const searchInput = $('#purescan-live-search');
    const spinner = $('#purescan-search-spinner');
    const resultsContainer = $('#purescan-search-results');
    const resultsList = $('#purescan-results-list');
    const resultsCount = $('#purescan-results-count');
    const truncatedWarning = $('#purescan-truncated-warning');
    const noResults = $('#purescan-no-results');
    const minLengthHint = $('#purescan-min-length');
    let debounceTimer = null;
    let currentRequest = null;
    // =============================================
    // Live search
    // =============================================
    searchInput?.addEventListener('input', function () {
        const query = this.value.trim();
        resultsContainer.style.display = 'none';
        noResults.style.display = 'none';
        minLengthHint.style.display = 'none';
        truncatedWarning.style.display = 'none';
        spinner.style.display = 'none';
        if (resultsList) resultsList.innerHTML = '';
        if (query.length < 2) {
            minLengthHint.style.display = 'block';
            return;
        }
        if (currentRequest) currentRequest.abort();
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            spinner.style.display = 'inline-block';
            currentRequest = new AbortController();
            fetch(PureScanAjax.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=purescan_search_live&nonce=${PureScanAjax.nonce}&query=${encodeURIComponent(query)}`,
                signal: currentRequest.signal
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) return;
                const { results, truncated } = data.data;
                resultsCount.textContent = results.length;
                truncatedWarning.style.display = truncated ? 'inline' : 'none';
                if (results.length === 0) {
                    noResults.style.display = 'block';
                    return;
                }
                resultsList.innerHTML = '';
                results.forEach(file => resultsList.appendChild(createResultItem(file)));
                resultsContainer.style.display = 'block';
            })
            .catch(err => {
                if (err.name !== 'AbortError') {
                    noResults.textContent = PureScanAjax.i18n.search_failed || 'Search failed.';
                    noResults.style.display = 'block';
                }
            })
            .finally(() => {
                spinner.style.display = 'none';
                currentRequest = null;
            });
        }, 300);
    });
    // =============================================
    // Create result item
    // =============================================
    function createResultItem(file) {
        const item = document.createElement('div');
        item.className = 'purescan-search-item';
        item.dataset.path = file.path;
        const resultId = 'result-' + btoa(file.path).substring(0, 12);
        item.innerHTML = `
            <div class="purescan-result-header">
                <div class="purescan-file-info">
                    <code class="purescan-file-path">${escapeHtml(file.path)}</code>
                    <span class="purescan-file-meta">${formatBytes(file.size)} • ${file.mtime}</span>
                </div>
                <button type="button" class="ps-btn ps-btn-scan-file" data-path="${escapeHtml(file.path)}">
                    ${PureScanAjax.i18n.scan || 'Scan'}
                </button>
            </div>
            <div id="${resultId}" class="purescan-scan-result" style="display:none;" data-loaded="false"></div>
        `;
        const scanBtn = item.querySelector('.ps-btn-scan-file');
        const resultBox = item.querySelector(`#${resultId}`);
        scanBtn.addEventListener('click', function () {
            if (resultBox.dataset.loaded === 'true') {
                resultBox.style.display = resultBox.style.display === 'block' ? 'none' : 'block';
                return;
            }
            this.disabled = true;
            this.textContent = PureScanAjax.i18n.scanning || 'Scanning...';
            fetch(PureScanAjax.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=purescan_search_scan_file&nonce=${PureScanAjax.nonce}&path=${encodeURIComponent(file.path)}`
            })
            .then(r => r.json())
            .then(response => {
                if (!response.success) {
                    resultBox.innerHTML = `<p class="purescan-scan-error">${response.data || 'Scan failed'}</p`;
                    resultBox.style.display = 'block';
                    return;
                }
                const finding = response.data.findings?.[0] || null;
                const isClean = response.data.clean === true;
                const patterns_source = response.data.patterns_source || 'Local Patterns';

                resultBox.innerHTML = renderSingleResult(isClean, finding, file, patterns_source);
                resultBox.dataset.loaded = 'true';
                resultBox.style.display = 'block';
                // Details toggle
                resultBox.querySelectorAll('.ps-btn-toggle').forEach(btn => {
                    btn.addEventListener('click', () => {
                        item.classList.toggle('open');
                        const content = resultBox.querySelector('.purescan-finding-content');
                        if (content) content.style.display = content.style.display === 'block' ? 'none' : 'block';
                    });
                });
            })
            .catch(() => {
                resultBox.innerHTML = `<p class="purescan-scan-error">Network error</p>`;
                resultBox.style.display = 'block';
            })
            .finally(() => {
                this.disabled = false;
                this.textContent = PureScanAjax.i18n.scan || 'Scan';
            });
        });
        return item;
    }
    // =============================================
    // Render single result
    // =============================================
    function renderSingleResult(isClean, finding, fileInfo, patterns_source = 'Local Patterns') {
        const path = fileInfo.path;
        const size = fileInfo.size;
        const viewFullUrl = PureScanAjax.purescan_url + '&action=view_full&file=' + encodeURIComponent(path);

        // Line for displaying the patterns source (exactly like Deep Scan)
        const patternsLine = patterns_source ? 
            `<div class="purescan-scan-stats" style="margin: 16px 0; padding: 8px 12px; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; font-size: 14px; color: #475569;">
                Scanned using ${escapeHtml(patterns_source)}
             </div>` : '';
             
        // Clean
        if (isClean) {
            return `
                <div class="purescan-finding purescan-finding-collapsible purescan-clean-border" style="margin-top:12px;">
                    <div class="purescan-finding-summary" role="button" tabindex="0">
                        <div class="purescan-finding-status">
                            <span class="purescan-status-badge purescan-clean">Clean</span>
                            <button type="button" class="ps-btn ps-btn-toggle">
                                <span class="text">Details</span>
                                <span class="dashicons dashicons-arrow-down-alt2"></span>
                            </button>
                        </div>
                    </div>
 
                    <div class="purescan-finding-content" style="display:none;">
                        <div class="purescan-clean-details" style="margin-bottom:16px;">
                            No malicious code detected.
                        </div>

                        ${patternsLine}

                        <div class="purescan-code-actions">
                            <button type="button"
                                    class="ps-btn ps-btn-view-full"
                                    onclick="window.open('${viewFullUrl}', '_blank')">
                                View Full File ${size > 1048576 ? `(${formatBytes(size)})` : ''}
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }

        // Malicious or suspicious
        let has_ai = false;
        let ai_status = 'malicious';
        let ai_explanation = '';
        let ai_notice = '';
        if (finding && finding.snippets && finding.snippets.length > 0) {
            for (const snippet of finding.snippets) {
                if (snippet.ai_status && snippet.ai_status !== 'skipped') {
                    has_ai = true;
                    if (snippet.ai_status === 'malicious') ai_status = 'malicious';
                    else if (snippet.ai_status === 'suspicious' && ai_status !== 'malicious') ai_status = 'suspicious';
                    else if (snippet.ai_status === 'clean' && ai_status !== 'malicious' && ai_status !== 'suspicious') ai_status = 'clean';
                    if (snippet.ai_debug?.explanation) ai_explanation = snippet.ai_debug.explanation;
                    else if (snippet.ai_analysis) ai_explanation = snippet.ai_analysis;
                    ai_explanation = ai_explanation.replace(/^(Details|Explanation|Analysis|Reasoning|Summary)\s*[:：]\s*/i, '').trim();
                }
            }
            let real_ai_error = null;
            if (finding?.snippets?.[0]?.ai_debug?.error) {
                real_ai_error = finding.snippets[0].ai_debug.error;
            } else if (finding?.snippets?.[0]?.[0]?.ai_debug?.error) {
                real_ai_error = finding.snippets[0][0].ai_debug.error;
            }
         
            if (!finding.ai_enabled_in_settings) {
                ai_notice = 'AI Deep Scan is currently disabled in plugin settings.';
            } else if (real_ai_error) {
                ai_notice = real_ai_error;
            } else if (!has_ai || !ai_explanation) {
                ai_notice = 'AI analysis was skipped or incomplete for this file.';
            }
        }
        const badgeClass = ai_status === 'clean' ? 'purescan-clean' :
                          ai_status === 'suspicious' ? 'purescan-suspicious' : 'purescan-infected';
        const badgeText = ai_status.charAt(0).toUpperCase() + ai_status.slice(1);
        const borderClass = badgeClass + '-border';
        const needAnalyzeBtn = !has_ai || !ai_explanation ||
                              finding?.snippets?.some(s => s.ai_debug?.retry_possible || s.ai_debug?.error);
        const analyzeBtn = needAnalyzeBtn ? `
            <button type="button"
                    class="ps-btn ps-btn-analyze"
                    data-path="${escapeHtml(path)}"
                    data-force="1">
                ${!finding?.ai_enabled_in_settings || !has_ai ? 'Analyze with AI' : 'Re-Analyze with AI'}
            </button>` : '';
        let detailsContent = '';
        if (ai_notice) {
            detailsContent += `
                <div class="purescan-ai-notice purescan-ai-notice-warning">
                    <strong>Warning: AI Analysis Unavailable</strong><br>
                    ${escapeHtml(ai_notice)}
                </div>`;
        }
        if (has_ai && ai_explanation) {
            const color = ai_status === 'malicious' ? '#ef4444' :
                         ai_status === 'clean' ? '#10b981' : '#f59e0b';
            const aiClass = ai_status === 'malicious' ? 'purescan-ai-malicious' :
                           ai_status === 'clean' ? 'purescan-ai-clean' : '';
            detailsContent += `
                <div class="purescan-ai-details ${aiClass}" style="border-left-color:${color}; margin-bottom:16px;">
                    ${escapeHtml(ai_explanation).replace(/\n/g, '<br>')}
                </div>`;
        }

        // Add patterns source line after AI details
        detailsContent += patternsLine;

        return `
            <div class="purescan-finding purescan-finding-collapsible ${borderClass}" style="margin-top:12px;">
                <div class="purescan-finding-summary" role="button" tabindex="0">
                    <div class="purescan-finding-status">
                        <span class="purescan-status-badge ${badgeClass}">${badgeText}</span>
                        <button type="button" class="ps-btn ps-btn-toggle">
                            <span class="text">Details</span>
                            <span class="dashicons dashicons-arrow-down-alt2"></span>
                        </button>
                    </div>
                </div>
 
                <div class="purescan-finding-content" style="display:none;">
                    ${detailsContent}
 
                    <div class="purescan-code-actions" style="margin-top:16px;">
                        <button type="button"
                                class="ps-btn ps-btn-view-full"
                                onclick="window.open('${viewFullUrl}', '_blank')">
                            View Full File ${size > 1048576 ? `(${formatBytes(size)})` : ''}
                        </button>
                        ${analyzeBtn}
                    </div>
                </div>
            </div>
        `;
    }
    // =============================================
    // Inline AI analysis
    // =============================================
    document.addEventListener('click', e => {
        if (e.target.matches('.ps-btn-analyze') && e.detail?.handledByScanJs) return;
        if (!e.target.matches('.ps-btn-analyze')) return;
        const btn = e.target;
        const path = btn.dataset.path?.trim();
        if (!path) return;
        const findingDiv = btn.closest('.purescan-finding-collapsible');
        if (!findingDiv) return;
        btn.disabled = true;
        const originalText = btn.textContent.trim();
        btn.textContent = 'Analyzing...';
        const payload = new URLSearchParams();
        payload.append('action', 'purescan_force_ai_analysis');
        payload.append('nonce', PureScanAjax.nonce);
        payload.append('path', path);
        payload.append('prompt', '');
        fetch(PureScanAjax.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: payload
        })
        .then(r => r.ok ? r.json() : Promise.reject())
        .then(data => {
            if (data.success) {
                e.detail = e.detail || {};
                e.detail.handledByScanJs = true;
                return;
            }
            btn.textContent = originalText;
        })
        .catch(() => {
            btn.textContent = originalText;
        })
        .finally(() => {
            setTimeout(() => btn.disabled = false, 1500);
        });
    });
    // =============================================
    // Utilities
    // =============================================
    function formatBytes(bytes) {
        if (!bytes) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});
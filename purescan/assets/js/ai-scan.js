/**
 * PureScan AI Manual Code Scan
 */
document.addEventListener('DOMContentLoaded', function () {
    const aiBtn = document.getElementById('purescan-ai-scan-btn');
    const nonAiBtn = document.getElementById('purescan-non-ai-scan-btn');
    const spinner = document.getElementById('purescan-ai-spinner');
    const clearBtn = document.getElementById('purescan-ai-clear-btn');
    const input = document.getElementById('purescan-ai-code-input');
    const status = document.getElementById('purescan-ai-status');
    const result = document.getElementById('purescan-ai-result');
    const nonAiResult = document.getElementById('purescan-non-ai-result');
    const nonAiContent = document.getElementById('purescan-non-ai-content');
    const counter = document.getElementById('purescan-char-count');
    const counterWrapper = document.getElementById('purescan-char-counter');

    const MAX_CHARS_AI = 8000;
    const WARNING_AT = 7200;

    if (!aiBtn || !nonAiBtn || !input || !status || !result || !nonAiResult || !nonAiContent || !counter || !counterWrapper || !clearBtn || !spinner) return;

    function updateUI() {
        const length = input.value.length;
        counter.textContent = length;
        counterWrapper.classList.remove('warning', 'error', 'large');
        status.textContent = '';
        status.style.color = '';

        if (length === 0) {
            aiBtn.disabled = true;
            nonAiBtn.disabled = true;
        } else {
            if (length > MAX_CHARS_AI) {
                counterWrapper.classList.add('error');
                aiBtn.disabled = true;
                nonAiBtn.disabled = false;
                status.innerHTML = `<span style="color:#dc2626;">AI scan is limited to ${MAX_CHARS_AI} characters.<br>Use "Scan without AI" for larger code.</span>`;
            } else if (length === MAX_CHARS_AI) {
                counterWrapper.classList.add('error');
                aiBtn.disabled = true;
                nonAiBtn.disabled = false;
                status.textContent = `AI scan limit reached (${MAX_CHARS_AI} characters).`;
            } else if (length >= WARNING_AT) {
                counterWrapper.classList.add('warning');
                aiBtn.disabled = false;
                nonAiBtn.disabled = false;
            } else {
                aiBtn.disabled = false;
                nonAiBtn.disabled = false;
            }

            if (length > 50000) {
                counterWrapper.classList.add('large');
            }
        }
    }

    input.addEventListener('input', updateUI);
    input.addEventListener('paste', updateUI);
    input.addEventListener('keyup', updateUI);
    input.addEventListener('cut', () => setTimeout(updateUI, 10));
    input.addEventListener('drop', updateUI);
    updateUI();

    function showClearButton() {
        clearBtn.style.display = 'inline-block';
    }

    clearBtn.addEventListener('click', function () {
        if (confirm('Clear code and analysis results?')) {
            input.value = '';
            result.style.display = 'none';
            result.innerHTML = '';
            nonAiResult.style.display = 'none';
            nonAiContent.innerHTML = '';
            clearBtn.style.display = 'none';
            spinner.style.display = 'none';
            status.textContent = '';
            updateUI();
        }
    });

    // ==================== AI Scan Button ====================
    aiBtn.addEventListener('click', function () {
        const code = input.value.trim();

        status.innerHTML = '';
        if (!code) {
            status.textContent = 'Please enter some code to scan.';
            return;
        }

        if (code.length > MAX_CHARS_AI) {
            status.innerHTML = `<span style="color:#dc2626;">Code exceeds AI limit (${MAX_CHARS_AI} characters).<br>Use "Scan without AI" instead.</span>`;
            return;
        }

        aiBtn.disabled = true;
        aiBtn.textContent = 'Analyzing...';
        spinner.style.display = 'inline-block';
        result.style.display = 'none';

        fetch(PureScanAjax.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                action: 'purescan_ai_scan_code',
                nonce: aiBtn.dataset.nonce,
                code: code
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const res = data.data;
                let icon = '';
                let resultClass = 'clean';
                if (res.is_malicious === 'malicious') {
                    icon = '<span class="dashicons dashicons-warning purescan-status-icon malicious" title="Malicious"></span>';
                    resultClass = 'malicious';
                } else if (res.is_malicious === 'suspicious') {
                    icon = '<span class="dashicons dashicons-editor-help purescan-status-icon suspicious" title="Possibly Malicious"></span>';
                    resultClass = 'suspicious';
                } else {
                    icon = '<span class="dashicons dashicons-yes-alt purescan-status-icon clean" title="Clean"></span>';
                }
                const summary = (res.summary || '').replace(/^Type:[^\n]*\n?/i, '').trim();
                const analysis = res.analysis || 'No detailed analysis returned.';
                const pre = document.createElement('pre');
                pre.textContent = analysis;
                Object.assign(pre.style, {
                    whiteSpace: 'pre-wrap',
                    background: '#f4f4f4',
                    padding: '12px',
                    borderRadius: '4px',
                    marginTop: '8px',
                    fontSize: '13px',
                    overflowX: 'auto'
                });
                result.innerHTML = `
                    <div class="status" style="margin-bottom:10px;">
                        <strong>Status:</strong> ${res.is_malicious.toUpperCase()} ${icon}
                    </div>
                    <p>${escapeHtml(summary)}</p>
                    <details open style="margin-top:10px;">
                        <summary>Full AI Analysis</summary>
                    </details>
                `;
                result.querySelector('details').appendChild(pre);
                result.className = `purescan-ai-result ${resultClass}`;
                result.style.display = 'block';
                showClearButton();
            } else {
                let errorMessage = typeof data.data === 'string' ? data.data : 'Analysis failed.';
                status.innerHTML = `<span style="color:#dc2626;">${errorMessage}</span>`;
            }
        })
        .catch(networkError => {
        })
        .finally(() => {
            aiBtn.disabled = false;
            aiBtn.textContent = 'Scan with AI';
            spinner.style.display = 'none';
            updateUI();
        });
    });

    // ==================== Non-AI Scan Button ====================
    nonAiBtn.addEventListener('click', function () {
        const code = input.value.trim();

        status.innerHTML = '';
        if (!code) {
            status.textContent = 'Please enter some code to scan.';
            return;
        }

        nonAiBtn.disabled = true;
        nonAiBtn.textContent = 'Analyzing...';
        spinner.style.display = 'inline-block';
        nonAiResult.style.display = 'none';
        nonAiContent.innerHTML = '';

        fetch(PureScanAjax.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                action: 'purescan_non_ai_scan_code',
                nonce: nonAiBtn.dataset.nonce,
                code: code
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                nonAiContent.innerHTML = data.data.html;
                nonAiResult.style.display = 'block';
                showClearButton();
            } else {
                status.innerHTML = `<span style="color:#dc2626;">${escapeHtml(data.data.message || 'Analysis failed.')}</span>`;
            }
        })
        .catch(err => {
            status.innerHTML = `<span style="color:#dc2626;">Network error. Please try again.</span>`;
            console.error(err);
        })
        .finally(() => {
            nonAiBtn.disabled = false;
            nonAiBtn.textContent = 'Scan without AI';
            spinner.style.display = 'none';
        });
    });

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});
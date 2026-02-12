/**
 * PureScan Settings Tab JavaScript – Ultra Professional OpenRouter Integration
 *
 * Key Features:
 * - Fully independent "Test Connection" for Manual and External modes
 * - Test success displays the EXACT response received from the AI (distinct prompts per mode)
 * - Manual API key and model are fully preserved in DB when switching to External
 * - Key/model only cleared when user clicks "Remove Manual API Key"
 * - Dynamic Manual active box created/updated after successful Manual test
 * - Dynamic External active box created/updated after successful External test (no page reload)
 * - Save prevented in Manual mode until successful test
 * - All messages and comments in English
 * - Professional, reliable UX
 *
 * @package PureScan
 */
document.addEventListener('DOMContentLoaded', function () {
    const $ = document.querySelector.bind(document);
    const $$ = document.querySelectorAll.bind(document);
    // Main elements
    const form = $('#purescan-settings-form');
    const saveBtn = $('#purescan-save-settings');
    const testBtn = $('#purescan-test-openrouter');
    const settingsStatusEl = $('#purescan-settings-status');
    const openRouterStatusEl = $('#purescan-openrouter-status');
    // OpenRouter elements
    const apiKeyInput = $('#openrouter_api_key');
    const modelSelect = $('#openrouter_model');
    const modelPriceInfo = $('#model-price-info');
    const manualWrapper = $('#manual-api-wrapper');
    if (!form) return;
    let modelsLoaded = false;
    let manualTested = false;
    // If page loads in Manual mode with existing connected state → previous test was successful
    const initialSource = document.querySelector('input[name="api_source_radio"]:checked')?.value || 'external';
    if (initialSource === 'manual' && document.getElementById('manual-key-info')) {
        manualTested = true;
    }
    // Helper: Get current selected source
    function getCurrentSource() {
        return document.querySelector('input[name="api_source_radio"]:checked')?.value || 'external';
    }
    // Update visibility of Manual fields and connection boxes
    function updateApiFieldsVisibility() {
        const source = getCurrentSource();
        if (source === 'manual') {
            manualWrapper.style.display = 'block';
            if (apiKeyInput.value.trim() && !modelsLoaded) {
                loadOpenRouterModels(apiKeyInput.value.trim());
            }
        } else {
            // Key & model preserved in DB and input – only hidden
            manualWrapper.style.display = 'none';
        }
        updateConnectionBoxesVisibility();
        updateTestButtonState();
    }
    // Show only the relevant active connection box
    function updateConnectionBoxesVisibility() {
        const source = getCurrentSource();
        const externalBox = $('#external-key-info');
        const manualBox = $('#manual-key-info');
        if (externalBox) externalBox.style.display = source === 'external' ? 'block' : 'none';
        if (manualBox) manualBox.style.display = source === 'manual' ? 'block' : 'none';
    }
    // Enable/disable Test button
    function updateTestButtonState() {
        const source = getCurrentSource();
        if (source === 'external') {
            testBtn.disabled = false;
        } else {
            testBtn.disabled = !(apiKeyInput.value.trim() && modelSelect.value);
        }
    }
    // Load models from OpenRouter
    async function loadOpenRouterModels(apiKey) {
        if (modelsLoaded) {
            enableModelSelect();
            updateTestButtonState();
            return;
        }
        modelSelect.innerHTML = '<option>Loading models...</option>';
        modelSelect.disabled = true;
        modelPriceInfo.textContent = '';
        try {
            const response = await fetch('https://openrouter.ai/api/v1/models', {
                headers: { 'Authorization': `Bearer ${apiKey}` }
            });
            if (!response.ok) throw new Error('Invalid response');
            const data = await response.json();
            const models = (data.data || []).sort((a, b) => {
                const aFree = a.id.includes(':free') || (a.pricing?.prompt === '0');
                const bFree = b.id.includes(':free') || (b.pricing?.prompt === '0');
                if (aFree && !bFree) return -1;
                if (!aFree && bFree) return 1;
                return a.id.localeCompare(b.id);
            });
            modelSelect.innerHTML = '<option value="">Select a model (required)</option>';
            const allModels = [];
            models.forEach(m => {
                const opt = document.createElement('option');
                opt.value = m.id;
                const isFree = m.id.includes(':free') || (m.pricing?.prompt === '0');
                opt.textContent = `${m.id} ${isFree ? '(Free)' : '(Paid)'}`;
                modelSelect.appendChild(opt);
                allModels.push(m);
            });
            // Restore saved model from hidden input (preserved in DB)
            const savedModelInput = form.querySelector('input[name="settings[openrouter_model]"]');
            const savedModel = savedModelInput?.value?.trim();
            if (savedModel && models.some(m => m.id === savedModel)) {
                modelSelect.value = savedModel;
            }
            modelsLoaded = true;
            enableModelSelect();
            updateTestButtonState();
            showModelPrice(allModels);
        } catch (err) {
            modelSelect.innerHTML = '<option value="">Failed to load models – Check your key</option>';
            modelPriceInfo.textContent = 'Error: Invalid API key or server issue.';
            modelSelect.disabled = true;
        }
    }
    function enableModelSelect() {
        modelSelect.disabled = false;
    }
    function showModelPrice(allModels) {
        const selectedId = modelSelect.value;
        const selected = allModels.find(m => m.id === selectedId);
        if (selected) {
            const p = selected.pricing;
            const free = selected.id.includes(':free') || p?.prompt === '0';
            modelPriceInfo.textContent = free
                ? 'This model is completely free.'
                : `Input: $${p?.prompt || 'N/A'}/1M tokens • Output: $${p?.completion || 'N/A'}/1M tokens`;
        } else {
            modelPriceInfo.textContent = '';
        }
    }
    // Test Connection
    testBtn.addEventListener('click', function () {
        const source = getCurrentSource();
        const key = source === 'manual' ? apiKeyInput.value.trim() : '';
        const model = source === 'manual' ? modelSelect.value : '';
        if (source === 'manual' && (!key || !model)) {
            openRouterStatusEl.textContent = 'Please enter API key and select a model.';
            openRouterStatusEl.className = 'purescan-status-error';
            return;
        }
        testBtn.disabled = true;
        openRouterStatusEl.textContent = 'Testing connection...';
        openRouterStatusEl.className = 'purescan-status-saving';
        const fd = new FormData();
        fd.append('action', 'purescan_test_openrouter');
        fd.append('nonce', PureScanAjax.nonce);
        fd.append('source', source);
        if (source === 'manual') {
            fd.append('api_key', key);
            fd.append('model', model);
        }
        fetch(PureScanAjax.url, {
            method: 'POST',
            body: new URLSearchParams(fd)
        })
        .then(r => r.json())
        .then(res => {
            if (res.success && res.data.ai_response) {
                const aiResponse = res.data.ai_response.trim();
                let message = `<strong style="color:#10b981;">Connection Successful!</strong><br><br>`;
                message += `AI Response: "<em>${escapeHtml(aiResponse)}</em>"<br><br>`;
                if (source === 'manual') {
                    message += `Your manual API key and selected model are working perfectly.`;
                    manualTested = true;
                    createOrUpdateManualBox(key, model);
                } else {
                    let activeModel = res.data.model || 'Unknown';
                    const cleanModel = activeModel.replace(':free', '');
                    message += `Server fallback key is active (Model: <code>${escapeHtml(cleanModel)}</code>).`;
                    createOrUpdateExternalBox(cleanModel);
                }
                openRouterStatusEl.innerHTML = message;
                openRouterStatusEl.className = 'purescan-status-success';
            } else {
                openRouterStatusEl.innerHTML = res.data || 'Connection test failed.';
                openRouterStatusEl.className = 'purescan-status-error';
                manualTested = false;
            }
        })
        .catch(() => {
            openRouterStatusEl.textContent = 'Network error.';
            openRouterStatusEl.className = 'purescan-status-error';
            manualTested = false;
        })
        .finally(() => {
            testBtn.disabled = false;
            setTimeout(() => {
                openRouterStatusEl.textContent = '';
                openRouterStatusEl.className = '';
            }, 12000);
        });
    });
    // Create or update dynamic Manual active key box
    function createOrUpdateManualBox(key, modelName) {
        let manualBox = $('#manual-key-info');
        if (!manualBox) {
            manualBox = document.createElement('div');
            manualBox.id = 'manual-key-info';
            manualBox.className = 'purescan-field';
            manualBox.style.marginTop = '18px';
            manualBox.style.padding = '18px';
            manualBox.style.background = '#f0f9ff';
            manualBox.style.border = '1px solid #3b82f6';
            manualBox.style.borderRadius = '12px';
            testBtn.closest('.purescan-field').insertAdjacentElement('afterend', manualBox);
        }
        const keyPreview = key.substring(0, 34) + '...';
        manualBox.innerHTML = `
            <p style="margin:0; font-size:15px; line-height:1.8; color:#1e40af;">
                <strong style="color:#2563eb; font-size:16px;">Active Manual API Key</strong>
                <br><strong>Model:</strong> <code>${escapeHtml(modelName)}</code>
                <br><strong>Key Preview:</strong> <code>${escapeHtml(keyPreview)}</code>
                <br><br>
                <small style="color:#2563eb; opacity:0.95; font-weight:500;">
                    Your own OpenRouter key is active and working perfectly.
                </small>
                <br><br>
                <button type="button" class="ps-btn ps-btn-danger purescan-remove-manual-key-btn" style="font-size:14px; padding:10px 18px;">
                    Remove Manual API Key
                </button>
            </p>
        `;
        updateConnectionBoxesVisibility();
    }
    // Create or update dynamic External active key box (no reload needed)
    function createOrUpdateExternalBox(cleanModel) {
        let externalBox = $('#external-key-info');
        if (!externalBox) {
            externalBox = document.createElement('div');
            externalBox.id = 'external-key-info';
            externalBox.className = 'purescan-field';
            externalBox.style.marginTop = '18px';
            externalBox.style.padding = '18px';
            externalBox.style.background = '#ecfdf5';
            externalBox.style.border = '1px solid #6ee7b7';
            externalBox.style.borderRadius = '12px';
            testBtn.closest('.purescan-field').insertAdjacentElement('afterend', externalBox);
        }
        externalBox.innerHTML = `
            <p style="margin:0; font-size:15px; line-height:1.8; color:#065f46;">
                <strong style="color:#059669; font-size:16px;">
                    Active External API Key
                </strong>
                <br><strong>Model:</strong> <code>${escapeHtml(cleanModel)}</code>
                <br><strong>Key Preview:</strong> <code>Managed by server (hidden)</code>
                <br><br>
                <small style="color:#059669; opacity:0.95; font-weight:500;">
                    PureScan automatically selects the best working key. This is the currently active one.
                </small>
            </p>
        `;
        updateConnectionBoxesVisibility();
    }
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
    // Remove Manual API Key – ONLY time the key/model are cleared
    function removeManualKey() {
        if (!confirm('Are you sure you want to remove your manual API key?\nThis will switch to External mode.')) {
            return;
        }
        apiKeyInput.value = '';
        modelSelect.innerHTML = '<option value="">Enter your API key first to load models...</option>';
        modelSelect.disabled = true;
        modelPriceInfo.textContent = '';
        modelsLoaded = false;
        manualTested = false;
        document.getElementById('api_source_external').checked = true;
        const manualBox = $('#manual-key-info');
        if (manualBox) manualBox.remove();
        updateApiFieldsVisibility();
        form.dispatchEvent(new Event('submit'));
    }
    // Delegated click for Remove button
    document.addEventListener('click', function (e) {
        if (e.target && e.target.matches('.purescan-remove-manual-key-btn')) {
            e.preventDefault();
            removeManualKey();
        }
    });
    // Event Listeners
    $$('input[name="api_source_radio"]').forEach(radio => radio.addEventListener('change', updateApiFieldsVisibility));
    apiKeyInput?.addEventListener('input', () => {
        if (getCurrentSource() === 'manual' && apiKeyInput.value.trim()) {
            modelsLoaded = false;
            loadOpenRouterModels(apiKeyInput.value.trim());
        }
        updateTestButtonState();
    });
    modelSelect?.addEventListener('change', () => {
        updateTestButtonState();
        if (modelsLoaded) showModelPrice([]);
    });
    // Save Settings – Require successful test in Manual mode
    form.addEventListener('submit', function (e) {
        e.preventDefault();
        const source = getCurrentSource();
        if (source === 'manual') {
            if (!apiKeyInput.value.trim()) {
                alert('API Key is required in Manual mode.');
                return;
            }
            if (!modelSelect.value) {
                alert('Please select an AI model.');
                return;
            }
            if (!manualTested) {
                alert('Please successfully test the manual connection before saving.');
                return;
            }
        }
        const data = new URLSearchParams();
        data.append('action', 'purescan_settings_save');
        data.append('nonce', PureScanAjax.nonce);
        form.querySelectorAll('input[name^="settings["], textarea[name^="settings["], select[name^="settings["]').forEach(field => {
            if (field.type === 'checkbox' || field.type === 'radio') {
                if (field.checked) data.append(field.name, field.value || '1');
            } else {
                data.append(field.name, field.value);
            }
        });
        data.append('settings[api_source]', source);
        data.append('settings[openrouter_connected]', '1');
        // Always send current key (preserves it when switching to External)
        data.append('settings[openrouter_api_key]', apiKeyInput.value.trim());
        // Only send model when in Manual mode (preserves previous when switching to External)
        if (source === 'manual') {
            data.append('settings[openrouter_model]', modelSelect.value);
        }
        saveBtn.disabled = true;
        settingsStatusEl.textContent = 'Saving settings...';
        settingsStatusEl.className = 'purescan-status-saving';
        fetch(PureScanAjax.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: data
        })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                settingsStatusEl.textContent = res.data?.message || 'Settings saved successfully!';
                settingsStatusEl.className = 'purescan-status-success';
                setTimeout(() => location.reload(), 1500);
            } else {
                settingsStatusEl.textContent = res.data || 'Failed to save settings.';
                settingsStatusEl.className = 'purescan-status-error';
            }
        })
        .catch(() => {
            settingsStatusEl.textContent = 'Network error.';
            settingsStatusEl.className = 'purescan-status-error';
        })
        .finally(() => {
            saveBtn.disabled = false;
            setTimeout(() => settingsStatusEl.textContent = '', 5000);
        });
    });
    // Reset to Defaults
    $('#purescan-reset-settings')?.addEventListener('click', () => {
        if (confirm('Reset all settings to defaults? This cannot be undone.')) {
            const data = new URLSearchParams();
            data.append('action', 'purescan_settings_save');
            data.append('nonce', PureScanAjax.nonce);
            data.append('reset', '1');
            fetch(PureScanAjax.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: data
            })
            .then(r => r.json())
            .then(res => {
                if (res.success) {
                    alert('Settings reset to defaults successfully!');
                    location.reload();
                } else {
                    alert('Error: ' + (res.data || 'Failed to reset settings.'));
                }
            })
            .catch(() => {
                alert('Network error while resetting settings.');
            });
        }
    });
    // Auto-resize textareas
    $$('textarea').forEach(textarea => {
        const resize = () => {
            textarea.style.height = 'auto';
            textarea.style.height = textarea.scrollHeight + 'px';
        };
        textarea.addEventListener('input', resize);
        resize();
    });
    // Limit Maximum Files Toggle
    const limitSwitch = $('#limit_files_enabled');
    const maxFilesWrapper = $('#max-files-wrapper');
    const maxFilesInput = $('#max_files');
    if (limitSwitch && maxFilesWrapper && maxFilesInput) {
        limitSwitch.addEventListener('change', function () {
            if (this.checked) {
                maxFilesWrapper.style.opacity = '1';
                maxFilesWrapper.style.pointerEvents = 'auto';
                maxFilesInput.disabled = false;
                if (!maxFilesInput.value || maxFilesInput.value === '0') {
                    maxFilesInput.value = '500000';
                }
            } else {
                maxFilesWrapper.style.opacity = '0.5';
                maxFilesWrapper.style.pointerEvents = 'none';
                maxFilesInput.disabled = true;
                maxFilesInput.value = '0';
            }
        });
    }
    // Scheduled Scan UI
    const schedEnabled = $('#scheduled_scan_enabled');
    const schedOptions = $('#scheduled-scan-options');
    const emailToggle = $('#scheduled_scan_send_email');
    const emailToggleWrapper = $('#email-toggle-wrapper');
    const emailBox = $('#email-recipient-info');
    const nextScanWrapper = $('#next-scheduled-info-wrapper');
    const weeklyWrapper = $('#weekly-day-wrapper');
    const monthlyWrapper = $('#monthly-date-wrapper');
    if (schedEnabled && schedOptions) {
        function refreshFrequencyUI() {
            const value = document.querySelector('input[name="settings[scheduled_scan_frequency]"]:checked')?.value || 'daily';
            weeklyWrapper.style.display = value === 'weekly' ? 'block' : 'none';
            monthlyWrapper.style.display = value === 'monthly' ? 'block' : 'none';
        }
        function updateFrequencyText() {
            const frequency = document.querySelector('input[name="settings[scheduled_scan_frequency]"]:checked')?.value || 'daily';
            const dayOfWeek = $('#scheduled_scan_day')?.value || 'monday';
            const dayOfMonth = parseInt($('#scheduled_scan_date')?.value || '1', 10);
            let text = 'Daily';
            if (frequency === 'weekly') {
                const daysEn = {
                    monday: 'Monday', tuesday: 'Tuesday', wednesday: 'Wednesday',
                    thursday: 'Thursday', friday: 'Friday', saturday: 'Saturday', sunday: 'Sunday'
                };
                text = 'Every ' + (daysEn[dayOfWeek] || dayOfWeek);
            } else if (frequency === 'monthly') {
                const suffix = dayOfMonth === 1 ? 'st' : dayOfMonth === 2 ? 'nd' : dayOfMonth === 3 ? 'rd' : 'th';
                text = `Day ${dayOfMonth}${suffix} of every month`;
            }
            const freqEl = $('#next-scan-frequency');
            if (freqEl) {
                freqEl.textContent = text;
            }
        }
        function updateScheduledScanUI() {
            const enabled = schedEnabled.checked;
            if (nextScanWrapper) nextScanWrapper.style.display = enabled ? 'block' : 'none';
            schedOptions.style.opacity = enabled ? '1' : '0.5';
            schedOptions.style.pointerEvents = enabled ? 'auto' : 'none';
            emailToggleWrapper.style.opacity = enabled ? '1' : '0.5';
            emailToggleWrapper.style.pointerEvents = enabled ? 'auto' : 'none';
            updateEmailRecipientBox();
            refreshFrequencyUI();
        }
        function updateEmailRecipientBox() {
            const show = schedEnabled.checked && emailToggle.checked;
            if (show) {
                emailBox.style.display = 'block';
                emailBox.style.opacity = '0';
                setTimeout(() => emailBox.style.opacity = '1', 10);
            } else {
                emailBox.style.opacity = '0';
                setTimeout(() => emailBox.style.display = 'none', 350);
            }
        }
        schedEnabled.addEventListener('change', updateScheduledScanUI);
        emailToggle.addEventListener('change', updateEmailRecipientBox);
        document.querySelectorAll('input[name="settings[scheduled_scan_frequency]"]').forEach(radio => {
            radio.addEventListener('change', () => {
                refreshFrequencyUI();
                updateFrequencyText();
            });
        });
        $('#scheduled_scan_day')?.addEventListener('change', updateFrequencyText);
        $('#scheduled_scan_date')?.addEventListener('change', updateFrequencyText);
        refreshFrequencyUI();
        updateFrequencyText();
        updateScheduledScanUI();
    }
    // AI Features Master Toggle with Confirmation Modal
    const aiToggle = $('#ai_features_enabled');
    const aiContent = $('#ai-integration-content');
    const aiModal = $('#ai-toggle-confirmation-modal');
    const aiModalMessage = $('#ai-modal-message');
    const aiModalConfirm = $('#ai-modal-confirm');
    const aiModalCancel = $('#ai-modal-cancel');
    let pendingAiState = null;
    if (aiToggle) {
        aiToggle.addEventListener('change', function (e) {
            e.preventDefault();
            pendingAiState = this.checked;
            if (pendingAiState) {
                aiModalMessage.innerHTML = `
                    <strong>Enabling AI Features</strong><br><br>
                    When AI features are enabled, PureScan will connect to our server to retrieve fallback API keys for OpenRouter.<br><br>
                    <strong>No personal or sensitive data is sent</strong> — only your site domain is used for verification.<br><br>
                    Alternatively, you can enter your own OpenRouter API key in Manual mode.<br><br>
                    Do you agree to enable AI features?
                `;
            } else {
                aiModalMessage.textContent = 'Are you sure you want to disable AI features? This will turn off all AI-powered analysis (Layer 2). Regular file scan will still work.';
            }
            aiModal.style.display = 'flex';
        });
        aiModalConfirm.addEventListener('click', () => {
            aiToggle.checked = pendingAiState;
            aiContent.style.opacity = pendingAiState ? '1' : '0.5';
            aiContent.style.pointerEvents = pendingAiState ? 'auto' : 'none';
            aiModal.style.display = 'none';
            pendingAiState = null;
        });
        aiModalCancel.addEventListener('click', () => {
            aiToggle.checked = !pendingAiState;
            aiModal.style.display = 'none';
            pendingAiState = null;
        });
        aiContent.style.opacity = aiToggle.checked ? '1' : '0.5';
        aiContent.style.pointerEvents = aiToggle.checked ? 'auto' : 'none';
    }
   
    // Initial setup
    updateApiFieldsVisibility();
});
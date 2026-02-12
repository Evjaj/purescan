<?php
/**
 * PureScan AI Manual Scan UI
 *
 * @package PureScan\AI
 */
namespace PureScan\AI;
if (!defined('ABSPATH')) {
    exit;
}
class AI_Scan_UI {
    public static function render() {
        $settings = \PureScan\Settings\Settings_Handler::get();
    
        $core = new \PureScan\Core();
        $is_pro = $core->is_pro();
    
        $connected = !empty($settings['openrouter_connected']);
        $nonce = wp_create_nonce(PURESCAN_NONCE);
        ?>
        <div class="purescan-card">
            <h2 class="purescan-section-title">AI Manual Code Scan</h2>
            <p class="purescan-description">
                Paste any code below and let AI analyze it for malware, backdoors, or vulnerabilities.
            </p>
    
            <?php if ( ! $is_pro ): ?>
                <div class="purescan-notice purescan-notice-warning" style="margin-bottom:24px;padding:20px;background:#fffbeb;border-radius:12px;border: 1px solid #f59e0b;">
                    <p style="margin:0; font-size:16px; color:#92400e;">
                        <strong>This feature is available only in PureScan Pro.</strong><br><br>
                        The AI Manual Code Scan tab allows you to paste and analyze any code instantly with advanced AI.<br><br>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=purescan&tab=upgrade')); ?>" style="color:#d97706; text-decoration:underline; font-weight:600;">
                            Upgrade to Pro now →
                        </a>
                    </p>
                </div>
            <?php endif; ?>
    
            <?php if (!$connected && $is_pro): ?>
                <div class="purescan-notice purescan-notice-error">
                    <p><strong>OpenRouter API is not connected.</strong> Go to <a href="<?php echo esc_url(admin_url('admin.php?page=purescan&tab=settings')); ?>">Settings</a> to connect.</p>
                </div>
            <?php endif; ?>
    
            <div class="purescan-ai-scan-box" style="<?php echo ! $is_pro ? 'opacity:0.5; pointer-events:none;' : ''; ?>">
                <textarea
                    id="purescan-ai-code-input"
                    placeholder="Paste your PHP/code here..."
                    rows="12"
                    <?php disabled( ! $is_pro || ! $connected ); ?>
                ></textarea>
          
                <div class="purescan-char-counter" id="purescan-char-counter">
                    <span id="purescan-char-count">0</span> / 8000 characters
                </div>
          
                <div class="purescan-ai-actions" style="position:relative; display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
                    <button
                        type="button"
                        id="purescan-ai-scan-btn"
                        class="ps-btn ps-btn-analyze"
                        <?php disabled( ! $is_pro || ! $connected ); ?>
                        data-nonce="<?php echo esc_attr($nonce); ?>"
                    >
                        Scan with AI
                    </button>
                    <button
                        type="button"
                        id="purescan-non-ai-scan-btn"
                        class="ps-btn ps-btn-secondary"
                        data-nonce="<?php echo esc_attr($nonce); ?>"
                    >
                        Scan without AI
                    </button>              
                    <div id="purescan-ai-spinner" class="purescan-spinner" style="display:none;"></div>
              
                    <button
                        type="button"
                        id="purescan-ai-clear-btn"
                        class="ps-btn ps-btn-ai-clear"
                        style="display:none;"
                    >
                        Clear All
                    </button>
              
                    <span id="purescan-ai-status" class="purescan-inline-error"></span>
                </div>
                <div id="purescan-ai-result" class="purescan-ai-result" style="display:none;"></div>
                <div id="purescan-non-ai-result" class="purescan-card-non-ai-result" style="margin-top: 32px; display: none;">
                    <div id="purescan-non-ai-content"></div>
                </div>
            </div>
        </div>
        <?php
    }
}
<?php
/**
 * PureScan AI Client
 *
 * Handles communication with OpenRouter API with smart instant fallback chain.
 * - Manual mode: uses user-provided key/model
 * - External mode: securely fetches keys from evjaj.com using short-lived (10-minute) HMAC token
 *
 * @package PureScan
 */
namespace PureScan;

if (!defined('ABSPATH')) {
    exit;
}

class AI_Client {

    /** @var array|null Current working key + model */
    private $current_key = null;

    /** @var array|null Cached full list of fallback keys */
    private $fallback_chain = null;

    /** @var string OpenRouter API endpoint */
    private $base_url = 'https://openrouter.ai/api/v1';

    /** @var string Your secure server (change only if you move the server) */
    private $fallback_host = 'https://www.evjaj.com/';

    /**
     * Constructor
     */
    public function __construct() {
        $settings = \PureScan\Settings\Settings_Handler::get();

        // Manual mode – user provided own key
        if (
            $settings['api_source'] === 'manual' &&
            !empty($settings['openrouter_api_key']) &&
            !empty($settings['openrouter_model']) &&
            !empty($settings['openrouter_connected'])
        ) {
            $this->current_key = [
                'key'   => trim($settings['openrouter_api_key']),
                'model' => trim($settings['openrouter_model']),
            ];
            return;
        }

        // External mode – secure fallback with token
        $this->load_best_available_key();
    }

    /**
     * Load the best possible working key (last good → fresh chain)
     */
    private function load_best_available_key(): void {
        // First, try to use the last known working key
        $last_good = get_option('purescan_active_external_key');
    
        if ($last_good && !empty($last_good['key']) && !empty($last_good['model'])) {
            $this->current_key = $last_good;
            return;
        }
    
        // If no cached good key, fetch fresh chain from server
        $chain = $this->get_fallback_chain();
    
        // Use the first key from the fresh chain if available
        if (!empty($chain[0])) {
            $this->current_key = $chain[0];
        }
    }

    /**
     * Get fallback keys with secure short-lived token + intelligent retry on 403
     */
    private function get_fallback_chain(): array {
        if ($this->fallback_chain !== null) {
            return $this->fallback_chain;
        }

        $cache_key = 'purescan_fallback_keys_v5_secure';
        $cached    = get_transient($cache_key);

        if ($cached !== false) {
            $this->fallback_chain = $cached;
            return $cached;
        }

        $keys = $this->fetch_secure_keys_with_retry();

        $chain = [];
        if (is_array($keys)) {
            foreach ($keys as $item) {
                if (
                    is_array($item) &&
                    !empty($item['key']) &&
                    str_starts_with(trim($item['key']), 'sk-or-v1-') &&
                    !empty($item['model']) &&
                    is_string($item['model'])
                ) {
                    $chain[] = [
                        'key'   => trim($item['key']),
                        'model' => trim($item['model']),
                    ];
                }
            }
        }

        // Cache for ~9.5 minutes (safe buffer before token expires)
        set_transient($cache_key, $chain, 9.5 * MINUTE_IN_SECONDS);
        $this->fallback_chain = $chain;

        return $chain;
    }

    /**
     * Fetch keys with automatic token refresh and one-time retry on token expiry
     */
    private function fetch_secure_keys_with_retry(int $retry = 1): array {
        $token_data = $this->get_valid_token();
    
        if (!$token_data) {
            return [];
        }
    
        $url = rtrim($this->fallback_host, '/') . '/purescan-fallback-keys';
    
        $response = wp_remote_get($url, [
            'timeout'    => 20,
            'sslverify'  => true,
            'headers'    => [
                'X-PureScan-Token'    => $token_data['token'],
                'X-PureScan-Expires'  => (string) $token_data['expires'],
                'Accept'              => 'application/json',
                'User-Agent'          => 'PureScan/' . (defined('PURESCAN_VERSION') ? PURESCAN_VERSION : '1.0'),
            ],
        ]);
    
        if (is_wp_error($response)) {
            return [];
        }
    
        $code = wp_remote_retrieve_response_code($response);
    
        // Retry once on 403 (likely expired/invalid token)
        if ($code === 403 && $retry > 0) {
            delete_transient('purescan_secure_token');
            return $this->fetch_secure_keys_with_retry(0);
        }
    
        if ($code !== 200) {
            return [];
        }
    
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
    
        return $data['keys'] ?? [];
    }

    /**
     * Get a valid token – from cache or fresh request
     */
    private function get_valid_token(): ?array {
        $cached = get_transient('purescan_secure_token');

        if (
            $cached &&
            !empty($cached['token']) &&
            !empty($cached['expires']) &&
            time() < ($cached['expires'] - 30) // refresh 30s early
        ) {
            return $cached;
        }

        return $this->request_new_token();
    }

    /**
     * Request a fresh token from /purescan-get-token endpoint
     */
    private function request_new_token(): ?array {
        $url = rtrim($this->fallback_host, '/') . '/purescan-get-token';

        $response = wp_remote_get($url, [
            'timeout'   => 12,
            'sslverify' => true,
            'headers'   => [
                'Accept'     => 'application/json',
                'User-Agent' => 'PureScan/' . (defined('PURESCAN_VERSION') ? PURESCAN_VERSION : '1.0'),
            ],
        ]);

        if (is_wp_error($response)) {
            return null;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            // Optional: log rate-limit or server error
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $json = json_decode($body, true);

        if (empty($json['token']) || empty($json['expires'])) {
            return null;
        }

        $token_data = [
            'token'   => $json['token'],
            'expires' => (int)$json['expires'],
        ];

        // Store with safe TTL (expires 5–10 seconds before real expiry)
        $ttl = max(60, $token_data['expires'] - time() - 10);
        set_transient('purescan_secure_token', $token_data, $ttl);
        return $token_data;
    }

    /**
     * Is AI ready to use?
     */
    public function is_connected(): bool {
        return !empty($this->current_key);
    }

    /**
     * Get current model name (for UI/logs)
     */
    public function get_current_model(): string {
        $model = $this->current_key['model'] ?? 'unknown';
        return str_replace(':free', '', $model);
    }

    /**
     * Send request with instant fallback to next working key
     */
    private function send_request(array $messages, ?string $model = null, float $temperature = 0.0) {
        $chain = $this->get_fallback_chain();

        if (empty($chain)) {
            return new \WP_Error('no_keys_available', 'No fallback keys available from server.');
        }

        foreach ($chain as $entry) {
            $this->current_key = $entry;

            $response = wp_remote_post("{$this->base_url}/chat/completions", [
                'timeout'   => 90,
                'sslverify' => true,
                'headers'   => [
                    'Authorization'  => 'Bearer ' . $entry['key'],
                    'HTTP-Referer'  => home_url(),
                    'X-Title'       => 'PureScan WordPress Plugin',
                    'Content-Type'  => 'application/json',
                ],
                'body' => wp_json_encode([
                    'model'       => $entry['model'],
                    'messages'    => $messages,
                    'temperature' => max(0.0, min(1.0, $temperature)),
                    'max_tokens'  => 2048,
                ]),
            ]);

            $code = wp_remote_retrieve_response_code($response);
            $body = json_decode(wp_remote_retrieve_body($response), true);

            if ($code === 200 && !empty($body['choices'][0]['message']['content'])) {
                $content = trim($body['choices'][0]['message']['content']);
                update_option('purescan_active_external_key', $entry, false);
                return $content;
            }

            $error = $body['error']['message'] ?? "HTTP $code";
        }

        update_option('purescan_active_external_key', end($chain), false);
        return new \WP_Error('all_keys_failed', 'All available OpenRouter keys failed or rate-limited.');
    }

    /** Public methods used by the rest of the plugin */
    public function chat(array $messages, ?string $model = null, float $temperature = 0.0) {
        return $this->send_request($messages, $model, $temperature);
    }

    public function analyze_code(string $code = '', string $filepath = 'unknown_file.txt') {
        $request_id = 'REQ_' . substr(wp_generate_uuid4(), 0, 8) . '_' . time();

        if (trim($code) === '') {
            $full_path = ABSPATH . ltrim($filepath, '/');
            if (!is_file($full_path) || !is_readable($full_path)) {
                return $this->format_strict_fallback('SUSPICIOUS', 'File not readable or missing.', 'The file could not be accessed.', 'Permission denied or file does not exist.', $request_id);
            }
            if (filesize($full_path) > 10 * 1024 * 1024) {
                return $this->format_strict_fallback('SUSPICIOUS', 'File exceeds 10MB limit.', 'Large files are skipped for performance.', 'Reduce file size or scan manually.', $request_id);
            }
            $code = @file_get_contents($full_path);
            if ($code === false || trim($code) === '') {
                return $this->format_strict_fallback('SUSPICIOUS', 'Empty or unreadable file.', 'File contains no text content.', 'Possibly binary or corrupted.', $request_id);
            }
            if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $code)) {
                return $this->format_strict_fallback('SUSPICIOUS', 'Binary data detected.', 'Non-text content found in file.', 'AI analysis skipped for safety.', $request_id);
            }
        }

        $raw_code     = trim($code);
        $display_code = strlen($raw_code) > 28000 ? substr($raw_code, 0, 28000) . "\n\n[...truncated...]" : $raw_code;

        $prompt = sprintf(
            "You are a senior WordPress security auditor and code analysis expert.\n" .
            "Analyze the following content carefully and respond EXACTLY in this structured format — no extra text, no markdown, no explanations outside this format:\n\n" .
            "Context: [WordPress Core | Plugin | Theme | Uploads | Config | General | Injected]\n" .
            "Status: [CLEAN | SUSPICIOUS | MALICIOUS]\n" .
            "Details: [Explain your reasoning in 3–5 clear lines]\n" .
            "Request ID: %s\n\n" .
            "CONTENT TO ANALYZE (%s):\n" .
            "-------------------\n%s\n" .
            "-------------------",
            esc_html($request_id),
            esc_html($filepath),
            $display_code
        );

        $result = $this->chat([['role' => 'user', 'content' => $prompt]], null, 0.1);

        if (is_wp_error($result)) {
            return $this->format_strict_fallback(
                'SUSPICIOUS',
                'AI analysis failed: ' . $result->get_error_message(),
                'All available keys failed.',
                'Check your connection or try again later.',
                $request_id
            );
        }

        return $result;
    }

    private function format_strict_fallback(string $status, string $detail1, string $detail2, string $request_id): string {
        return "Context: General\n" .
               "Status: " . strtoupper($status) . "\n" .
               "Details: " . $detail1 . ".\n" .
               $detail2 . ".\n" .
               "AI analysis unavailable — fallback response generated.\n" .
               "Request ID: " . $request_id;
    }

    // Optional helper (kept for future use)
    private function detect_content_type(string $code, string $extension): string {
        $code = trim($code);
        if (preg_match('#^/[\w/\-\.]*\.[\w]{1,6}$#', $code) || preg_match('#wp-(content|admin|includes)/#', $code)) {
            return 'File Path';
        }
        if ($extension === 'php' || stripos($code, '<?php') === 0 || preg_match('/\beval\s*\(/i', $code)) {
            return 'PHP';
        }
        if (in_array($extension, ['js', 'mjs'], true) || preg_match('/\b(function|const|let|var|document\.|window\.|alert\()/i', $code)) {
            return 'JavaScript';
        }
        if (in_array($extension, ['html', 'htm', 'svg'], true) || preg_match('/<\/?[a-z][\s\S]*>/i', $code)) {
            return 'HTML';
        }
        if ($extension === 'css' || preg_match('/\{[^}]*\}/s', $code)) {
            return 'CSS';
        }
        if ($extension === 'json' || (str_starts_with($code, '{') && str_ends_with($code, '}'))) {
            return 'JSON';
        }
        if (preg_match('/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|system\(|passthru\()/i', $code)) {
            return 'SQL/Shell';
        }
        return 'Text';
    }
}
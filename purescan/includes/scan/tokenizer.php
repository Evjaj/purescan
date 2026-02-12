<?php
/**
 * /tokenizer.php
 * PureScan Tokenizer PRO 2025 — context-aware tokenizer + RAW pre-scan
 *
 * Features:
 *  - raw_pre_scan()               : quick regex checks on raw file contents (before tokenization)
 *  - strip_comments()             : removes comments but preserves strings/heredocs
 *  - strip_with_line_map()        : returns cleaned code + line_map + offset_map
 *  - tokenize_preserve_strings()  : token_get_all wrapper that preserves string content exactly
 *  - is_probably_php()            : heuristic to decide if file is worth scanning
 *
 * Tokenizer is designed to feed both raw pattern engine and token pattern engine.
 */

namespace PureScan\Scan;

class Tokenizer {
    /**
     * Quick RAW pre-scan for patterns that may be hidden by whitespace/comments
     * This runs BEFORE token_get_all to catch things like long gaps, arithmetic cookie indices, hex-escaped tags, etc.
     * Returns an array of RAW matches (pattern_key => matched_text) — empty array if nothing found.
     */
    public static function raw_pre_scan(string $code): array {
        $matches = [];

        // Patterns tuned to catch obfuscation that survives comment/whitespace removal

        $raw_patterns = [

            // Existing
            'cookie_arith' => '/<\?php[\s\S]{0,2000}?(?:isset\s*\(|\$_COOKIE)\s*\[\s*[0-9+\-\(\)\s]+\s*\]/i',
            'hex_php_tag'  => '/\\x3c\\x3f(?:\\x70|p)/i',
            'tempnam_write' => '/tempnam\s*\([^)]{0,200}\)\s*;?.{0,400}?(?:fopen|fwrite|fputs|file_put_contents)/is',
            'rot13_cookie' => '/base64_decode\s*\(\s*str_rot13\s*\(\s*\$_COOKIE\s*\[.*?\]\s*\)\s*\)/i',
            'long_gap_after_open' => '/<\?php[\t \r\n]{50,}/',

            // 🔥 NEW — numeric COOKIE keys
            'cookie_numeric' => '/\$_COOKIE\s*\[\s*\d{1,3}\s*\]/',

            // 🔥 NEW — function table construction
            'array_function_table' =>
                '/\$\w+\s*=\s*array\s*\(\s*\)\s*;\s*\$\w+\s*\[\s*\$\w+\s*\]\s*=\s*[\'"]/is',

            // 🔥 NEW — while loop assembling strings
            'while_char_assembly' =>
                '/while\s*\([^\)]*\)\s*\{[\s\S]{0,800}?\$\w+\s*\[\s*\$\w+\s*\]\s*\.=\s*\$\w+\s*\[[^\]]+\]/i',

            // 🔥 NEW — variable function from array index
            'array_callable_exec' =>
                '/\$\w+\s*\[\s*\d+\s*\]\s*\(/',

            // 🔥 NEW — dynamic include loader
            'dynamic_include_var' =>
                '/(?:include|require|include_once|require_once)\s*\(\s*\$\w+\s*\)\s*;/i',
        ];

        foreach ($raw_patterns as $k => $p) {
            if (preg_match($p, $code, $m)) {
                $matches[$k] = $m[0] ?? true;
            }
        }

        return $matches;
    }

    /**
     * Remove comments and optionally normalize whitespace while preserving string contents and heredocs.
     */
    public static function strip_comments(string $code, bool $strip_whitespace = true): string {
        if (false === strpos($code, '<?')) {
            $out = $strip_whitespace ? preg_replace('/\s+/', ' ', $code) : $code;
            return $strip_whitespace ? trim($out) : $out;
        }

        $tokens = token_get_all($code);
        $output = '';
        $in_heredoc = false;

        foreach ($tokens as $token) {
            if (is_string($token)) {
                $output .= $token;
                continue;
            }
            [$id, $text] = $token + [null, ''];

            // Preserve heredoc boundaries and content exactly
            if ($id === T_START_HEREDOC) {
                $in_heredoc = true;
                $output .= $text;
                continue;
            }
            if ($id === T_END_HEREDOC) {
                $in_heredoc = false;
                $output .= $text;
                continue;
            }
            if ($in_heredoc) {
                $output .= $text;
                continue;
            }

            switch ($id) {
                case T_COMMENT:
                case T_DOC_COMMENT:
                    // remove comments entirely
                    break;
                case T_WHITESPACE:
                    $output .= $strip_whitespace ? ' ' : $text;
                    break;
                default:
                    $output .= $text;
            }
        }

        if ($strip_whitespace) {
            $output = preg_replace('/\s+/', ' ', $output);
            $output = trim((string) $output);
        }

        return $output;
    }

    /**
     * Strip comments and produce a line_map and offset_map for reporting and mapping back to original file.
     */
    public static function strip_with_line_map(string $code, bool $strip_whitespace = true): array {
        $code = str_replace(["\xEF\xBB\xBF", "\xC2\xA0", "\xE2\x80\x80", "\xE2\x80\x81"], ' ', $code);

        if (false === strpos($code, '<?')) {
            $clean = $strip_whitespace ? preg_replace('/\s+/', ' ', $code) : $code;
            $clean = $strip_whitespace ? trim((string)$clean) : $clean;
            return ['code' => $clean, 'line_map' => [0 => 1], 'offset_map' => [0 => 0]];
        }

        $tokens = token_get_all($code);
        $clean = '';
        $line_map = [];
        $offset_map = [];
        $clean_offset = 0;
        $original_offset = 0;
        $original_line = 1;
        $in_heredoc = false;

        foreach ($tokens as $token) {
            if (is_string($token)) {
                $text = $token;
                $lines = substr_count($text, "\n");
                if (!array_key_exists($clean_offset, $line_map)) {
                    $line_map[$clean_offset] = $original_line;
                    $offset_map[$clean_offset] = $original_offset;
                }
                $clean .= $text;
                $clean_offset += strlen($text);
                $original_offset += strlen($text);
                $original_line += $lines;
                continue;
            }

            [$id, $text] = $token + [null, ''];
            $lines = substr_count($text, "\n");

            if ($id === T_START_HEREDOC) {
                if (!array_key_exists($clean_offset, $line_map)) {
                    $line_map[$clean_offset] = $original_line;
                    $offset_map[$clean_offset] = $original_offset;
                }
                $clean .= $text;
                $clean_offset += strlen($text);
                $original_offset += strlen($text);
                $original_line += $lines;
                $in_heredoc = true;
                continue;
            }

            if ($id === T_END_HEREDOC) {
                if (!array_key_exists($clean_offset, $line_map)) {
                    $line_map[$clean_offset] = $original_line;
                    $offset_map[$clean_offset] = $original_offset;
                }
                $clean .= $text;
                $clean_offset += strlen($text);
                $original_offset += strlen($text);
                $original_line += $lines;
                $in_heredoc = false;
                continue;
            }

            if ($in_heredoc) {
                if (!array_key_exists($clean_offset, $line_map)) {
                    $line_map[$clean_offset] = $original_line;
                    $offset_map[$clean_offset] = $original_offset;
                }
                $clean .= $text;
                $clean_offset += strlen($text);
                $original_offset += strlen($text);
                $original_line += $lines;
                continue;
            }

            if ($id === T_COMMENT || $id === T_DOC_COMMENT) {
                $original_offset += strlen($text);
                $original_line += $lines;
                continue;
            }

            if ($id === T_WHITESPACE) {
                if ($strip_whitespace) {
                    if (!array_key_exists($clean_offset, $line_map)) {
                        $line_map[$clean_offset] = $original_line;
                        $offset_map[$clean_offset] = $original_offset;
                    }
                    $clean .= ' ';
                    $clean_offset += 1;
                    $original_offset += strlen($text);
                    $original_line += $lines;
                } else {
                    if (!array_key_exists($clean_offset, $line_map)) {
                        $line_map[$clean_offset] = $original_line;
                        $offset_map[$clean_offset] = $original_offset;
                    }
                    $clean .= $text;
                    $clean_offset += strlen($text);
                    $original_offset += strlen($text);
                    $original_line += $lines;
                }
                continue;
            }

            if (!array_key_exists($clean_offset, $line_map)) {
                $line_map[$clean_offset] = $original_line;
                $offset_map[$clean_offset] = $original_offset;
            }

            $clean .= $text;
            $clean_offset += strlen($text);
            $original_offset += strlen($text);
            $original_line += $lines;
        }

        if (empty($line_map)) {
            $line_map[0] = 1;
            $offset_map[0] = 0;
        } elseif (!array_key_exists(0, $line_map)) {
            $firstKey = array_key_first($line_map);
            if ($firstKey !== 0) {
                $line0 = $line_map[$firstKey];
                $offset0 = $offset_map[$firstKey];
                $line_map = [0 => $line0] + $line_map;
                $offset_map = [0 => $offset0] + $offset_map;
            }
        }

        ksort($line_map);
        ksort($offset_map);

        return ['code' => $clean, 'line_map' => $line_map, 'offset_map' => $offset_map];
    }

    /**
     * Return true if the content looks like PHP executable code
     */
    public static function is_probably_php(string $code): bool {
        if (stripos($code, '<?php') !== false || stripos($code, '<?=') !== false) {
            return true;
        }
        if (preg_match('/\b(function|class|namespace|use|trait)\b/i', $code)) {
            return true;
        }
        return false;
    }

    /**
     * Token_get_all wrapper that returns tokens but keeps string content exactly as in source
     * (This is effectively token_get_all but ensures we can index into tokens reliably.)
     */
    public static function tokenize_preserve_strings(string $code): array {
        return token_get_all($code);
    }

    /**
     * Utility: find original line from cleaned offset using line_map
     */
    public static function original_line_from_offset(array $line_map, int $cleaned_offset): int {
        if (array_key_exists($cleaned_offset, $line_map)) {
            return $line_map[$cleaned_offset];
        }
        $keys = array_keys($line_map);
        $pos = null;
        foreach ($keys as $k) {
            if ($k <= $cleaned_offset) $pos = $k; else break;
        }
        if ($pos === null) return reset($line_map);
        return $line_map[$pos];
    }
}

// Backwards compatible alias
class_alias('PureScan\\Scan\\Tokenizer', 'Tokenizer');
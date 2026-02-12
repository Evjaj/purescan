<?php
/**
 * PureScan Industrial Detector Patterns – Professional No-Whitelist Pack (2026)
 *
 * Token-aware + Sequence Heuristics + Raw Obfuscation Detection
 * Fully compatible with PureScan_Scan_Engine
 * Zero whitelists — Maximum possible detection accuracy
 *
 * @return array Pattern definitions
 */
if (!defined('ABSPATH')) {
    exit; // Prevent direct access
}
return [
    // 1. Nested decoder on $_COOKIE → eval/assert (extremely high confidence)
    [
        'regex' => '/\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode)\s*\(\s*str_rot13\s*\(\s*\$_COOKIE\s*\[\s*[^\]]+\s*\]\s*\)\s*\)\s*\)/i',
        'score' => 100,
        'note' => 'Nested decoder chain (str_rot13 → base64/gz → eval) on $_COOKIE',
        'context' => 'token'
    ],
    // 2. Any decoder on superglobal → dangerous sink in close proximity
    [
        'regex' => '/(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\][\s\S]{0,1200}?(?:eval|assert|include|require|system|exec|shell_exec|popen|passthru)\s*\(/i',
        'score' => 96,
        'note' => 'Decoded superglobal passed to dangerous function (eval/include/system etc.)',
        'context' => 'both'
    ],
    // 3. File infector: tempnam → write → include/require variable
    [
        'regex' => '/tempnam\s*\([^)]{0,400}\)(?:[\s\S]{0,1200}?(?:fopen|fwrite|fputs|file_put_contents)[\s\S]{0,800}?(?:include|require|include_once|require_once)\s*\([^)]*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)/i',
        'score' => 100,
        'note' => 'Classic file-infector pattern: tempnam + write + dynamic include/require',
        'context' => 'both'
    ],
    // 4. Obfuscated $_COOKIE index with arithmetic or variables
    [
        'regex' => '/\$_COOKIE\s*\[\s*[^\]]*(?:\+|-|\*|\/|\$|\()/',
        'score' => 48,
        'note' => 'Obfuscated $_COOKIE key using arithmetic operators or variables',
        'context' => 'token'
    ],
    // 5. Strongly obfuscated hex-escaped PHP tag or extremely long double-escaped hex chains
    [
        'regex' => '/\\\\x3c\\\\x3f(?:php)?|(?:\\\\x[0-9A-Fa-f]{2}){60,}/i',
        'score' => 85,
        'note' => 'Double-escaped hex for <?php tag or extremely long hex chains (>60 bytes) — strong indicator of heavy payload obfuscation (crypto constants usually <32 bytes)',
        'context' => 'both'
    ],
    // 6. Variable function invoked directly with superglobal argument
    [
        'regex' => '/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST|SERVER)\s*\[/i',
        'score' => 68,
        'note' => 'Variable function call with superglobal (obfuscated execution sink)',
        'context' => 'token'
    ],
    // 7. Direct RCE functions with user input or remote content
    [
        'regex' => '/\b(system|exec|shell_exec|popen|passthru|proc_open)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[|file_get_contents\s*\(\s*[\'"]https?:\/\/)/i',
        'score' => 98,
        'note' => 'Direct shell execution from user input or remote URL',
        'context' => 'token'
    ],
    // 8. eval/assert of large encoded literal string (classic webshell)
    [
        'regex' => '/\b(eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13)\s*\(\s*[\'\"][A-Za-z0-9+\/=]{80,}[\'\"]\s*\)\s*\)/i',
        'score' => 94,
        'note' => 'eval/assert of large encoded string (typical one-liner webshell)',
        'context' => 'token'
    ],
    // 9. Error-suppressed dangerous functions (@eval, @include, etc.)
    [
        'regex' => '/@\s*(?:eval|assert|include|require|system|exec|shell_exec)\s*\(/i',
        'score' => 92,
        'note' => 'Error-suppressed dangerous function (@eval, @include, etc.)',
        'context' => 'token'
    ],
    // 10. preg_replace() with /e modifier (deprecated RCE)
    [
        'regex' => '/preg_replace\s*\(\s*[\'\"][^\'\"]*\\/e[^\'\"]*[\'\"]\s*,/i',
        'score' => 100,
        'note' => 'preg_replace with /e modifier — direct code execution vulnerability',
        'context' => 'token'
    ],
    // 11. create_function() usage — significantly lowered score for legacy compatibility
    [
        'regex' => '/\bcreate_function\s*\(\s*[\'\"]/i',
        'score' => 50,
        'note' => 'create_function() — legacy function, common in old legitimate code but also backdoors',
        'context' => 'token'
    ],
    // 12. Low-confidence heuristic: decoding superglobal without immediate sink
    [
        'regex' => '/\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i',
        'score' => 15,
        'note' => 'Heavy obfuscation decoder on superglobal (without immediate sink)',
        'context' => 'token'
    ],
    // 13. Dynamic include/require of user-controlled path (path traversal style)
    [
        'regex' => '/(?:include|require|include_once|require_once)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*?\??->)/i',
        'score' => 88,
        'note' => 'Dynamic include/require using superglobal (potential LFI/RFI)',
        'context' => 'token'
    ],
    // 14. Reflection-based execution (advanced obfuscation)
    [
        'regex' => '/(?:ReflectionFunction|ReflectionMethod)\s*::\s*invoke\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'score' => 90,
        'note' => 'Reflection API used to invoke code from user input (advanced backdoor)',
        'context' => 'token'
    ],
   
    // 15. @@ Protocol Beacon - Hardcoded root path (common in C2 beacons)
    [
        'regex' => '/\$[a-zA-Z_]\w*\s*=\s*[\'"]\/home\/[^\'"]*public_html[\'"]/i',
        'score' => 40,
        'note' => '@@ Beacon: Hardcoded /home/.../public_html path',
        'context' => 'both'
    ],
    // 16. @@ Protocol Beacon - Entry with @@ID@@ pattern
    [
        'regex' => '/=>\s*[\'"]?[a-z0-9]{1,8}@@\d{4,}@@[^\'"\[\]]{1,60}[\'"]?/i',
        'score' => 60,
        'note' => '@@ Beacon: Map entry with prefix@@ID@@checksum/pattern',
        'context' => 'both'
    ],
    // 17. @@ Protocol Beacon - explode on @@ separator
    [
        'regex' => '/explode\s*\(\s*[\'"]@@[\'"]\s*,\s*\$\w+\s*\)/i',
        'score' => 50,
        'note' => '@@ Beacon: explode("@@") for parsing beacon data',
        'context' => 'both'
    ],
    // 18. @@ Protocol Beacon - list() destructuring after explode
    [
        'regex' => '/list\s*\(\s*\$\w+\s*,\s*\$\w+\s*,\s*\$\w+\s*\)\s*=\s*explode/i',
        'score' => 40,
        'note' => '@@ Beacon: list($tag,$id,$pattern) = explode(@@)',
        'context' => 'both'
    ],
    // 19. @@ Protocol Beacon - XML-style print with ##d or ##bs
    [
        'regex' => '/print\s*"<\$[^>]+>\s*\{\s*\$[^}]+\s*\}##[a-z]{1,2}\s*<\/\$[^>]+>/i',
        'score' => 70,
        'note' => '@@ Beacon: XML-like response <tag>{id}##d(or bs)</tag>',
        'context' => 'both'
    ],
    // 20. @@ Protocol Beacon - die("!end!") kill-switch
    [
        'regex' => '/die\s*\(\s*[\'"]!end![\'"]\s*\)/i',
        'score' => 50,
        'note' => '@@ Beacon: Standard die("!end!") terminator',
        'context' => 'both'
    ],
   
    // 21. Cookie copied to local variable then used indirectly (taint staging)
    [
        'regex' => '/\$\w+\s*=\s*\$_COOKIE\s*;/i',
        'score' => 20,
        'note' => 'Superglobal $_COOKIE staged into local variable (taint propagation setup)',
        'context' => 'token'
    ],
    // 22. Runtime-built function table using numeric indices
    [
        'regex' => '/\$\w+\s*=\s*array\s*\(\s*\);\s*\$\w+\s*\[\s*\$\w+\s*\]\s*=\s*[\'"]/is',
        'score' => 45,
        'note' => 'Runtime function table built dynamically with numeric indices',
        'context' => 'both'
    ],
    // 23. While-loop assembling callable names character-by-character
    [
        'regex' => '/while\s*\([^\)]*\)\s*\{[\s\S]{0,600}?\$\w+\s*\[\s*\$\w+\s*\]\s*\.=\s*\$\w+\s*\[[^\]]+\]/i',
        'score' => 80,
        'note' => 'Character-by-character assembly of function names (advanced obfuscation)',
        'context' => 'both'
    ],
    // 24. Variable function invoked from array index
    [
        'regex' => '/\$\w+\s*\[\s*\d+\s*\]\s*\(\s*(?:\$_(?:GET|POST|COOKIE|REQUEST|SERVER)|\$\w+\s*\[\s*\d+\s*\])/i',
        'score' => 75,
        'note' => 'Function call via numeric array index with tainted argument or nested — strong obfuscation indicator',
        'context' => 'token'
    ],
    // 25. Nested variable-function execution chain
    [
        'regex' => '/\$\w+\s*\[\s*\d+\s*\]\s*\(\s*\$\w+\s*\[\s*\d+\s*\]\s*\(/i',
        'score' => 85,
        'note' => 'Nested variable-function execution chain (obfuscated execution pipeline)',
        'context' => 'both'
    ],
    // 26. File write using variable function names
    [
        'regex' => '/\$\w+\s*\[\s*\d+\s*\]\s*\(\s*\$\w+\s*,\s*\$?\w+/i',
        'score' => 70,
        'note' => 'File write via variable function (file_put_contents/fwrite abstraction)',
        'context' => 'both'
    ],
    // 27. Include of dynamically constructed path variable (restricted to variable-variable only)
    [
        'regex' => '/\b(include|require|include_once|require_once)\s*(?:\$\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*|\([ \t]*\$\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*(?:,\s*[\'"]?once[\'"]?\s*)?\))/i',
        'score' => 70,
        'note' => 'Dynamic include/require using variable-variable ($$var or include($$var)) — rare in legitimate code, common in obfuscated LFI/backdoors',
        'context' => 'token'
    ],
    // 28. File existence/readability check immediately preceding dynamic include (common in autoloaders)
    [
        'regex' => '/(?:file_exists|is_file|is_readable)\s*\(\s*\$\w+\s*\)[\s\S]{0,500}?(include|require|include_once|require_once)\s*\(\s*\$\w+\s*\)/i',
        'score' => 55,
        'note' => 'File check (file_exists/is_file/is_readable) followed by dynamic include — common in legitimate autoloaders but also dropper behavior',
        'context' => 'both'
    ],
    // 29. Cookie-sourced payload decoded then written to disk (indirect)
    [
        'regex' => '/\$\w+\s*\[\s*\d+\s*\]\s*\(\s*\$\w+\s*\[\s*\d+\s*\]\s*\(\s*\$\w+\s*\[\s*\d+\s*\]\s*\)\s*\)/i',
        'score' => 90,
        'note' => 'Multi-stage decoding pipeline from COOKIE to executable payload',
        'context' => 'both'
    ],
    // 30. Suspicious numeric COOKIE indices (non-semantic keys)
    [
        'regex' => '/\$_COOKIE\s*\[\s*\d{1,3}\s*\]/i',
        'score' => 35,
        'note' => 'Numeric-indexed COOKIE access (common in stealth backdoors)',
        'context' => 'token'
    ],
    // 31. Control-flow dependent on COOKIE presence only
    [
        'regex' => '/if\s*\(\s*isset\s*\(\s*\$_COOKIE\s*\[\s*\d+\s*\]\s*\)\s*(?:&&|\|\|)\s*isset\s*\(\s*\$_COOKIE\s*\[\s*\d+\s*\]\s*\)\s*\)/i',
        'score' => 55,
        'note' => 'Execution gate controlled solely by numeric COOKIE presence',
        'context' => 'token'
    ],
    // 32. Silent loader without output except include execution
    [
        'regex' => '/if\s*\([^\)]*\)\s*\{[\s\S]{0,800}?include\s*\(\s*\$\w+\s*\)\s*;\s*\}/i',
        'score' => 60,
        'note' => 'Silent conditional loader block (stealth execution)',
        'context' => 'both'
    ],
   
    // 33. call_user_func / call_user_func_array with tainted input (dispatcher webshell)
    [
        'regex' => '/\bcall_user_func(?:_array)?\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|\$GLOBALS)\s*\[/i',
        'score' => 90,
        'note' => 'call_user_func(_array) executed with user-controlled input',
        'context' => 'token'
    ],
    // 34. forward_static_call / forward_static_call_array dispatcher
    [
        'regex' => '/\bforward_static_call(?:_array)?\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|\$GLOBALS)\s*\[/i',
        'score' => 88,
        'note' => 'forward_static_call(_array) with tainted callable input',
        'context' => 'token'
    ],
    // 35. $GLOBALS used as indirect taint source
    [
        'regex' => '/\$GLOBALS\s*$$ \s*[\'"][^\'"]+[\'"]\s* $$/i',
        'score' => 35,
        'note' => 'Indirect taint access via $GLOBALS array',
        'context' => 'token'
    ],
    // 36. assert() directly on user input (memory-only execution)
    [
        'regex' => '/\bassert\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|\$GLOBALS)\s*\[/i',
        'score' => 92,
        'note' => 'assert() executed directly on user-controlled input',
        'context' => 'token'
    ],
    // 37. register_* callback with user-controlled callable
    [
        'regex' => '/\bregister_(?:shutdown_function|tick_function|error_handler)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$GLOBALS)\s*\[/i',
        'score' => 85,
        'note' => 'register_* callback using tainted callable',
        'context' => 'token'
    ],
    // 38. preg_filter with user-controlled replacement
    [
        'regex' => '/\bpreg_filter\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$GLOBALS)\s*\[/i',
        'score' => 90,
        'note' => 'preg_filter replacement controlled by user input',
        'context' => 'token'
    ],
    // 39. Function name assembled via chr()/ord() concatenation
    [
        'regex' => '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){4,}chr\s*\(\s*\d+\s*\)/i',
        'score' => 95,
        'note' => 'Long chain of chr() (at least 5) to build hidden strings — strong indicator of obfuscation',
        'context' => 'both'
    ],
    // 40. implode(array_map(chr)) function name construction
    [
        'regex' => '/implode\s*\(\s*[\'"]{0,1}\s*[\'"]{0,1}\s*,\s*array_map\s*\(\s*[\'"]chr[\'"]\s*,/i',
        'score' => 78,
        'note' => 'Function name assembled via implode(array_map(chr))',
        'context' => 'token'
    ],
    // 41. ob_start with user-controlled callback
    [
        'regex' => '/\bob_start\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$GLOBALS)\s*\[/i',
        'score' => 82,
        'note' => 'ob_start callback controlled by user input',
        'context' => 'token'
    ],
    // 42. Logic-based execution gate (time/hash condition)
    [
        'regex' => '/if\s*\(\s*(?:date|time|md5|sha1|hash)\s*\([^\)]*\)\s*(?:==|===|!=|!==)/i',
        'score' => 45,
        'note' => 'Logic-based execution gate (time/hash comparison)',
        'context' => 'token'
    ],
    // 43. Advanced dropper chain with self-delete
    [
        'regex' => '/
            file_put_contents\s*\(\s*
            (\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)
            \s*,\s*
            [^)]*
            \)
            [\s\S]{0,900}?
            (?:include|require|include_once|require_once|eval|assert)\s*\(\s*\1\s*\)
            [\s\S]{0,700}?
            @?\s*unlink\s*\(\s*__FILE__\s*\)
        /ix',
        'score' => 100,
        'note' => 'Advanced dropper: file_put_contents($var, ...) → execute same $var → self-delete (__FILE__)',
        'context' => 'both'
    ],
];
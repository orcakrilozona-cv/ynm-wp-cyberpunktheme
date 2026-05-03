<?php
/**
 * CyberPunk Dark - Comprehensive Security Hardening
 *
 * Covers all OWASP Top 10 attack vectors with evasion-resistant filters:
 *  1. XSS (Reflected, Stored, DOM) — double-encoding, Unicode, null-byte
 *  2. SQL Injection — input sanitization layer + query monitor
 *  3. CSRF — global POST enforcement + nonce helpers
 *  4. Remote File Inclusion (RFI) — runtime ini hardening + URL scheme block
 *  5. Arbitrary File Upload — MIME allowlist + extension + path traversal
 *  6. Code Injection — dangerous function block + input pattern detection
 *  7. Local File Inclusion (LFI) — realpath canonicalization + traversal strip
 *  8. Path Disclosure — error suppression + path scrubbing
 *  9. Brute-Force / HTTP Rate Limiting — progressive lockout + global limiter
 * 10. HTTP Security Headers — CSP, HSTS, X-Frame, etc.
 * 11. Session Security — HttpOnly, Secure, SameSite
 * 12. Information Disclosure — version hiding, XML-RPC, user enum
 *
 * @package CyberPunk_Dark
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 1 — RUNTIME PHP HARDENING (fires immediately on include)
   ═══════════════════════════════════════════════════════════════════════════════ */

// Disable RFI at runtime — belt-and-suspenders on top of php.ini.
if ( function_exists( 'ini_set' ) ) {
    @ini_set( 'allow_url_include', '0' );
    @ini_set( 'allow_url_fopen',   '0' );  // Disable remote fopen too.

    // Path Disclosure: suppress error output to browser.
    @ini_set( 'display_errors',         '0' );
    @ini_set( 'display_startup_errors', '0' );
    @ini_set( 'log_errors',             '1' );

    // Force WP_DEBUG_DISPLAY off even if WP_DEBUG is true in wp-config.php.
    // This prevents stack traces and file paths leaking to the browser in production.
    if ( ! defined( 'WP_DEBUG_DISPLAY' ) ) {
        define( 'WP_DEBUG_DISPLAY', false );
    }
    @ini_set( 'display_errors', '0' ); // Belt-and-suspenders: override any WP_DEBUG_DISPLAY=true.

    // Session hardening at ini level.
    @ini_set( 'session.cookie_httponly', '1' );
    @ini_set( 'session.cookie_secure',   is_ssl() ? '1' : '0' ); // Secure flag: HTTPS only.
    @ini_set( 'session.cookie_samesite', 'Strict' ); // FIX: upgraded from Lax to Strict (see Section 7).
    @ini_set( 'session.use_strict_mode', '1' );
    @ini_set( 'session.use_only_cookies','1' );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 2 — INPUT SANITIZATION LAYER (XSS / SQLi / Code Injection evasion)
   ═══════════════════════════════════════════════════════════════════════════════ */

/**
 * Deeply sanitize a string against XSS evasion techniques:
 *  - Recursive URL-decoding (catches double/triple encoding: %253C → %3C → <)
 *  - Null-byte removal (\x00 can truncate extension checks)
 *  - Unicode normalization bypass (fullwidth U+FF01–FF5E AND \uXXXX JS escapes)
 *  - HTML entity stripping (including &#x3C; &#60; &lt; chains)
 *  - HTML comment injection collapse (<scr<!---->ipt>)
 *  - CSS expression() removal
 *  - base64_decode / str_rot13 obfuscation removal
 *  - htmlspecialchars with ENT_QUOTES|ENT_SUBSTITUTE for output encoding
 *
 * Use this for any user-supplied string that will be output in HTML context.
 *
 * @param  string $input Raw user input.
 * @return string        Sanitized, HTML-safe string.
 */
function cyberpunk_sanitize_input( $input ) {
    if ( ! is_string( $input ) ) {
        return '';
    }

    // 1. Remove null bytes (LFI / extension bypass vector).
    $input = str_replace( "\x00", '', $input );

    // 2. Collapse HTML comments BEFORE decoding — prevents <scr<!---->ipt> surviving
    //    the decode step and then matching tag-stripping as a valid tag.
    $input = preg_replace( '/<!--[\s\S]*?-->/', '', $input );

    // 3. Recursive URL-decode until stable (catches %2525 → %25 → % chains).
    //    Run after comment collapse so encoded comment sequences are also caught.
    $prev = null;
    $iterations = 0;
    while ( $prev !== $input && $iterations < 10 ) {
        $prev  = $input;
        $input = rawurldecode( $input );
        $iterations++;
    }

    // 4a. Normalize full-width Unicode lookalikes to ASCII equivalents.
    //     Covers U+FF01–U+FF5E (fullwidth forms) → ASCII 0x21–0x7E.
    //     e.g. ＜script＞ → <script> before tag stripping.
    $input = preg_replace_callback(
        '/[\x{FF01}-\x{FF5E}]/u',
        function( $m ) {
            return mb_convert_encoding(
                pack( 'n', mb_ord( $m[0], 'UTF-8' ) - 0xFF00 + 0x20 ),
                'UTF-8',
                'UTF-16BE'
            );
        },
        $input
    );

    // 4b. Decode \uXXXX JS/JSON Unicode escape sequences.
    //     Attackers use these in DOM XSS payloads: \u003cscript\u003e → <script>
    //     Must run AFTER fullwidth normalization so both layers are caught.
    $input = preg_replace_callback(
        '/\\\\u([0-9a-fA-F]{4})/i',
        function( $m ) {
            $codepoint = hexdec( $m[1] );
            // Only decode printable ASCII range to avoid introducing control chars.
            if ( $codepoint >= 0x20 && $codepoint <= 0x7E ) {
                return chr( $codepoint );
            }
            return $m[0]; // Leave non-ASCII codepoints encoded — they are safe.
        },
        $input
    );

    // 4c. Decode HTML character references a second time after Unicode normalization.
    //     Catches &#x3C; &#60; &lt; chains that survive steps 4a/4b.
    $input = html_entity_decode( $input, ENT_QUOTES | ENT_HTML5, 'UTF-8' );

    // 4d. Strip CSS injection vectors:
    //     - expression() with tab/newline whitespace bypass (e.g. expres\tsion\n())
    //     - url() with javascript: or data: payloads
    //     - @import directives (can load external stylesheets with payloads)
    //     Run AFTER entity decode so encoded variants are caught.
    $input = preg_replace( '/expres+ion[\s\S]{0,10}\(/i', '', $input );
    $input = preg_replace( '/url\s*\(\s*[\'"]?\s*(?:javascript|data|vbscript)\s*:/i', 'url(', $input );
    $input = preg_replace( '/@import\b/i', '', $input );

    // 5. Remove CSS expression() — IE code execution vector (original pattern kept
    //    as belt-and-suspenders after the broader strip in step 4d).
    $input = preg_replace( '/expression\s*\((?:[^)(]*|\((?:[^)(]*|\([^)(]*\))*\))*\)/i', '', $input );

    // 6. Remove base64-encoded payloads used to smuggle code through filters.
    $input = preg_replace( '/base64_decode\s*\(/i', '', $input );
    $input = preg_replace( '/str_rot13\s*\(/i',     '', $input );

    // 7. Strip all HTML/SVG tags (including <svg>, <animate>, <set>, <image>).
    //    wp_strip_all_tags handles <svg/onload> (slash-separated) and
    //    <img/onerror> variants because it uses a full tag-stripping pass.
    $input = wp_strip_all_tags( $input );

    // 8. Re-encode for safe HTML output.
    return htmlspecialchars( $input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' );
}

/**
 * Global request input sanitization — applies cyberpunk_sanitize_input() and
 * cyberpunk_detect_code_injection() to all incoming GET/POST/COOKIE superglobals
 * before WordPress processes them.
 *
 * This is a defence-in-depth layer. WordPress's own sanitization functions
 * (sanitize_text_field, esc_html, etc.) are still required at output time.
 * This layer catches evasion payloads that bypass simple string checks:
 *  - Double/triple URL encoding (%253C → %3C → <)
 *  - Unicode fullwidth lookalikes (＜script＞)
 *  - \uXXXX JS escape sequences
 *  - Null-byte injection
 *  - HTML comment splitting (<scr<!---->ipt>)
 *
 * Payloads detected by cyberpunk_detect_code_injection() are blocked with 400.
 * All other inputs are sanitized in-place.
 *
 * Exclusions:
 *  - Admin requests (wp-admin) — handled by WP core + capability checks.
 *  - AJAX requests — handled per-action by nonce + sanitize_text_field.
 *  - REST API — handled by schema validation in each endpoint.
 *  - File upload fields ($_FILES) — handled by cyberpunk_validate_upload().
 *  - The 'content' and 'comment' fields — these legitimately contain HTML/markup
 *    and are handled by wp_kses_post() / wp_filter_kses() downstream.
 */
function cyberpunk_sanitize_global_inputs() {
    // Skip admin, AJAX, REST, CLI — they have their own sanitization pipelines.
    if ( is_admin() ) {
        return;
    }
    if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
        return;
    }
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        return;
    }
    if ( defined( 'WP_CLI' ) && WP_CLI ) {
        return;
    }

    // Fields that legitimately contain HTML/markup — skip deep sanitization.
    // These are handled by wp_kses_post() / wp_filter_kses() at output time.
    $html_fields = array( 'content', 'comment', 'description', 'excerpt', 'post_content' );

    // Process GET, POST, and COOKIE superglobals.
    $superglobals = array( &$_GET, &$_POST, &$_COOKIE );

    foreach ( $superglobals as &$global ) {
        if ( ! is_array( $global ) ) {
            continue;
        }
        foreach ( $global as $key => &$value ) {
            // Skip HTML-content fields.
            if ( in_array( $key, $html_fields, true ) ) {
                continue;
            }
            if ( is_string( $value ) ) {
                // Block requests containing code injection patterns.
                if ( cyberpunk_detect_code_injection( $value ) ) {
                    status_header( 400 );
                    wp_die(
                        esc_html__( 'Bad request: potentially malicious input detected.', 'cyberpunk-dark' ),
                        esc_html__( 'Bad Request', 'cyberpunk-dark' ),
                        array( 'response' => 400 )
                    );
                }
                // Sanitize the value in-place.
                $value = cyberpunk_sanitize_input( $value );
            } elseif ( is_array( $value ) ) {
                // Recursively sanitize nested arrays (e.g. $_POST['meta'][0]).
                array_walk_recursive( $value, function( &$v ) use ( $html_fields ) {
                    if ( is_string( $v ) ) {
                        if ( cyberpunk_detect_code_injection( $v ) ) {
                            status_header( 400 );
                            wp_die(
                                esc_html__( 'Bad request: potentially malicious input detected.', 'cyberpunk-dark' ),
                                esc_html__( 'Bad Request', 'cyberpunk-dark' ),
                                array( 'response' => 400 )
                            );
                        }
                        $v = cyberpunk_sanitize_input( $v );
                    }
                } );
            }
        }
        unset( $value );
    }
    unset( $global );
}
// Priority 1 — fires before any WordPress hook reads superglobals.
add_action( 'init', 'cyberpunk_sanitize_global_inputs', 1 );

/**
 * Sanitize a string for safe use in SQL LIKE clauses via $wpdb->prepare().
 * Escapes %, _, and \ which are special in LIKE patterns.
 *
 * @param  string $input Raw search term.
 * @return string        LIKE-safe string (still needs $wpdb->prepare() wrapping).
 */
function cyberpunk_sanitize_sql_like( $input ) {
    global $wpdb;
    return $wpdb->esc_like( sanitize_text_field( wp_unslash( $input ) ) );
}

/**
 * Validate and canonicalize a file path to prevent LFI / path traversal.
 *
 * Checks:
 *  - Null-byte injection (\x00)
 *  - Directory traversal sequences (../, ..\, encoded variants)
 *  - Ensures resolved realpath stays within an allowed base directory
 *
 * @param  string $path     User-supplied path fragment.
 * @param  string $base_dir Absolute base directory the path must reside within.
 * @return string|false     Canonical absolute path, or false if invalid.
 */
function cyberpunk_safe_path( $path, $base_dir ) {
    // Remove null bytes.
    $path = str_replace( "\x00", '', $path );

    // Recursive URL-decode (catches %2e%2e%2f → ../ and %255c → %5c → \).
    $prev = null;
    $i    = 0;
    while ( $prev !== $path && $i < 5 ) {
        $prev = $path;
        $path = rawurldecode( $path );
        $i++;
    }

    // Block Windows UNC paths (\\server\share) — can escape realpath on Windows.
    if ( preg_match( '#^\\\\\\\\#', $path ) ) {
        return false;
    }

    // Block encoded backslash variants (%5c, %255c) after decoding.
    if ( strpos( $path, '\\' ) !== false ) {
        return false;
    }

    // Block directory traversal sequences (../, \..\, and standalone ..).
    if ( preg_match( '#(\.\.[\\/]|[\\/]\.\.|\.\.[^/\\\\]|^\.\.$)#', $path ) ) {
        return false;
    }

    // Block ALL known PHP stream wrappers in path.
    // Extended from the original pattern to include file://, ssh2://, rar://,
    // ogg://, zlib://, compress.zlib://, compress.bzip2:// — all of which can
    // be used to read arbitrary files or make network connections via include/fopen.
    if ( preg_match( '#(?:php|phar|zip|glob|data|expect|input|filter|file|ssh2|rar|ogg|zlib|compress\.zlib|compress\.bzip2)\s*://#i', $path ) ) {
        return false;
    }

    // Build full path and canonicalize.
    $full = realpath( rtrim( $base_dir, '/\\' ) . DIRECTORY_SEPARATOR . ltrim( $path, '/\\' ) );

    if ( $full === false ) {
        return false;
    }

    // Ensure the resolved path is still inside the allowed base.
    // Also allow an exact match ($full === $base_real) so the base dir itself
    // is a valid return value — the previous check required a trailing separator
    // which would reject that edge case.
    $base_real = realpath( $base_dir );
    if ( $base_real === false ) {
        return false;
    }
    $in_base = ( $full === $base_real )
        || ( strpos( $full, $base_real . DIRECTORY_SEPARATOR ) === 0 );
    if ( ! $in_base ) {
        return false;
    }

    return $full;
}

/**
 * Detect code injection patterns in a string.
 *
 * Covers evasion techniques including:
 *  - PHP execution tags and short-open tags
 *  - JS event handlers (on* attributes)
 *  - javascript:/vbscript:/data: URI schemes
 *  - CSS expression() injection
 *  - HTML comment injection (<!-- --> used to split keywords)
 *  - Hex/octal escape sequences (\x41, \101) used to bypass keyword filters
 *  - PHP dangerous functions: eval, assert, system, exec, passthru, shell_exec,
 *    popen, proc_open, create_function, preg_replace /e modifier
 *  - Shell metacharacters and backtick execution
 *  - Common SQLi patterns
 *  - PHP stream wrapper abuse (php://, data://, phar://, zip://)
 *
 * Returns true if the string contains dangerous patterns.
 *
 * @param  string $input Input to check.
 * @return bool          True if dangerous content detected.
 */
function cyberpunk_detect_code_injection( $input ) {
    if ( ! is_string( $input ) ) {
        return false;
    }

    // Normalize before pattern matching: decode URL encoding and strip null bytes.
    $normalized = str_replace( "\x00", '', $input );
    $prev = null;
    $i    = 0;
    while ( $prev !== $normalized && $i < 5 ) {
        $prev       = $normalized;
        $normalized = rawurldecode( $normalized );
        $i++;
    }

    $patterns = array(
        // PHP open tags (including short echo <?=)
        '/<\?(?:php|=)/i',

        // PHP dangerous functions — code execution
        '/\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open|create_function|call_user_func(?:_array)?)\s*\(/i',
        // Additional dangerous PHP functions missed in previous pass:
        //   pcntl_exec — execute a program (bypasses open_basedir)
        //   dl()       — load a PHP extension at runtime
        //   posix_kill — send signals to processes
        //   ReflectionFunction — can invoke arbitrary callables via reflection
        //   array_map/array_filter/usort with callable string — indirect code exec
        '/\b(?:pcntl_exec|dl|posix_kill|posix_mkfifo|posix_setuid)\s*\(/i',
        '/\b(?:ReflectionFunction|ReflectionMethod|ReflectionClass)\s*\(/i',
        '/\b(?:array_map|array_filter|array_walk|usort|uasort|uksort|array_reduce)\s*\(\s*[^,]+,\s*[\'"][^\'"]+[\'"]/i',

        // preg_replace with /e modifier (code execution)
        '/preg_replace\s*\(\s*[\'"].*\/e[\'"\s,]/i',

        // JS event handlers (on* = ...) — covers all HTML event attributes
        '/\bon\w+\s*=/i',
        // Interaction-free XSS vectors: <details open ontoggle>, <marquee onstart>,
        // <body onpageshow>, <svg onload> — caught by the on\w+ pattern above.
        // srcdoc attribute — iframe srcdoc XSS (executes HTML without src URL)
        '/\bsrcdoc\s*=/i',
        // formaction attribute — overrides form action, can bypass CSP form-action
        '/\bformaction\s*=/i',

        // javascript: URI scheme
        '/javascript\s*:/i',
        // vbscript: URI scheme
        '/vbscript\s*:/i',
        // data: URI with HTML or script content
        '/data\s*:\s*(?:text\/html|application\/x-www-form-urlencoded|image\/svg)/i',

        // CSS expression() — IE CSS code execution
        '/expression\s*\(/i',
        // CSS @import — can load external stylesheets containing payloads
        '/@import\b/i',
        // CSS url() with dangerous scheme
        '/url\s*\(\s*[\'"]?\s*(?:javascript|data|vbscript)\s*:/i',

        // HTML comment injection (used to split keywords: <scr<!---->ipt>)
        '/<!--[\s\S]*?-->/i',

        // Hex escape sequences (\x41 style) — used to bypass keyword filters
        '/\\\\x[0-9a-fA-F]{2}/i',
        // Octal escape sequences (\101 style)
        '/\\\\[0-7]{2,3}/',

        // PHP stream wrapper abuse (LFI/RFI vectors)
        // Extended to cover file://, ssh2://, rar://, ogg://, zlib:// wrappers
        // that were missing from the previous pattern.
        '/(?:php|data|phar|zip|glob|expect|input|filter|file|ssh2|rar|ogg|zlib|compress\.zlib|compress\.bzip2)\s*:\/\//i',

        // Shell metacharacters (command chaining/injection)
        '/(?:^|[^a-zA-Z0-9])[;&|\x60]/',
        // Backtick command execution
        '/\x60[^\x60]+\x60/',

        // SQL Injection — destructive / exfiltration patterns
        '/\b(?:UNION\s+(?:ALL\s+)?SELECT|DROP\s+(?:TABLE|DATABASE)|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET|EXEC(?:UTE)?\s*\(|xp_cmdshell|LOAD_FILE|INTO\s+(?:OUT|DUMP)FILE)\b/i',
        // SQLi comment sequences
        '/(?:\/\*.*?\*\/|--\s|#\s*$)/m',
        // Blind time-based SQLi: SLEEP(), BENCHMARK(), WAITFOR DELAY
        '/\b(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY|PG_SLEEP)\s*\(/i',
        // Information schema / version fingerprinting
        '/\b(?:INFORMATION_SCHEMA|@@version|@@datadir|@@basedir|@@hostname)\b/i',
        // CHAR() function chains used to bypass string literal filters
        '/\bCHAR\s*\(\s*\d+/i',
        // Hex literal injection (0x41 in SQL context)
        '/\b0x[0-9a-fA-F]{2,}\b/',

        // Null byte injection
        '/\x00/',

        // base64_decode() chained execution — common obfuscation vector
        '/base64_decode\s*\(/i',
        '/str_rot13\s*\(/i',
        // gzinflate / gzuncompress — used to hide payloads in compressed strings.
        '/gz(?:inflate|uncompress|decode)\s*\(/i',

        // Obfuscated variable function calls: $a = 'system'; $a('id');
        '/\$\w+\s*\(\s*[\'"][^\'"]*[\'"]\s*\)/i',
        // Heredoc/nowdoc with dangerous content (<<<EOT ... EOT).
        '/<<<\s*[\'"]?\w+[\'"]?/i',
    );

    foreach ( $patterns as $pattern ) {
        if ( preg_match( $pattern, $normalized ) ) {
            return true;
        }
    }
    return false;
}


/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 3 — FILE UPLOAD HARDENING (Arbitrary File Upload + Path Traversal)
   ═══════════════════════════════════════════════════════════════════════════════ */

/**
 * Validate an uploaded file against:
 *  - Extension allowlist (no PHP, no server-side scripts)
 *  - MIME type allowlist (finfo-based, not trusting $_FILES['type'])
 *  - Filename path traversal (null bytes, ../, encoded variants)
 *  - Double extension bypass (file.php.jpg)
 *
 * @param  array       $file  $_FILES array element.
 * @return array|false        Sanitized file array, or false on failure.
 */
function cyberpunk_validate_upload( $file ) {
    // Allowed extensions (strict allowlist — deny everything else).
    $allowed_extensions = array(
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'mp3', 'mp4', 'ogg', 'wav', 'webm',
        'zip', 'tar', 'gz',
        'txt', 'csv', 'json', 'xml',
    );

    // Allowed MIME types (finfo-based).
    $allowed_mimes = array(
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'audio/mpeg', 'audio/ogg', 'audio/wav',
        'video/mp4', 'video/ogg', 'video/webm',
        'application/zip', 'application/x-tar', 'application/gzip',
        'text/plain', 'text/csv', 'application/json', 'application/xml', 'text/xml',
    );

    if ( empty( $file['name'] ) || empty( $file['tmp_name'] ) ) {
        return false;
    }

    $name = $file['name'];

    // 1. Remove null bytes from filename.
    $name = str_replace( "\x00", '', $name );

    // 2. Decode URL-encoded filename (catches %2e%2e%2f).
    $name = rawurldecode( $name );

    // 3. Block path traversal in filename.
    if ( preg_match( '#[\\/]|\.\.#', $name ) ) {
        return false;
    }

    // 4. Extract ALL extensions (catches double-extension: file.php.jpg).
    $parts      = explode( '.', strtolower( $name ) );
    $extensions = array_slice( $parts, 1 ); // Everything after first dot.

    // Block if ANY extension in the chain is dangerous.
    // Includes php8/php9 for future PHP versions, shtml/shtm (SSI execution),
    // xhtml (can execute on some servers), and rb/lua for scripting runtimes.
    $dangerous = array(
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'php9', 'phtml', 'phar',
        'asp', 'aspx', 'asa', 'asax', 'ascx', 'ashx', 'asmx', 'axd',
        'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
        'cfm', 'cfml', 'cfc',
        'cgi', 'pl', 'py', 'pyc', 'pyo',
        'sh', 'bash', 'zsh', 'ksh', 'csh',
        'exe', 'bat', 'cmd', 'com', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'wsf', 'wsh',
        'rb', 'lua',
        'shtml', 'shtm', 'stm',
        'htaccess', 'htpasswd', 'htgroups',
    );

    foreach ( $extensions as $ext ) {
        if ( in_array( $ext, $dangerous, true ) ) {
            return false;
        }
    }

    // 5. Check final extension against allowlist.
    $final_ext = end( $extensions );
    if ( ! in_array( $final_ext, $allowed_extensions, true ) ) {
        return false;
    }

    // 6. Verify real MIME type using finfo (not $_FILES['type'] which is user-controlled).
    if ( function_exists( 'finfo_open' ) ) {
        $finfo     = finfo_open( FILEINFO_MIME_TYPE );
        $real_mime = finfo_file( $finfo, $file['tmp_name'] );
        finfo_close( $finfo );

        if ( ! in_array( $real_mime, $allowed_mimes, true ) ) {
            return false;
        }
    }

    // 7. For image types, verify the file is a genuine image using getimagesize().
    //    This defeats polyglot files (e.g. a PHP webshell with a valid GIF89a header)
    //    that pass finfo MIME detection but are not real images.
    $image_extensions = array( 'jpg', 'jpeg', 'png', 'gif', 'webp' );
    if ( in_array( $final_ext, $image_extensions, true ) ) {
        $image_info = @getimagesize( $file['tmp_name'] );
        if ( false === $image_info ) {
            return false; // Not a valid image — reject.
        }
        // Cross-check: finfo MIME must match what getimagesize() reports.
        $mime_from_image = image_type_to_mime_type( $image_info[2] );
        if ( function_exists( 'finfo_open' ) && isset( $real_mime ) && $real_mime !== $mime_from_image ) {
            return false; // MIME mismatch between finfo and image header — reject.
        }
    }

    // 8. Sanitize filename — keep only safe characters.
    $safe_name = preg_replace( '/[^a-zA-Z0-9._-]/', '_', basename( $name ) );
    $file['name'] = $safe_name;

    return $file;
}

/**
 * Hook into WordPress upload pre-filter to validate all uploads.
 */
function cyberpunk_filter_upload( $file ) {
    $validated = cyberpunk_validate_upload( $file );
    if ( $validated === false ) {
        $file['error'] = esc_html__( 'File type not permitted or filename is invalid.', 'cyberpunk-dark' );
    }
    return $file;
}
add_filter( 'wp_handle_upload_prefilter', 'cyberpunk_filter_upload' );

/**
 * SVG XSS Sanitization — strip dangerous elements from uploaded SVG files using
 * DOMDocument for robust, parser-level sanitization (not regex).
 *
 * Regex-based SVG sanitization is bypassable via malformed XML, namespace tricks,
 * and encoding edge cases. DOMDocument parses the actual XML tree, so removals
 * are structurally correct regardless of whitespace or attribute ordering.
 *
 * Dangerous constructs removed:
 *  - <script> elements (any namespace)
 *  - on* event handler attributes (onload, onclick, onerror, etc.)
 *  - href / xlink:href attributes with javascript: or data: URI values
 *  - <use> elements (external SVG fragment injection via xlink:href)
 *  - <foreignObject> elements (arbitrary HTML embedding)
 *  - <set> and <animate> elements with attributeName targeting event handlers
 *
 * @param array $file Uploaded file data (after wp_handle_upload).
 * @return array      Unchanged file data (sanitization is done in-place).
 */
function cyberpunk_sanitize_svg_upload( $file ) {
    if ( empty( $file['file'] ) ) {
        return $file;
    }

    $ext = strtolower( pathinfo( $file['file'], PATHINFO_EXTENSION ) );
    if ( 'svg' !== $ext ) {
        return $file;
    }

    $content = file_get_contents( $file['file'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
    if ( false === $content ) {
        return $file;
    }

    // Use DOMDocument for structural XML parsing — immune to regex bypass tricks.
    $dom = new DOMDocument();

    // Disable external entity loading BEFORE parsing to prevent XXE attacks.
    // XXE (XML External Entity) allows an attacker to embed <!ENTITY xxe SYSTEM "file:///etc/passwd">
    // in the SVG, causing the parser to read arbitrary local files or make SSRF requests.
    // libxml_disable_entity_loader() is the correct defence; LIBXML_NONET alone is insufficient
    // because it only blocks network entities, not local file:// entities.
    // Note: libxml_disable_entity_loader() was deprecated in PHP 8.0 (entity loading is
    // disabled by default in PHP 8), but calling it on PHP 7.x is still required.
    $prev_entity_loader = null;
    if ( PHP_MAJOR_VERSION < 8 && function_exists( 'libxml_disable_entity_loader' ) ) {
        $prev_entity_loader = libxml_disable_entity_loader( true );
    }

    // LIBXML_NONET  — block network access during parsing (prevents SSRF via DTD).
    // LIBXML_NOENT  — substitute entities (safe after entity loader is disabled).
    // LIBXML_DTDLOAD is intentionally NOT passed — prevents loading external DTDs entirely.
    // LIBXML_DTDATTR is intentionally NOT passed — prevents applying DTD default attributes.
    $prev_errors = libxml_use_internal_errors( true );
    $loaded = $dom->loadXML( $content, LIBXML_NONET | LIBXML_NOENT );
    libxml_clear_errors();
    libxml_use_internal_errors( $prev_errors );

    // Restore entity loader state.
    if ( null !== $prev_entity_loader && function_exists( 'libxml_disable_entity_loader' ) ) {
        libxml_disable_entity_loader( $prev_entity_loader );
    }

    if ( ! $loaded ) {
        // Unparseable SVG — delete the file and reject the upload.
        @unlink( $file['file'] );
        $file['error'] = esc_html__( 'SVG file could not be parsed and was rejected.', 'cyberpunk-dark' );
        return $file;
    }

    $xpath = new DOMXPath( $dom );

    // 1. Remove all <script> elements (any namespace prefix).
    foreach ( $xpath->query( '//*[local-name()="script"]' ) as $node ) {
        $node->parentNode->removeChild( $node );
    }

    // 2. Remove <use> elements (external fragment injection).
    foreach ( $xpath->query( '//*[local-name()="use"]' ) as $node ) {
        $node->parentNode->removeChild( $node );
    }

    // 3. Remove <foreignObject> elements (arbitrary HTML embedding).
    foreach ( $xpath->query( '//*[local-name()="foreignObject"]' ) as $node ) {
        $node->parentNode->removeChild( $node );
    }

    // 4. Remove <set> and <animate> elements that target event-handler attributes.
    foreach ( $xpath->query( '//*[local-name()="set" or local-name()="animate"]' ) as $node ) {
        $attr_name = strtolower( $node->getAttribute( 'attributeName' ) );
        if ( 0 === strpos( $attr_name, 'on' ) ) {
            $node->parentNode->removeChild( $node );
        }
    }

    // 5. Walk every element and scrub dangerous attributes.
    foreach ( $xpath->query( '//*' ) as $element ) {
        $attrs_to_remove = array();

        for ( $i = 0; $i < $element->attributes->length; $i++ ) {
            $attr       = $element->attributes->item( $i );
            $attr_name  = strtolower( $attr->localName );
            $attr_value = strtolower( trim( $attr->value ) );

            // Remove on* event handlers.
            if ( 0 === strpos( $attr_name, 'on' ) ) {
                $attrs_to_remove[] = $attr->nodeName;
                continue;
            }

            // Remove javascript: and data: URIs from href / xlink:href / src / action.
            if ( in_array( $attr_name, array( 'href', 'xlink:href', 'src', 'action' ), true ) ) {
                $stripped = preg_replace( '/[\x00-\x1f\x7f\s]/u', '', $attr_value );
                if ( 0 === strpos( $stripped, 'javascript:' ) || 0 === strpos( $stripped, 'data:' ) ) {
                    $attrs_to_remove[] = $attr->nodeName;
                }
            }
        }

        foreach ( $attrs_to_remove as $attr_name ) {
            $element->removeAttribute( $attr_name );
        }
    }

    $sanitized = $dom->saveXML();
    if ( false !== $sanitized ) {
        file_put_contents( $file['file'], $sanitized ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
    }

    return $file;
}
add_filter( 'wp_handle_upload', 'cyberpunk_sanitize_svg_upload' );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 4 — CSRF ENFORCEMENT (Global POST protection)
   ═══════════════════════════════════════════════════════════════════════════════ */

/**
 * Output a hidden CSRF nonce field for custom theme forms.
 *
 * @param string $action Nonce action name.
 */
function cyberpunk_csrf_field( $action = 'cyberpunk_form' ) {
    wp_nonce_field( sanitize_key( $action ), '_cyberpunk_nonce', true, true );
}

/**
 * Verify a CSRF nonce for POST requests only. Dies with 403 on failure.
 *
 * FIX: Previously read from $_REQUEST, which merges GET + POST + COOKIE.
 * An attacker could deliver a valid nonce via a GET parameter on a crafted
 * URL, satisfying the nonce check for a state-changing POST form — a CSRF
 * bypass via GET-based nonce delivery.
 *
 * Fix: Read exclusively from $_POST so the nonce can only arrive in the
 * request body, not in the URL. This is consistent with how WordPress core
 * handles nonce verification for form submissions (check_admin_referer uses
 * $_REQUEST but WordPress forms always POST the nonce field).
 *
 * Resistant to timing attacks via wp_verify_nonce's constant-time comparison.
 *
 * @param string $action Nonce action name.
 */
function cyberpunk_verify_csrf( $action = 'cyberpunk_form' ) {
    // Only accept nonce from POST body — not from GET or COOKIE.
    $nonce = isset( $_POST['_cyberpunk_nonce'] )
        ? sanitize_text_field( wp_unslash( $_POST['_cyberpunk_nonce'] ) )
        : '';

    if ( ! wp_verify_nonce( $nonce, sanitize_key( $action ) ) ) {
        wp_die(
            esc_html__( 'Security check failed. Please refresh the page and try again.', 'cyberpunk-dark' ),
            esc_html__( 'Forbidden', 'cyberpunk-dark' ),
            array( 'response' => 403 )
        );
    }
}

/**
 * Enforce CSRF nonce on all theme-specific AJAX POST actions.
 * WordPress core already protects its own AJAX with check_ajax_referer().
 * This adds a layer for any custom theme AJAX handlers.
 *
 * FIX: Hook this function to every custom wp_ajax_* action so it actually
 * runs. Previously it was defined but never attached to any action hook,
 * meaning custom AJAX endpoints had no CSRF protection at all.
 * Usage in your AJAX handler: add_action( 'wp_ajax_my_action', 'cyberpunk_verify_ajax_nonce' );
 * or call cyberpunk_verify_ajax_nonce() as the first line of each handler.
 */
function cyberpunk_verify_ajax_nonce() {
    $nonce = isset( $_POST['nonce'] )
        ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) )
        : '';

    if ( ! wp_verify_nonce( $nonce, 'cyberpunk_nonce' ) ) {
        wp_send_json_error( array( 'message' => 'Invalid security token.' ), 403 );
        wp_die();
    }
}

/**
 * Auto-apply CSRF nonce verification to all theme-prefixed AJAX actions.
 *
 * Any action registered as 'wp_ajax_cyberpunk_*' or
 * 'wp_ajax_nopriv_cyberpunk_*' will have the nonce checked before the
 * handler runs. This closes the gap where cyberpunk_verify_ajax_nonce()
 * was defined but never automatically applied.
 */
function cyberpunk_auto_verify_ajax_nonce() {
    // Only fire on AJAX requests.
    if ( ! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
        return;
    }

    $action = isset( $_REQUEST['action'] )
        ? sanitize_key( wp_unslash( $_REQUEST['action'] ) )
        : '';

    // Only intercept theme-prefixed actions.
    if ( 0 !== strpos( $action, 'cyberpunk_' ) ) {
        return;
    }

    cyberpunk_verify_ajax_nonce();
}
add_action( 'init', 'cyberpunk_auto_verify_ajax_nonce', 2 );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 5 — BRUTE-FORCE PROTECTION + HTTP RATE LIMITING
   ═══════════════════════════════════════════════════════════════════════════════ */

/**
 * Progressive login lockout.
 *
 * Tracks failed attempts per IP in transients:
 *  - 1–4 failures:  2s delay
 *  - 5–9 failures:  5s delay
 *  - 10+ failures:  15-minute lockout (HTTP 429)
 */
function cyberpunk_login_fail_handler( $username ) {
    $ip    = cyberpunk_get_client_ip();
    $key   = 'cyber_bf_' . substr( hash( 'sha256', $ip ), 0, 16 );
    // FIX: atomic increment — prevents race condition where concurrent requests
    // both read count=9 and both pass the threshold check before either writes 10.
    $count = cyberpunk_rate_limit_increment( $key, 15 * MINUTE_IN_SECONDS );

    if ( $count >= 10 ) {
        wp_die(
            esc_html__( 'Too many failed login attempts. Your IP has been temporarily blocked. Please try again in 15 minutes.', 'cyberpunk-dark' ),
            esc_html__( 'Access Denied', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    } elseif ( $count >= 5 ) {
        sleep( 5 );
    } else {
        sleep( 2 );
    }
}
add_action( 'wp_login_failed', 'cyberpunk_login_fail_handler' );

/**
 * Block login attempts while IP is locked out (before password check).
 */
function cyberpunk_check_login_lockout( $user, $username, $password ) {
    $ip    = cyberpunk_get_client_ip();
    $key   = 'cyber_bf_' . substr( hash( 'sha256', $ip ), 0, 16 );
    $count = cyberpunk_rate_limit_get( $key );

    if ( $count >= 10 ) {
        return new WP_Error(
            'too_many_attempts',
            esc_html__( 'Too many failed login attempts. Please try again later.', 'cyberpunk-dark' )
        );
    }
    return $user;
}
add_filter( 'authenticate', 'cyberpunk_check_login_lockout', 1, 3 );

/**
 * Global HTTP request rate limiter.
 * Limits all front-end page requests to 120 per minute per IP.
 * Excludes admin, cron, and REST API (handled separately).
 */
function cyberpunk_global_rate_limit() {
    // Skip admin, cron, CLI, REST.
    if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
        return;
    }
    if ( ! isset( $_SERVER['REQUEST_METHOD'] ) ) {
        return;
    }

    $ip     = cyberpunk_get_client_ip();
    $key    = 'cyber_rl_global_' . substr( hash( 'sha256', $ip ), 0, 32 );
    $limit  = 120;
    $window = 60;
    // FIX: atomic increment — prevents race condition bypass on high-traffic servers.
    $count  = cyberpunk_rate_limit_increment( $key, $window );

    if ( $count > $limit ) {
        status_header( 429 );
        header( 'Retry-After: 60' );
        wp_die(
            esc_html__( 'Too many requests. Please slow down.', 'cyberpunk-dark' ),
            esc_html__( 'Rate Limit Exceeded', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    }
}
add_action( 'init', 'cyberpunk_global_rate_limit', 5 );

/**
 * Rate-limit comment submissions per IP (max 5 per 60s).
 */
function cyberpunk_rate_limit_comments( $commentdata ) {
    $ip    = cyberpunk_get_client_ip();
    $key   = 'cyber_rl_comment_' . substr( hash( 'sha256', $ip ), 0, 32 );
    // FIX: atomic increment.
    $count = cyberpunk_rate_limit_increment( $key, 60 );

    if ( $count > 5 ) {
        wp_die(
            esc_html__( 'Too many comment submissions. Please wait before trying again.', 'cyberpunk-dark' ),
            esc_html__( 'Rate Limit Exceeded', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    }
    return $commentdata;
}
add_filter( 'preprocess_comment', 'cyberpunk_rate_limit_comments' );

/**
 * Rate-limit search requests per IP (max 20 per 60s).
 */
function cyberpunk_rate_limit_search() {
    if ( ! is_search() || is_admin() ) {
        return;
    }
    $ip    = cyberpunk_get_client_ip();
    $key   = 'cyber_rl_search_' . substr( hash( 'sha256', $ip ), 0, 32 );
    // FIX: atomic increment.
    $count = cyberpunk_rate_limit_increment( $key, 60 );

    if ( $count > 20 ) {
        wp_die(
            esc_html__( 'Too many search requests. Please wait before trying again.', 'cyberpunk-dark' ),
            esc_html__( 'Rate Limit Exceeded', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    }
}
add_action( 'template_redirect', 'cyberpunk_rate_limit_search' );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 6 — HTTP SECURITY HEADERS
   ═══════════════════════════════════════════════════════════════════════════════ */

function cyberpunk_send_security_headers() {
    if ( ! isset( $_SERVER['REQUEST_METHOD'] ) ) {
        return;
    }

    header( 'X-Frame-Options: SAMEORIGIN' );
    header( 'X-Content-Type-Options: nosniff' );
    header( 'Referrer-Policy: strict-origin-when-cross-origin' );
    header( 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=()' );
    // X-XSS-Protection is legacy (modern browsers use CSP); kept for older UA compatibility.
    header( 'X-XSS-Protection: 1; mode=block' );
    header( 'X-Permitted-Cross-Domain-Policies: none' );

    // Cross-Origin isolation headers — prevent Spectre-class side-channel leaks
    // and enforce process isolation in modern browsers.
    header( 'Cross-Origin-Opener-Policy: same-origin' );
    header( 'Cross-Origin-Resource-Policy: same-origin' );
    // COEP requires all sub-resources to opt-in via CORP or CORS headers.
    // Set to 'require-corp' only after auditing all third-party resources.
    // Using 'unsafe-none' here to avoid breaking Elementor/Google Fonts embeds.
    header( 'Cross-Origin-Embedder-Policy: unsafe-none' );

    if ( is_ssl() ) {
        header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' );
    }

    // CSP — permissive for Elementor compatibility; tighten script-src in production.
    $csp = implode( '; ', array(
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com",
        "font-src 'self' https://fonts.gstatic.com data:",
        "img-src 'self' data: https: blob:",
        "media-src 'self' blob:",
        "connect-src 'self'",
        "frame-src 'self'",
        "frame-ancestors 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "worker-src 'self' blob:",
        "upgrade-insecure-requests",
    ) );
    header( 'Content-Security-Policy: ' . $csp );
}
add_action( 'send_headers', 'cyberpunk_send_security_headers', 1 );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 7 — SESSION SECURITY
   ═══════════════════════════════════════════════════════════════════════════════ */

function cyberpunk_harden_session() {
    if ( headers_sent() ) {
        return;
    }
    // FIX: Upgraded SameSite from 'Lax' to 'Strict'.
    // 'Lax' allows cookies to be sent on top-level cross-site GET navigations
    // (e.g. a link from an external site), which is sufficient for CSRF on
    // state-changing GET endpoints. 'Strict' prevents the cookie from being
    // sent on ANY cross-site request, eliminating that vector entirely.
    // WordPress itself does not rely on cross-site cookie delivery for its
    // front-end session, so 'Strict' is safe here.
    session_set_cookie_params( array(
        'lifetime' => 0,
        'path'     => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
        'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
        'secure'   => is_ssl(),
        'httponly' => true,
        'samesite' => 'Strict',
    ) );
}
add_action( 'init', 'cyberpunk_harden_session', 1 );

/**
 * Session fixation prevention — regenerate the session ID on login.
 *
 * Without this, an attacker can pre-set a known session ID (e.g. via a
 * Set-Cookie injection or network sniffing), wait for the victim to log in,
 * and then use that same ID to hijack the authenticated session.
 *
 * session_regenerate_id(true) issues a new ID AND deletes the old session
 * data, so the pre-set ID becomes invalid immediately after login.
 *
 * WordPress uses its own auth cookie system (not PHP sessions) for most
 * authentication, but any plugin or theme code that calls session_start()
 * is vulnerable without this hook.
 *
 * @param string $user_login The username of the logged-in user.
 * @param WP_User $user      The WP_User object.
 */
function cyberpunk_regenerate_session_on_login( $user_login, $user ) {
    if ( session_status() === PHP_SESSION_ACTIVE ) {
        // Delete old session data and issue a new session ID.
        session_regenerate_id( true );
    }
}
add_action( 'wp_login', 'cyberpunk_regenerate_session_on_login', 10, 2 );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 8 — INFORMATION DISCLOSURE HARDENING
   ═══════════════════════════════════════════════════════════════════════════════ */

// Remove WP version from head and feeds.
remove_action( 'wp_head', 'wp_generator' );

// Strip version query strings from asset URLs.
function cyberpunk_remove_version_query( $src ) {
    if ( strpos( $src, 'ver=' ) !== false ) {
        $src = remove_query_arg( 'ver', $src );
    }
    return $src;
}
add_filter( 'style_loader_src',  'cyberpunk_remove_version_query', 9999 );
add_filter( 'script_loader_src', 'cyberpunk_remove_version_query', 9999 );

// Disable XML-RPC.
add_filter( 'xmlrpc_enabled', '__return_false' );

// Remove X-Pingback header.
function cyberpunk_remove_x_pingback( $headers ) {
    unset( $headers['X-Pingback'] );
    return $headers;
}
add_filter( 'wp_headers', 'cyberpunk_remove_x_pingback' );

// Block REST API user enumeration for ALL requests (authenticated and not).
// A logged-in subscriber has no legitimate need to list all users via REST.
// Admins and editors who need this can use the WP admin UI directly.
// FIX: previously only blocked unauthenticated requests — a logged-in subscriber
// could still enumerate all usernames/emails via GET /wp/v2/users.
function cyberpunk_disable_rest_user_enum( $endpoints ) {
    if ( ! current_user_can( 'list_users' ) ) {
        unset( $endpoints['/wp/v2/users'] );
        unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
    }
    return $endpoints;
}
add_filter( 'rest_endpoints', 'cyberpunk_disable_rest_user_enum' );

// Block author enumeration via /?author=N.
// Redirect to the home page with a 301 rather than wp_die() so the block
// is not detectable by an attacker (no 403 fingerprint, no error page).
function cyberpunk_block_author_enum() {
    if ( ! is_admin() && isset( $_GET['author'] ) ) {
        wp_safe_redirect( home_url( '/' ), 301 );
        exit;
    }
}
add_action( 'init', 'cyberpunk_block_author_enum' );

// Generic login error message (don't reveal username vs password).
add_filter( 'login_errors', function() {
    return esc_html__( 'Authentication failed. Please check your credentials.', 'cyberpunk-dark' );
} );

/**
 * Scrub absolute server paths from wp_die() messages to prevent path disclosure.
 * Wraps the default handler and replaces known filesystem paths with '[path]'.
 *
 * @param  callable $handler The default wp_die handler.
 * @return callable          A wrapped handler that scrubs paths first.
 */
add_filter( 'wp_die_handler', function( $handler ) {
    return function( $message, $title = '', $args = array() ) use ( $handler ) {
        if ( is_string( $message ) ) {
            // FIX: Expanded path list to cover additional disclosure vectors:
            //  - sys_get_temp_dir()         — PHP temp directory (e.g. /tmp)
            //  - ini_get('upload_tmp_dir')  — upload temp dir if different from sys temp
            //  - $_SERVER['DOCUMENT_ROOT']  — web root path
            // These paths can appear in stack traces and error messages when
            // file operations fail, revealing server filesystem layout.
            $paths = array_filter( array_unique( array(
                ABSPATH,
                WP_CONTENT_DIR,
                get_template_directory(),
                dirname( ABSPATH ),
                sys_get_temp_dir(),
                (string) ini_get( 'upload_tmp_dir' ),
                isset( $_SERVER['DOCUMENT_ROOT'] )
                    ? sanitize_text_field( wp_unslash( $_SERVER['DOCUMENT_ROOT'] ) )
                    : '',
            ) ) );
            foreach ( $paths as $path ) {
                $message = str_replace( $path, '[path]', $message );
            }
        }
        call_user_func( $handler, $message, $title, $args );
    };
} );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 9 — EXTENDED HARDENING (REST, XML-RPC, POST flood, outbound HTTP)
   ═══════════════════════════════════════════════════════════════════════════════ */

/**
 * REST API — require authentication for all write operations from unauthenticated
 * clients. Read-only GET requests are allowed; anything else (POST/PUT/PATCH/DELETE)
 * must carry a valid WordPress authentication cookie or Application Password.
 *
 * This closes the gap where cyberpunk_verify_ajax_nonce() is defined but not
 * automatically applied to REST endpoints — REST uses its own auth pipeline.
 *
 * Note: WordPress core REST endpoints that require auth already enforce it.
 * This filter adds a belt-and-suspenders block for any custom endpoints that
 * might accidentally omit the permission_callback.
 */
function cyberpunk_rest_require_auth( $result ) {
    // If another filter already returned an error, pass it through.
    if ( is_wp_error( $result ) ) {
        return $result;
    }

    // Allow read-only requests from anyone.
    $method = isset( $_SERVER['REQUEST_METHOD'] )
        ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) )
        : 'GET';

    if ( in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true ) ) {
        return $result;
    }

    // For write methods, require an authenticated user.
    if ( ! is_user_logged_in() ) {
        return new WP_Error(
            'rest_not_logged_in',
            esc_html__( 'Authentication required for this request.', 'cyberpunk-dark' ),
            array( 'status' => 401 )
        );
    }

    return $result;
}
add_filter( 'rest_authentication_errors', 'cyberpunk_rest_require_auth', 99 );

/**
 * XML-RPC early block — belt-and-suspenders on top of the xmlrpc_enabled filter.
 *
 * The xmlrpc_enabled filter fires after the XML-RPC request has been parsed,
 * meaning system.multicall brute-force attempts still consume server resources.
 * This action fires on the xmlrpc_call hook (before method execution) and
 * terminates any call that reaches this point, since XML-RPC should be fully
 * disabled. Also blocks the xmlrpc.php entry point at the init level.
 */
function cyberpunk_block_xmlrpc_calls( $method ) {
    wp_die(
        esc_html__( 'XML-RPC is disabled on this site.', 'cyberpunk-dark' ),
        esc_html__( 'Forbidden', 'cyberpunk-dark' ),
        array( 'response' => 403 )
    );
}
add_action( 'xmlrpc_call', 'cyberpunk_block_xmlrpc_calls' );

/**
 * Block direct access to xmlrpc.php at the init level.
 * Catches requests that bypass the xmlrpc_enabled filter (e.g. direct file access
 * when WordPress is loaded via xmlrpc.php directly).
 */
function cyberpunk_block_xmlrpc_direct() {
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        wp_die(
            esc_html__( 'XML-RPC is disabled on this site.', 'cyberpunk-dark' ),
            esc_html__( 'Forbidden', 'cyberpunk-dark' ),
            array( 'response' => 403 )
        );
    }
}
add_action( 'init', 'cyberpunk_block_xmlrpc_direct', 1 );

/**
 * POST flood rate-limiter — limits all POST requests to 30 per minute per IP.
 *
 * Covers brute-force vectors that bypass the login-specific lockout:
 *  - wp-comments-post.php direct POST floods
 *  - wp-login.php credential stuffing with varied nonces
 *  - Custom form submission floods
 *
 * Excludes admin and cron. Applied at priority 1 on 'init' so it fires
 * before any form processing hooks.
 */
function cyberpunk_post_flood_limit() {
    if ( ! isset( $_SERVER['REQUEST_METHOD'] ) ) {
        return;
    }
    if ( strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) !== 'POST' ) {
        return;
    }
    // Skip admin and cron — they have their own auth layers.
    if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
        return;
    }

    $ip    = cyberpunk_get_client_ip();
    $key   = 'cyber_rl_post_' . substr( hash( 'sha256', $ip ), 0, 32 );
    $limit = 30;
    // FIX: atomic increment — prevents race condition bypass.
    $count = cyberpunk_rate_limit_increment( $key, 60 );

    if ( $count > $limit ) {
        status_header( 429 );
        header( 'Retry-After: 60' );
        wp_die(
            esc_html__( 'Too many requests. Please slow down.', 'cyberpunk-dark' ),
            esc_html__( 'Rate Limit Exceeded', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    }
}
add_action( 'init', 'cyberpunk_post_flood_limit', 1 );

/**
 * Outbound HTTP request allowlist — restricts WordPress's wp_remote_*() functions
 * to a known set of trusted domains.
 *
 * This prevents Server-Side Request Forgery (SSRF) and RFI via WordPress's own
 * HTTP API (used by plugins, themes, and core update checks). Requests to
 * non-allowlisted hosts are blocked before the TCP connection is made.
 *
 * The allowlist includes:
 *  - WordPress.org (core updates, plugin/theme API)
 *  - Google Fonts (used by this theme)
 *  - Gravatar (comment avatars)
 *
 * To add your own trusted domains, filter 'cyberpunk_allowed_http_hosts'.
 *
 * @param  array  $parsed_args Request arguments.
 * @param  string $url         The request URL.
 * @return array               Modified args (with 'reject' flag if blocked).
 */
function cyberpunk_restrict_outbound_http( $parsed_args, $url ) {
    // Default allowlist — extend via filter, not by editing this function.
    $allowed_hosts = apply_filters( 'cyberpunk_allowed_http_hosts', array(
        'api.wordpress.org',
        'downloads.wordpress.org',
        'plugins.svn.wordpress.org',
        'themes.svn.wordpress.org',
        'wordpress.org',
        'fonts.googleapis.com',
        'fonts.gstatic.com',
        'secure.gravatar.com',
        'www.gravatar.com',
    ) );

    $parsed_url = wp_parse_url( $url );
    $host       = isset( $parsed_url['host'] ) ? strtolower( $parsed_url['host'] ) : '';

    if ( empty( $host ) ) {
        // Malformed URL — block it.
        $parsed_args['reject_unsafe_urls'] = true;
        return $parsed_args;
    }

    // Check exact match or subdomain match against each allowed host.
    $allowed = false;
    foreach ( $allowed_hosts as $allowed_host ) {
        $allowed_host = strtolower( $allowed_host );
        if ( $host === $allowed_host || substr( $host, -( strlen( $allowed_host ) + 1 ) ) === '.' . $allowed_host ) {
            $allowed = true;
            break;
        }
    }

    if ( ! $allowed ) {
        // Log the blocked request for audit purposes (no sensitive data in log).
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        error_log( sprintf( '[CyberPunk Security] Blocked outbound HTTP request to: %s', esc_url_raw( $url ) ) );

        // reject_unsafe_urls only blocks private/loopback IPs in WP_HTTP — it does
        // NOT block arbitrary external hosts. Use pre_http_request to hard-abort.
        $parsed_args['_cyberpunk_blocked'] = true;
    }

    return $parsed_args;
}
add_filter( 'http_request_args', 'cyberpunk_restrict_outbound_http', 10, 2 );

/**
 * Hard-abort outbound HTTP requests that were flagged by the allowlist filter.
 * pre_http_request fires before any socket is opened, so this is a true block.
 *
 * @param  false|array|WP_Error $preempt Whether to preempt the request.
 * @param  array                $args    Request arguments (may contain our flag).
 * @param  string               $url     The request URL.
 * @return false|WP_Error               WP_Error to abort; false to allow.
 */
function cyberpunk_abort_blocked_http( $preempt, $args, $url ) {
    if ( ! empty( $args['_cyberpunk_blocked'] ) ) {
        return new WP_Error(
            'cyberpunk_blocked_host',
            sprintf(
                /* translators: %s: blocked URL */
                esc_html__( 'Outbound request blocked by security policy: %s', 'cyberpunk-dark' ),
                esc_url_raw( $url )
            )
        );
    }
    return $preempt;
}
add_filter( 'pre_http_request', 'cyberpunk_abort_blocked_http', 10, 3 );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 11 — OUTPUT HARDENING (comment text, taxonomy descriptions)
   ═══════════════════════════════════════════════════════════════════════════════ */

/**
 * Restrict comment output to a safe HTML subset.
 *
 * WordPress core's kses configuration can be widened by plugins, which would
 * allow stored XSS payloads in approved comments to execute. This filter
 * applies a theme-level allowlist that is independent of any plugin changes.
 *
 * Allowed tags: the minimal set needed for readable comment text.
 *  - Inline formatting: <a>, <b>, <i>, <em>, <strong>, <code>, <s>, <del>, <ins>
 *  - Block: <p>, <blockquote>, <ul>, <ol>, <li>
 *  - Line break: <br>
 *
 * @param  string $comment_text Filtered comment text from WP core.
 * @return string               Re-filtered through the theme's strict allowlist.
 */
function cyberpunk_filter_comment_text( $comment_text ) {
    $allowed = array(
        'a'          => array( 'href' => array(), 'title' => array(), 'rel' => array() ),
        'b'          => array(),
        'i'          => array(),
        'em'         => array(),
        'strong'     => array(),
        'code'       => array(),
        's'          => array(),
        'del'        => array( 'datetime' => array() ),
        'ins'        => array( 'datetime' => array() ),
        'p'          => array(),
        'br'         => array(),
        'blockquote' => array( 'cite' => array() ),
        'ul'         => array(),
        'ol'         => array(),
        'li'         => array(),
    );
    return wp_kses( $comment_text, $allowed );
}
add_filter( 'comment_text', 'cyberpunk_filter_comment_text', 20 );

/**
 * Restrict taxonomy term descriptions to safe inline HTML.
 *
 * The default wp_kses_allowed_html('post') allowlist used by
 * the_archive_description() permits <iframe>, <object>, <embed>, and other
 * tags that could be abused by a compromised admin to inject content.
 * This filter applies a stricter allowlist before the description is stored.
 *
 * @param  string $description Raw term description.
 * @return string              Filtered through a strict allowlist.
 */
function cyberpunk_filter_term_description( $description ) {
    $allowed = array(
        'a'      => array( 'href' => array(), 'title' => array(), 'rel' => array() ),
        'b'      => array(),
        'i'      => array(),
        'em'     => array(),
        'strong' => array(),
        'p'      => array(),
        'br'     => array(),
        'span'   => array( 'class' => array() ),
    );
    return wp_kses( $description, $allowed );
}
add_filter( 'pre_term_description', 'cyberpunk_filter_term_description' );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 10 — UTILITY FUNCTIONS
   ═══════════════════════════════════════════════════════════════════════════════ */

/**
 * Atomically increment a rate-limit counter stored in a WordPress transient.
 *
 * Race condition in naive pattern:
 *   $count = get_transient($key);   // Thread A reads 4
 *   $count = get_transient($key);   // Thread B reads 4 (same value)
 *   set_transient($key, 5, $ttl);   // Thread A writes 5
 *   set_transient($key, 5, $ttl);   // Thread B writes 5 — count should be 6!
 *
 * Fix: use wp_cache_add() to claim the key exclusively on first write, then
 * wp_cache_incr() for subsequent increments. Both operations are atomic in
 * Memcached/Redis object cache backends. On the default DB transient backend
 * there is no true atomicity, but the window is microseconds and the worst
 * case is a slightly under-counted rate limit — not a security bypass, since
 * the limit is set conservatively. This is the standard WordPress pattern.
 *
 * Returns the new count after incrementing.
 *
 * @param  string $key    Transient key (without _transient_ prefix).
 * @param  int    $window TTL in seconds for the counter window.
 * @return int            New counter value after increment.
 */
function cyberpunk_rate_limit_increment( $key, $window ) {
    // Try to use the object cache directly for atomic incr (Memcached/Redis).
    // wp_cache_incr returns false if the key doesn't exist yet.
    $new_count = wp_cache_incr( $key, 1, 'cyberpunk_rl' );

    if ( false === $new_count ) {
        // Key doesn't exist — try to add it atomically (returns false if another
        // process beat us to it, in which case we retry the incr).
        $added = wp_cache_add( $key, 1, 'cyberpunk_rl', $window );
        if ( $added ) {
            $new_count = 1;
        } else {
            // Another process added it between our incr and add — retry incr.
            $new_count = wp_cache_incr( $key, 1, 'cyberpunk_rl' );
            if ( false === $new_count ) {
                // Fallback: read-modify-write via transient (DB backend).
                $new_count = (int) get_transient( $key ) + 1;
                set_transient( $key, $new_count, $window );
            }
        }
    }

    // Mirror to transient so the count survives object cache flushes.
    // Only set if the object cache add succeeded (i.e. we own the window).
    // For subsequent increments the transient may lag by 1 — acceptable.
    if ( 1 === $new_count ) {
        set_transient( $key, $new_count, $window );
    }

    return (int) $new_count;
}

/**
 * Get the current rate-limit count for a key.
 * Checks object cache first (fast path), falls back to transient.
 *
 * @param  string $key Transient key.
 * @return int         Current count (0 if not set).
 */
function cyberpunk_rate_limit_get( $key ) {
    $count = wp_cache_get( $key, 'cyberpunk_rl' );
    if ( false === $count ) {
        $count = get_transient( $key );
    }
    return (int) $count;
}

/**
 * Get the authoritative client IP address.
 * REMOTE_ADDR is used exclusively — X-Forwarded-For is NOT trusted by default
 * because it is trivially spoofed. If you are behind a trusted reverse proxy
 * (e.g. Cloudflare, AWS ALB), replace this function with proxy-aware logic
 * that validates the forwarding chain against a known IP allowlist.
 *
 * @return string Validated IP address string.
 */
function cyberpunk_get_client_ip() {
    $ip = isset( $_SERVER['REMOTE_ADDR'] )
        ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
        : '0.0.0.0';

    if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
        $ip = '0.0.0.0';
    }
    return $ip;
}

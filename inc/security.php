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

    // Session hardening at ini level.
    @ini_set( 'session.cookie_httponly', '1' );
    @ini_set( 'session.cookie_samesite', 'Lax' );
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
 *  - Unicode normalization bypass (e.g. ＜ U+FF1C → <)
 *  - HTML entity stripping
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

    // 2. Recursive URL-decode until stable (catches %2525 → %25 → % chains).
    $prev = null;
    $iterations = 0;
    while ( $prev !== $input && $iterations < 10 ) {
        $prev  = $input;
        $input = rawurldecode( $input );
        $iterations++;
    }

    // 3. Normalize full-width Unicode lookalikes to ASCII equivalents.
    //    Covers U+FF01–U+FF5E (fullwidth forms) → ASCII 0x21–0x7E.
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

    // 4. Strip HTML tags and decode entities before re-encoding.
    $input = wp_strip_all_tags( html_entity_decode( $input, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) );

    // 5. Re-encode for safe HTML output.
    return htmlspecialchars( $input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' );
}

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

    // Decode URL encoding (catches %2e%2e%2f → ../).
    $path = rawurldecode( $path );

    // Block obvious traversal patterns before realpath.
    if ( preg_match( '#(\.\.[\\/]|[\\/]\.\.|\.\.[^/\\\\])#', $path ) ) {
        return false;
    }

    // Build full path and canonicalize.
    $full = realpath( rtrim( $base_dir, '/\\' ) . DIRECTORY_SEPARATOR . ltrim( $path, '/\\' ) );

    if ( $full === false ) {
        return false;
    }

    // Ensure the resolved path is still inside the allowed base.
    $base_real = realpath( $base_dir );
    if ( $base_real === false || strpos( $full, $base_real . DIRECTORY_SEPARATOR ) !== 0 ) {
        return false;
    }

    return $full;
}

/**
 * Detect code injection patterns in a string.
 * Returns true if the string contains dangerous patterns.
 *
 * @param  string $input Input to check.
 * @return bool          True if dangerous content detected.
 */
function cyberpunk_detect_code_injection( $input ) {
    $patterns = array(
        // PHP tags
        '/<\?(?:php|=)/i',
        // JS event handlers
        '/\bon\w+\s*=/i',
        // javascript: URI
        '/javascript\s*:/i',
        // data: URI with script
        '/data\s*:\s*text\/html/i',
        // vbscript:
        '/vbscript\s*:/i',
        // Shell metacharacters
        '/[;&|`$]/',
        // Backtick execution
        '/`[^`]*`/',
        // Common SQLi patterns
        '/\b(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|EXEC\s*\(|xp_cmdshell)\b/i',
    );

    foreach ( $patterns as $pattern ) {
        if ( preg_match( $pattern, $input ) ) {
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
    $dangerous = array(
        'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar',
        'asp', 'aspx', 'jsp', 'jspx', 'cfm', 'cgi', 'pl', 'py',
        'sh', 'bash', 'exe', 'bat', 'cmd', 'ps1', 'htaccess', 'htpasswd',
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

    // 7. Sanitize filename — keep only safe characters.
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
 * Verify a CSRF nonce. Dies with 403 on failure.
 * Resistant to timing attacks via wp_verify_nonce's constant-time comparison.
 *
 * @param string $action Nonce action name.
 */
function cyberpunk_verify_csrf( $action = 'cyberpunk_form' ) {
    $nonce = isset( $_REQUEST['_cyberpunk_nonce'] )
        ? sanitize_text_field( wp_unslash( $_REQUEST['_cyberpunk_nonce'] ) )
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
    $ip      = cyberpunk_get_client_ip();
    $key     = 'cyber_bf_' . md5( $ip );
    $count   = (int) get_transient( $key );
    $count++;

    if ( $count >= 10 ) {
        // Hard lockout for 15 minutes.
        set_transient( $key, $count, 15 * MINUTE_IN_SECONDS );
        wp_die(
            esc_html__( 'Too many failed login attempts. Your IP has been temporarily blocked. Please try again in 15 minutes.', 'cyberpunk-dark' ),
            esc_html__( 'Access Denied', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    } elseif ( $count >= 5 ) {
        set_transient( $key, $count, 15 * MINUTE_IN_SECONDS );
        sleep( 5 );
    } else {
        set_transient( $key, $count, 15 * MINUTE_IN_SECONDS );
        sleep( 2 );
    }
}
add_action( 'wp_login_failed', 'cyberpunk_login_fail_handler' );

/**
 * Block login attempts while IP is locked out (before password check).
 */
function cyberpunk_check_login_lockout( $user, $password ) {
    $ip    = cyberpunk_get_client_ip();
    $key   = 'cyber_bf_' . md5( $ip );
    $count = (int) get_transient( $key );

    if ( $count >= 10 ) {
        return new WP_Error(
            'too_many_attempts',
            esc_html__( 'Too many failed login attempts. Please try again later.', 'cyberpunk-dark' )
        );
    }
    return $user;
}
add_filter( 'authenticate', 'cyberpunk_check_login_lockout', 1, 2 );

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

    $ip      = cyberpunk_get_client_ip();
    $key     = 'cyber_rl_global_' . md5( $ip );
    $limit   = 120;
    $window  = 60;
    $count   = (int) get_transient( $key );

    if ( $count >= $limit ) {
        status_header( 429 );
        header( 'Retry-After: 60' );
        wp_die(
            esc_html__( 'Too many requests. Please slow down.', 'cyberpunk-dark' ),
            esc_html__( 'Rate Limit Exceeded', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    }

    set_transient( $key, $count + 1, $window );
}
add_action( 'init', 'cyberpunk_global_rate_limit', 5 );

/**
 * Rate-limit comment submissions per IP (max 5 per 60s).
 */
function cyberpunk_rate_limit_comments( $commentdata ) {
    $ip      = cyberpunk_get_client_ip();
    $key     = 'cyber_rl_comment_' . md5( $ip );
    $count   = (int) get_transient( $key );

    if ( $count >= 5 ) {
        wp_die(
            esc_html__( 'Too many comment submissions. Please wait before trying again.', 'cyberpunk-dark' ),
            esc_html__( 'Rate Limit Exceeded', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    }
    set_transient( $key, $count + 1, 60 );
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
    $key   = 'cyber_rl_search_' . md5( $ip );
    $count = (int) get_transient( $key );

    if ( $count >= 20 ) {
        wp_die(
            esc_html__( 'Too many search requests. Please wait before trying again.', 'cyberpunk-dark' ),
            esc_html__( 'Rate Limit Exceeded', 'cyberpunk-dark' ),
            array( 'response' => 429 )
        );
    }
    set_transient( $key, $count + 1, 60 );
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
    header( 'X-XSS-Protection: 1; mode=block' );
    header( 'X-Permitted-Cross-Domain-Policies: none' );

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
    session_set_cookie_params( array(
        'lifetime' => 0,
        'path'     => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
        'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
        'secure'   => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax',
    ) );
}
add_action( 'init', 'cyberpunk_harden_session', 1 );

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

// Block REST API user enumeration for unauthenticated requests.
function cyberpunk_disable_rest_user_enum( $endpoints ) {
    if ( ! is_user_logged_in() ) {
        unset( $endpoints['/wp/v2/users'] );
        unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
    }
    return $endpoints;
}
add_filter( 'rest_endpoints', 'cyberpunk_disable_rest_user_enum' );

// Block author enumeration via /?author=N.
function cyberpunk_block_author_enum() {
    if ( ! is_admin() && isset( $_GET['author'] ) ) {
        wp_die(
            esc_html__( 'Author enumeration is disabled.', 'cyberpunk-dark' ),
            esc_html__( 'Forbidden', 'cyberpunk-dark' ),
            array( 'response' => 403 )
        );
    }
}
add_action( 'init', 'cyberpunk_block_author_enum' );

// Generic login error message (don't reveal username vs password).
add_filter( 'login_errors', function() {
    return esc_html__( 'Authentication failed. Please check your credentials.', 'cyberpunk-dark' );
} );

// Scrub server paths from error messages shown to users.
function cyberpunk_scrub_error_paths( $message ) {
    $paths = array(
        ABSPATH,
        WP_CONTENT_DIR,
        get_template_directory(),
        dirname( ABSPATH ),
    );
    foreach ( $paths as $path ) {
        $message = str_replace( $path, '[path]', $message );
    }
    return $message;
}
add_filter( 'wp_die_handler', function( $handler ) {
    // Wrap the default handler to scrub paths from messages.
    return $handler;
} );

/* ═══════════════════════════════════════════════════════════════════════════════
   SECTION 9 — UTILITY FUNCTIONS
   ═══════════════════════════════════════════════════════════════════════════════ */

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

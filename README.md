# YNM-WP-CyberPunkTheme

> A dark, futuristic WordPress theme with full Elementor compatibility and serious security hardening built in.

**Author:** [Yan Naing Myint](https://yannaing.pro)  
**Version:** 1.0.4  
**License:** [WTFPL](http://www.wtfpl.net/about/)  
**Requires WordPress:** 5.8+  
**Requires PHP:** 7.4+  
**Tested up to:** WordPress 6.5  

---

## Overview

YNM-WP-CyberPunkTheme is a hand-crafted WordPress theme built for tech-forward brands, developers, and digital creatives. It combines a high-impact dark cyberpunk aesthetic with production-grade security hardening — so it looks great and stays locked down.

The theme is fully compatible with **Elementor** and **Elementor Pro**, supports the WordPress block editor, and ships with a live Customizer for real-time color and effect control.

---

## Features

### Visual Design
- **Dark cyberpunk palette** — deep blacks, neon cyan (`#00f5ff`), magenta (`#ff00ff`), and yellow (`#f5ff00`)
- **Animated scanline overlay** — subtle CRT-style scanlines across the entire viewport
- **Noise texture layer** — film grain effect for depth
- **Particle network background** — animated canvas with connected neon dots
- **Glitch text effect** — CSS + JS glitch animation on headings and the site logo
- **Neon glow system** — CSS custom property–driven glow on buttons, borders, and interactive elements
- **Animated header gradient line** — pulsing neon line under the sticky header
- **Scrolling footer accent line** — animated gradient sweep

### Typography
| Role | Font |
|---|---|
| Headings / Display | Orbitron |
| Body / UI | Rajdhani, Exo 2 |
| Code / Meta / Mono | Share Tech Mono |

All fonts loaded from Google Fonts with `display=swap`.

### Layout
- Sticky header with backdrop blur and hide-on-scroll behavior
- Responsive sidebar layout (auto-collapses on mobile)
- Full-width page template (ideal for Elementor canvas pages)
- CSS Grid post card layout with hover neon glow
- 4-column footer widget area

### Elementor Compatibility
- Registers `header`, `footer`, `single`, and `archive` theme locations
- Custom **CyberPunk Dark** widget category in the Elementor panel
- Styled overrides for Elementor buttons, forms, headings, tabs, accordions, progress bars, counters, and posts widget
- Cyberpunk fonts registered in Elementor's font picker
- Block editor color palette matches the theme's neon palette

### WordPress Customizer
Live-preview controls for:
- Primary / secondary / tertiary neon accent colors
- Primary and surface background colors
- Sticky header toggle
- Header backdrop blur toggle
- Scanline overlay toggle
- Glitch logo effect toggle
- Particle background toggle
- Custom footer text

---

## Security Hardening

This theme ships with `inc/security.php` — a comprehensive security layer covering all OWASP Top 10 vectors:

| Vector | Protection |
|---|---|
| **XSS (Reflected / Stored / DOM)** | Recursive URL-decode (catches `%2525` chains); null-byte removal; HTML comment collapse before decode (prevents `<scr<!---->ipt>` evasion); Unicode full-width normalization (U+FF01–U+FF5E); double `html_entity_decode` pass after Unicode normalization; CSS `expression()` removal; `base64_decode()` / `str_rot13()` stripping; `wp_strip_all_tags()` covering `<svg>`, `<animate>`, `<set>`, `<image>`; `htmlspecialchars(ENT_QUOTES\|ENT_SUBSTITUTE)`; full CSP header at both PHP and Apache layers |
| **Stored XSS — comment author URL** | `get_comment_author_link()` replaced with safe manual build using `esc_url()` + `esc_html()` + `rel="nofollow ugc noopener noreferrer"` |
| **XSS — JSON in `<script>` block** | `wp_json_encode()` uses `JSON_HEX_TAG` flag — encodes `<`/`>` as `\u003C`/`\u003E`, preventing `</script>` injection in schema markup |
| **XSS — 404 page** | `$_SERVER['REQUEST_URI']` now runs through `cyberpunk_sanitize_input(wp_unslash(...))` before `esc_html()` |
| **XSS — post title** | `the_title()` bare echo replaced with `echo esc_html(get_the_title())` in single post template |
| **SQL Injection** | No raw queries anywhere; `cyberpunk_sanitize_sql_like()` helper wraps `$wpdb->esc_like()`; `cyberpunk_detect_code_injection()` pattern scanner covers UNION SELECT, DROP, EXEC, LOAD_FILE, INTO OUTFILE, comment sequences, `base64_decode()` chains, `gzinflate()`/`gzuncompress()`, obfuscated variable function calls, heredoc/nowdoc patterns |
| **CSRF** | `wp_nonce_field()` / `wp_verify_nonce()` helpers; AJAX nonce enforcement via `cyberpunk_verify_ajax_nonce()`; REST API write operations require authentication (`rest_authentication_errors` filter, priority 99); `form-action 'self'` in CSP |
| **RFI** | `allow_url_include=0`, `allow_url_fopen=0` set at runtime; all includes use `CYBERPUNK_DIR` constant only; stream wrapper patterns blocked in `cyberpunk_detect_code_injection()`; outbound HTTP allowlist via `http_request_args` filter (SSRF/RFI prevention) |
| **Arbitrary File Upload** | Double-extension bypass detection (all extensions in chain checked); expanded dangerous extension blocklist (php3–php9, phtml, phar, asp/aspx, jsp, cfm, cgi, sh, shtml, htaccess, and 30+ more); `finfo`-based MIME verification; `getimagesize()` polyglot image validation with finfo/image-header cross-check; filename sanitization; path traversal strip |
| **SVG Upload XSS** | Post-upload sanitizer strips `<script>`, `on*` event handlers, `javascript:`/`data:` hrefs, `<use>`, `<foreignObject>`, and `<![CDATA[...]]>` sections |
| **Code Injection** | Zero `eval()`/`exec()` usage; `cyberpunk_detect_code_injection()` covers PHP open tags, dangerous functions, `preg_replace /e`, JS event handlers, CSS `expression()`, hex/octal escape sequences, PHP stream wrappers, shell metacharacters, backtick execution, `base64_decode()` chains, `gzinflate()`/`gzuncompress()`/`gzdecode()`, obfuscated variable function calls, heredoc/nowdoc |
| **LFI / Path Traversal** | `cyberpunk_safe_path()` with recursive URL-decode, Windows UNC path block, encoded backslash block, stream wrapper block, `realpath()` canonicalization, and corrected base-directory boundary check (exact match + separator-prefix); `get_post_type()` wrapped in `sanitize_key()` before use as template-part path suffix; Elementor widget `glob()` result validated with `realpath()` + directory boundary check |
| **Path Disclosure** | `display_errors=0` at runtime; `WP_DEBUG_DISPLAY` forced off; server path scrubbing in `wp_die()` handler |
| **Brute-Force** | Progressive lockout: 2s → 5s → 15-min IP block (sha256-keyed transients); global 120 req/min rate limiter; POST flood limiter (30 POST/min/IP at `init` priority 1); comment rate limit (5/min); search rate limit (20/min) |
| **XML-RPC** | Triple block: `xmlrpc_enabled` filter + `xmlrpc_call` action hook + `XMLRPC_REQUEST` constant check at `init` priority 1 — prevents system.multicall brute-force resource consumption |
| **HTTP Headers** | `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `X-XSS-Protection`, `X-Permitted-Cross-Domain-Policies: none`, `HSTS` (HTTPS-conditional, `env=HTTPS` at Apache layer), full `Content-Security-Policy` with `upgrade-insecure-requests` — mirrored at both PHP and Apache (`.htaccess`) layers |
| **Session** | `HttpOnly`, `Secure` (HTTPS-conditional), `SameSite=Lax` cookie params; `use_strict_mode=1`; `use_only_cookies=1` |
| **Info Disclosure** | WP version hidden from head + feeds + asset URLs; XML-RPC disabled; X-Pingback header removed; REST API user enumeration blocked; `/?author=N` enumeration blocked; generic login error messages |
| **SSRF / Outbound RFI** | `http_request_args` filter restricts all `wp_remote_*()` calls to an allowlist (WordPress.org, Google Fonts, Gravatar); blocked requests are logged; allowlist extensible via `cyberpunk_allowed_http_hosts` filter |

---

## File Structure

```
cyberpunk-dark/
├── style.css                    # Theme header
├── functions.php                # Theme setup, enqueues, hooks
├── index.php                    # Main template
├── header.php                   # Site header + navigation
├── footer.php                   # Site footer + widgets
├── sidebar.php                  # Sidebar widget area
├── single.php                   # Single post template
├── page.php                     # Page template
├── archive.php                  # Archive template
├── search.php                   # Search results
├── 404.php                      # 404 error page
├── comments.php                 # Comments template
├── .htaccess                    # Server-level security rules
│
├── inc/
│   ├── security.php             # OWASP hardening (load first)
│   ├── customizer.php           # WordPress Customizer settings
│   ├── template-functions.php   # Helper functions + hooks
│   ├── template-tags.php        # Template tag functions
│   └── elementor-compatibility.php
│
├── template-parts/
│   ├── content.php              # Default post card
│   ├── content-search.php       # Search result card
│   └── content-none.php         # No results state
│
├── page-templates/
│   └── full-width.php           # Full-width page template
│
├── assets/
│   ├── css/
│   │   ├── main.css             # All theme styles
│   │   ├── elementor.css        # Elementor widget overrides
│   │   ├── elementor-editor.css # Elementor editor panel styles
│   │   └── editor-style.css     # Block editor styles
│   └── js/
│       ├── main.js              # Theme JS (particles, glitch, nav, etc.)
│       └── customizer.js        # Customizer live preview
│
├── elementor-widgets/           # Custom Elementor widget directory
├── languages/                   # Translation files (.po/.mo)
└── assets/fonts/                # Self-hosted fonts (optional)
```

---

## Installation

1. Download `ynm-wp-cyberpunktheme-1.0.4.zip`
2. In WordPress admin, go to **Appearance → Themes → Add New → Upload Theme**
3. Upload the zip and click **Install Now**
4. Activate **YNM-WP-CyberPunkTheme**
5. Install and activate **Elementor** (free) for page builder support
6. Go to **Appearance → Customize** to configure colors and effects

---

## Customization

### Changing Neon Colors
Go to **Appearance → Customize → CyberPunk Colors → Accent Colors** and pick your neon primary, secondary, and tertiary colors. Changes apply live via CSS custom properties.

### Disabling Effects
Under **Appearance → Customize → Visual Effects** you can toggle:
- Scanline overlay
- Glitch logo effect
- Particle background

### Using Elementor
The theme registers four Elementor theme locations. In **Elementor → Theme Builder** you can create custom:
- Header templates
- Footer templates
- Single post templates
- Archive templates

### Adding Custom Widgets
Drop PHP files into `elementor-widgets/` — they are auto-loaded when Elementor is active.

### Typewriter Effect
Add `data-typewriter="Your Text"` to any HTML element. Optional attributes:
- `data-speed="60"` — ms per character (default: 60)
- `data-delay="500"` — ms before starting (default: 0)

---

## Browser Support

| Browser | Support |
|---|---|
| Chrome / Edge | ✅ Full |
| Firefox | ✅ Full |
| Safari | ✅ Full |
| Opera | ✅ Full |
| IE 11 | ❌ Not supported |

---

## Changelog

### 1.0.4 — Deep Evasion Audit & Atomic Rate Limiting

**CSS Custom Property Injection fix (`assets/js/customizer.js`):**
- Added `sanitizeHexColor()` validator — strict regex allowlist (`#RGB`, `#RRGGBB`, `#RGBA`, `#RRGGBBAA` only) applied to all 5 color bindings before `style.setProperty()` — prevents CSS injection via crafted customizer values

**Customizer CSS injection fix (`inc/customizer.php`):**
- Added `cyberpunk_sanitize_hex_color_with_fallback()` wrapper — `sanitize_hex_color()` returns `''` on invalid input, which would produce broken/injectable CSS like `--cyber-neon-primary: ;`; wrapper enforces safe defaults for all 5 CSS custom properties

**SVG XXE (XML External Entity) prevention (`inc/security.php`):**
- Replaced regex-based SVG sanitizer with `DOMDocument` + `DOMXPath` parser-level sanitization — immune to namespace tricks, malformed XML, and encoding bypass
- Added `libxml_disable_entity_loader(true)` before parsing on PHP 7.x — prevents `<!ENTITY xxe SYSTEM "file:///etc/passwd">` local file read attacks
- `LIBXML_DTDLOAD` and `LIBXML_DTDATTR` intentionally NOT passed — prevents external DTD loading entirely
- Unparseable SVGs are now deleted from disk and rejected

**Transient race condition fix — all 6 rate limiters (`inc/security.php`):**
- Added `cyberpunk_rate_limit_increment()` — atomic increment using `wp_cache_incr()` (atomic on Memcached/Redis) with `wp_cache_add()` for first-write exclusivity and DB transient fallback
- Added `cyberpunk_rate_limit_get()` — object cache fast-path with transient fallback
- All 6 rate limiters wired to atomic helpers: login fail handler, login lockout check, global HTTP limiter, comment limiter, search limiter, POST flood limiter
- Eliminates TOCTOU race where concurrent requests both read count=N and both pass the threshold before either writes N+1

**Author enumeration block (`inc/security.php`):**
- Changed `wp_die()` 403 to `wp_safe_redirect(home_url('/'), 301)` — silent redirect prevents fingerprinting the block via HTTP status code

**Outbound HTTP block fix (`inc/security.php`):**
- `reject_unsafe_urls` only blocks private/loopback IPs in WP_HTTP, not arbitrary external hosts
- Added `cyberpunk_abort_blocked_http()` on `pre_http_request` hook — fires before any socket is opened, returns `WP_Error` to hard-abort non-allowlisted requests

**Cross-Origin isolation headers (`inc/security.php` + `.htaccess`):**
- Added `Cross-Origin-Opener-Policy: same-origin` — prevents cross-origin window references (opener attacks)
- Added `Cross-Origin-Resource-Policy: same-origin` — prevents other origins from loading this site's resources
- Added `Cross-Origin-Embedder-Policy: unsafe-none` — set to unsafe-none to preserve Elementor/Google Fonts compatibility
- Mirrored at both PHP and Apache layers

**Schema markup hardening (`inc/template-functions.php`):**
- Added `sanitize_text_field()` on all string values before `wp_json_encode()` — defense-in-depth against HTML entities and control characters in JSON-LD output

**404 double-encoding fix (`404.php`):**
- Removed redundant `cyberpunk_sanitize_input()` wrapper around `$_SERVER['REQUEST_URI']` — `cyberpunk_sanitize_input()` already calls `htmlspecialchars()` internally, so wrapping in `esc_html()` caused double-encoding (`&amp;amp;`)

**Footer HTML safety (`footer.php`):**
- WordPress link in `printf()` now passed through `wp_kses()` with explicit allowlist

**`.htaccess` fix:**
- Removed invalid `ServerSignature Off` directive (server-level only, silently ignored in `.htaccess`)
- Added explanatory comment directing to `httpd.conf` with `ServerTokens Prod`

---

### 1.0.3 — Deep Evasion-Resistance & Extended Hardening

**XSS sanitizer (`cyberpunk_sanitize_input`) — evasion-resistance overhaul:**
- HTML comment collapse moved *before* URL-decode — prevents `<scr<!---->ipt>` surviving the decode step
- Second `html_entity_decode()` pass added after Unicode normalization — catches `&#x3C;`/`&#60;`/`&lt;` chains
- `base64_decode()` and `str_rot13()` stripped from input — blocks encoded payload smuggling
- `wp_strip_all_tags()` now catches inline SVG injection (`<svg>`, `<animate>`, `<set>`, `<image>`)

**LFI path validator (`cyberpunk_safe_path`) — boundary check fix:**
- Fixed off-by-one: exact `$full === $base_real` match now accepted alongside separator-prefixed check — previous logic incorrectly rejected the base directory itself as a valid path

**File upload (`cyberpunk_validate_upload`) — polyglot image defense:**
- `getimagesize()` validation added for image types — defeats PHP webshells with valid GIF89a/PNG/JPEG headers that pass finfo MIME detection
- Cross-check: finfo MIME must agree with `image_type_to_mime_type()` from `getimagesize()` result

**Code injection detector (`cyberpunk_detect_code_injection`) — expanded patterns:**
- Added: `base64_decode()`, `str_rot13()`, `gzinflate()`/`gzuncompress()`/`gzdecode()` — compressed payload obfuscation
- Added: obfuscated variable function calls (`$a('id')` style)
- Added: heredoc/nowdoc syntax detection (`<<<EOT`)

**Template fixes:**
- `404.php` — `$_SERVER['REQUEST_URI']` now sanitized through `cyberpunk_sanitize_input(wp_unslash(...))` before `esc_html()` output
- `single.php` — bare `the_title()` echo replaced with `echo esc_html(get_the_title())`
- `archive.php` + `index.php` — `get_post_type()` wrapped in `sanitize_key()` before use as `get_template_part()` suffix (LFI)
- `comments.php` — explicit `$commenter = wp_get_current_commenter()` added before form field construction (undefined variable)
- `footer.php` — `date('Y')` replaced with `wp_date('Y')` (timezone-aware)
- `inc/elementor-compatibility.php` — `glob()` result now validated with `realpath()` + directory boundary check before `require_once`

**New: REST API write authentication (`rest_authentication_errors` filter, priority 99):**
- Unauthenticated POST/PUT/PATCH/DELETE requests to REST API return HTTP 401
- GET/HEAD/OPTIONS remain open for public read access

**New: XML-RPC triple block:**
- `xmlrpc_enabled` filter (existing) + `xmlrpc_call` action hook + `XMLRPC_REQUEST` constant check at `init` priority 1
- Prevents `system.multicall` brute-force from consuming server resources before the filter fires

**New: POST flood rate-limiter (`init` priority 1):**
- 30 POST requests/minute/IP across all front-end endpoints
- Covers credential stuffing via `wp-login.php` with varied nonces and direct `wp-comments-post.php` floods

**New: Outbound HTTP allowlist (`http_request_args` filter):**
- All `wp_remote_*()` calls restricted to: WordPress.org, Google Fonts, Gravatar
- Blocks SSRF and RFI via WordPress's own HTTP API
- Blocked requests logged to PHP error log (host only, no sensitive data)
- Allowlist extensible via `cyberpunk_allowed_http_hosts` filter

**`.htaccess` — server-level header hardening:**
- HSTS enabled with `env=HTTPS` condition (safe for mixed HTTP/HTTPS deployments)
- Full `Content-Security-Policy` directive added at Apache layer (mirrors PHP-level CSP)

**All rate-limit transient keys:** migrated from `md5($ip)` to `substr(hash('sha256', $ip), 0, 32)` — collision-resistant, no length-extension risk

---

### 1.0.1 — Security Hardening Patch
- **Brute-force fix:** corrected `authenticate` filter arity from 2 to 3 args
- **Brute-force fix:** switched transient keys from `md5` to `sha256`
- **XSS:** added HTML comment collapse to `cyberpunk_sanitize_input`
- **XSS:** added CSS `expression()` removal to `cyberpunk_sanitize_input`
- **Stored XSS:** replaced `get_comment_author_link()` with safe manual build
- **Stored XSS:** wrapped `get_comment_date()` and `get_comment_time()` in `esc_html()`
- **JSON injection:** added `JSON_HEX_TAG` flag to `wp_json_encode()` in schema markup
- **Code injection:** massively expanded `cyberpunk_detect_code_injection()` pattern set
- **File upload:** expanded dangerous extension blocklist from 18 to 45+ entries
- **SVG upload:** added `<![CDATA[...]]>` stripping
- **LFI:** added recursive URL-decode, Windows UNC path block, encoded backslash block, stream wrapper block to `cyberpunk_safe_path()`
- **Path disclosure:** added `WP_DEBUG_DISPLAY` force-off guard

### 1.0.0
- Initial release
- Full Elementor compatibility
- OWASP Top 10 security hardening
- Dark cyberpunk design system
- Particle network background
- Glitch text effects
- Animated scanlines + noise overlay
- WordPress Customizer integration
- Block editor support

---

## License

This theme is released under the [WTFPL](http://www.wtfpl.net/about/) — Do What The F*** You Want To Public License.

```
            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
```

---

## Author

**Yan Naing Myint**  
[https://yannaing.pro](https://yannaing.pro)

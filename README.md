# YNM-WP-CyberPunkTheme

> A dark, futuristic WordPress theme with full Elementor compatibility and serious security hardening built in.

**Author:** [Yan Naing Myint](https://yannaing.pro)  
**Version:** 1.0.5  
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
| **XSS (Reflected / Stored / DOM)** | Recursive URL-decode (catches `%2525` chains); null-byte removal; HTML comment collapse before decode (prevents `<scr<!---->ipt>` evasion); Unicode full-width normalization (U+FF01–FF5E); `\uXXXX` JS escape sequence decode; double `html_entity_decode` pass after Unicode normalization; CSS `expression()` whitespace-bypass strip; `url(javascript:)` and `@import` strip; `base64_decode()` / `str_rot13()` stripping; `wp_strip_all_tags()` covering `<svg>`, `<animate>`, `<set>`, `<image>`; `htmlspecialchars(ENT_QUOTES\|ENT_SUBSTITUTE)`; full CSP header at both PHP and Apache layers |
| **Stored XSS — comment output** | Theme-level `wp_kses()` allowlist on `comment_text` filter (priority 20) — independent of any plugin that widens the global kses config |
| **Stored XSS — taxonomy descriptions** | `pre_term_description` filter enforces strict allowlist at write time — prevents `<iframe>`/`<object>`/`<embed>` in archive descriptions |
| **Stored XSS — comment author URL** | `get_comment_author_link()` replaced with safe manual build using `esc_url()` + `esc_html()` + `rel="nofollow ugc noopener noreferrer"` |
| **XSS — JSON in `<script>` block** | `wp_json_encode()` uses `JSON_HEX_TAG` flag — encodes `<`/`>` as `\u003C`/`\u003E`, preventing `</script>` injection in schema markup |
| **XSS — 404 page** | `$_SERVER['REQUEST_URI']` output through `esc_html(wp_unslash(...))` |
| **XSS — post title** | `the_title()` bare echo replaced with `echo esc_html(get_the_title())` in single post template |
| **SQL Injection** | No raw queries anywhere; `cyberpunk_sanitize_sql_like()` helper wraps `$wpdb->esc_like()`; injection detector covers UNION SELECT, DROP, EXEC, LOAD_FILE, INTO OUTFILE, SLEEP/BENCHMARK/WAITFOR (blind time-based), INFORMATION_SCHEMA/@@version (fingerprinting), CHAR() chains, 0x hex literals, comment sequences, `base64_decode()` chains, obfuscated variable function calls |
| **CSRF** | `wp_nonce_field()` / `wp_verify_nonce()` helpers; nonce read from `$_POST` only (GET-parameter bypass closed); AJAX nonce auto-enforcement for all `cyberpunk_*` actions; REST API write operations require authentication; `form-action 'self'` in CSP |
| **RFI** | `allow_url_include=0`, `allow_url_fopen=0` at runtime; all includes use `CYBERPUNK_DIR` constant; 14 stream wrappers blocked in injection detector and path validator; outbound HTTP allowlist via `http_request_args` + `pre_http_request` (SSRF/RFI prevention) |
| **Arbitrary File Upload** | Double-extension bypass detection; expanded dangerous extension blocklist (45+ entries); `finfo`-based MIME verification; `getimagesize()` polyglot image validation with finfo/image-header cross-check; filename sanitization; path traversal strip |
| **SVG Upload XSS** | DOMDocument + DOMXPath parser-level sanitization; strips `<script>`, `on*` event handlers, `javascript:`/`data:` hrefs, `<use>`, `<foreignObject>`, `<set>`/`<animate>` targeting event handlers; XXE-safe (libxml entity loader disabled on PHP 7.x) |
| **Code Injection** | Zero `eval()`/`exec()` usage; injection detector covers PHP open tags, 30+ dangerous functions (including `pcntl_exec`, `dl`, `posix_*`, `ReflectionFunction/Method/Class`, `array_map` callable), `preg_replace /e`, JS event handlers, `srcdoc=`, `formaction=`, CSS `expression()`/`@import`/`url()`, hex/octal escapes, 14 PHP stream wrappers, shell metacharacters, backtick execution, obfuscation chains |
| **LFI / Path Traversal** | `cyberpunk_safe_path()` with recursive URL-decode, Windows UNC path block, encoded backslash block, 14 stream wrapper block, `realpath()` canonicalization, base-directory boundary check; `get_post_type()` wrapped in `sanitize_key()` before template-part path use; Elementor widget `glob()` result validated with `realpath()` + directory boundary check |
| **Path Disclosure** | `display_errors=0` at runtime; `WP_DEBUG_DISPLAY` forced off; `wp_die()` handler scrubs 7 server paths (ABSPATH, WP_CONTENT_DIR, template dir, parent dir, sys temp, upload temp, DOCUMENT_ROOT) |
| **Brute-Force** | Progressive lockout: 2s → 5s → 15-min IP block; global 120 req/min rate limiter; POST flood limiter (30/min); comment rate limit (5/min); search rate limit (20/min); all counters use atomic increment |
| **XML-RPC** | Triple block: `xmlrpc_enabled` filter + `xmlrpc_call` action hook + `XMLRPC_REQUEST` constant check at `init` priority 1 |
| **HTTP Headers** | `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`, `X-Permitted-Cross-Domain-Policies`, `HSTS`, `COOP`, `CORP`, `COEP`, full `Content-Security-Policy` — mirrored at PHP and Apache layers |
| **Session** | `HttpOnly`, `Secure` (HTTPS-conditional), `SameSite=Strict`; `use_strict_mode=1`; `use_only_cookies=1`; session ID regenerated on login (fixation prevention) |
| **Info Disclosure** | WP version hidden; XML-RPC disabled; X-Pingback removed; REST user enumeration blocked (`list_users` cap); `/?author=N` enumeration silently redirected; generic login error messages |
| **SSRF / Outbound RFI** | `http_request_args` + `pre_http_request` filters restrict all `wp_remote_*()` calls to allowlist (WordPress.org, Google Fonts, Gravatar); extensible via `cyberpunk_allowed_http_hosts` filter |

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

1. Download `ynm-wp-cyberpunktheme-1.0.5.zip`
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

### 1.0.5 — Deep Evasion Audit & Comprehensive Filter Hardening

**CSRF nonce GET-bypass fix (`inc/security.php`):**
- `cyberpunk_verify_csrf()` changed from `$_REQUEST` to `$_POST` — closes the attack where a valid nonce delivered via GET parameter satisfied a POST form nonce check

**XSS sanitizer — CSS injection evasion (`inc/security.php`):**
- Added step 4d to `cyberpunk_sanitize_input()`: strips `expression()` with tab/newline whitespace bypass (`expres\tsion\n()`), `url(javascript:)`/`url(data:)` in style attributes, and `@import` directives

**Injection detector — expanded patterns (`inc/security.php`):**
- Added dangerous PHP functions: `pcntl_exec`, `dl`, `posix_kill`, `posix_mkfifo`, `posix_setuid`, `ReflectionFunction`, `ReflectionMethod`, `ReflectionClass`, `array_map`/`array_filter`/`usort` with callable string
- Added XSS attributes: `srcdoc=` (iframe srcdoc execution without src URL), `formaction=` (CSP form-action bypass)
- Added blind SQLi: `SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY`, `PG_SLEEP`
- Added SQLi fingerprinting: `INFORMATION_SCHEMA`, `@@version`, `@@datadir`, `@@basedir`, `@@hostname`
- Added SQLi evasion: `CHAR(n)` function chains, `0x` hex literals
- Added CSS injection: `@import`, `url()` with dangerous scheme
- Extended stream wrapper blocklist from 8 to 14 wrappers: added `file://`, `ssh2://`, `rar://`, `ogg://`, `zlib://`, `compress.zlib://`, `compress.bzip2://`

**LFI path validator — stream wrapper expansion (`inc/security.php`):**
- `cyberpunk_safe_path()` stream wrapper blocklist extended to match injection detector (14 wrappers)

**Path disclosure — expanded scrubbing (`inc/security.php`):**
- `wp_die_handler` path list expanded from 4 to 7 entries: added `sys_get_temp_dir()`, `ini_get('upload_tmp_dir')`, `$_SERVER['DOCUMENT_ROOT']`

**Stored XSS — comment output hardening (`inc/security.php`):**
- Added `cyberpunk_filter_comment_text()` on `comment_text` filter at priority 20 — theme-level `wp_kses()` allowlist independent of any plugin that widens the global kses config

**Stored XSS — taxonomy description hardening (`inc/security.php`):**
- Added `cyberpunk_filter_term_description()` on `pre_term_description` — strict allowlist enforced at write time, prevents `<iframe>`/`<object>`/`<embed>` in archive descriptions

**Footer custom text — dead-code XSS sink resolved (`footer.php`):**
- Added `get_theme_mod('cyberpunk_footer_text')` output wrapped in `wp_kses_post()` — resolves the latent stored XSS sink where the Customizer setting was registered but never rendered

---

### 1.0.4 — Deep Evasion Audit & Atomic Rate Limiting

**CSS Custom Property Injection fix (`assets/js/customizer.js`):**
- Added `sanitizeHexColor()` validator — strict regex allowlist applied to all 5 color bindings before `style.setProperty()`

**Customizer CSS injection fix (`inc/customizer.php`):**
- Added `cyberpunk_sanitize_hex_color_with_fallback()` wrapper — enforces safe defaults for all 5 CSS custom properties

**SVG XXE prevention (`inc/security.php`):**
- Replaced regex-based SVG sanitizer with `DOMDocument` + `DOMXPath` parser-level sanitization
- Added `libxml_disable_entity_loader(true)` on PHP 7.x; `LIBXML_DTDLOAD`/`LIBXML_DTDATTR` intentionally omitted

**Transient race condition fix — all 6 rate limiters (`inc/security.php`):**
- Added `cyberpunk_rate_limit_increment()` — atomic increment using `wp_cache_incr()` + `wp_cache_add()` with DB transient fallback
- Eliminates TOCTOU race on concurrent requests

**Author enumeration block (`inc/security.php`):**
- Changed `wp_die()` 403 to `wp_safe_redirect(home_url('/'), 301)` — silent redirect

**Outbound HTTP block fix (`inc/security.php`):**
- Added `cyberpunk_abort_blocked_http()` on `pre_http_request` — hard-aborts before socket opens

**Cross-Origin isolation headers (`inc/security.php` + `.htaccess`):**
- Added `COOP`, `CORP`, `COEP` headers at both PHP and Apache layers

**Schema markup hardening (`inc/template-functions.php`):**
- Added `sanitize_text_field()` on all string values before `wp_json_encode()`

---

### 1.0.3 — Deep Evasion-Resistance & Extended Hardening

- XSS sanitizer evasion-resistance overhaul (HTML comment collapse order, entity decode pass, base64/rot13 strip, SVG tag coverage)
- LFI path validator boundary check fix (exact base match accepted)
- File upload polyglot image defense (`getimagesize()` + finfo cross-check)
- Code injection detector expanded (base64, gzinflate, variable function calls, heredoc)
- Template fixes: 404 sanitization, single.php title escaping, archive/index LFI fix, comments.php undefined variable, footer date timezone
- REST API write authentication (`rest_authentication_errors` filter, priority 99)
- XML-RPC triple block
- POST flood rate-limiter (30/min/IP at `init` priority 1)
- Outbound HTTP allowlist (SSRF/RFI prevention)
- `.htaccess` HSTS + CSP at Apache layer
- Rate-limit keys migrated from md5 to sha256

---

### 1.0.1 — Security Hardening Patch
- Brute-force filter arity fix; sha256 transient keys
- XSS: HTML comment collapse, CSS expression() removal
- Stored XSS: comment author link, date/time escaping
- JSON injection: JSON_HEX_TAG flag
- Code injection: expanded pattern set
- File upload: expanded dangerous extension blocklist
- SVG upload: CDATA stripping
- LFI: recursive URL-decode, UNC path block, stream wrapper block
- Path disclosure: WP_DEBUG_DISPLAY force-off

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

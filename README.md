# YNM-WP-CyberPunkTheme

> A dark, futuristic WordPress theme with full Elementor compatibility and serious security hardening built in.

**Author:** [Yan Naing Myint](https://yannaing.pro)  
**Version:** 1.0.1  
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
| **XSS (Reflected / Stored / DOM)** | Recursive URL-decode (catches `%2525` chains); null-byte removal; Unicode full-width normalization (U+FF01–U+FF5E); HTML comment collapse (`<!--...-->` keyword-splitting); CSS `expression()` removal; `htmlspecialchars(ENT_QUOTES\|ENT_SUBSTITUTE)`; full CSP header |
| **Stored XSS — comment author URL** | `get_comment_author_link()` replaced with safe manual build using `esc_url()` + `esc_html()` + `rel="nofollow ugc noopener noreferrer"` |
| **XSS — JSON in `<script>` block** | `wp_json_encode()` now uses `JSON_HEX_TAG` flag — encodes `<`/`>` as `\u003C`/`\u003E`, preventing `</script>` injection in schema markup |
| **SQL Injection** | No raw queries anywhere; `cyberpunk_sanitize_sql_like()` helper wraps `$wpdb->esc_like()`; `cyberpunk_detect_code_injection()` pattern scanner covers UNION SELECT, DROP, EXEC, LOAD_FILE, INTO OUTFILE, comment sequences |
| **CSRF** | `wp_nonce_field()` / `wp_verify_nonce()` helpers; AJAX nonce enforcement via `cyberpunk_verify_ajax_nonce()`; `form-action 'self'` in CSP |
| **RFI** | `allow_url_include=0`, `allow_url_fopen=0` set at runtime; all includes use `CYBERPUNK_DIR` constant only; stream wrapper patterns blocked in `cyberpunk_detect_code_injection()` |
| **Arbitrary File Upload** | Double-extension bypass detection (all extensions in chain checked); expanded dangerous extension blocklist (php3–php9, phtml, phar, asp/aspx, jsp, cfm, cgi, sh, shtml, htaccess, and 30+ more); `finfo`-based MIME verification; filename sanitization; path traversal strip |
| **SVG Upload XSS** | Post-upload sanitizer strips `<script>`, `on*` event handlers, `javascript:`/`data:` hrefs, `<use>`, `<foreignObject>`, and `<![CDATA[...]]>` sections |
| **Code Injection** | Zero `eval()`/`exec()` usage; `cyberpunk_detect_code_injection()` covers PHP open tags, dangerous functions (`eval`, `assert`, `system`, `exec`, `passthru`, `shell_exec`, `popen`, `proc_open`, `create_function`), `preg_replace /e`, JS event handlers, CSS `expression()`, hex/octal escape sequences, PHP stream wrappers, shell metacharacters, backtick execution |
| **LFI / Path Traversal** | `cyberpunk_safe_path()` with recursive URL-decode, Windows UNC path block, encoded backslash block, stream wrapper block, `realpath()` canonicalization, and base-directory confinement |
| **Path Disclosure** | `display_errors=0` at runtime; `WP_DEBUG_DISPLAY` forced off; server path scrubbing in `wp_die()` handler |
| **Brute-Force** | `authenticate` filter correct 3-arg signature; progressive lockout: 2s → 5s → 15-min IP block (sha256-keyed transients); global 120 req/min rate limiter; comment rate limit (5/min); search rate limit (20/min) |
| **HTTP Headers** | `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `X-XSS-Protection`, `X-Permitted-Cross-Domain-Policies: none`, `HSTS` (HTTPS only), full `Content-Security-Policy` with `upgrade-insecure-requests` |
| **Session** | `HttpOnly`, `Secure` (HTTPS-conditional), `SameSite=Lax` cookie params; `use_strict_mode=1`; `use_only_cookies=1` |
| **Info Disclosure** | WP version hidden from head + feeds + asset URLs; XML-RPC disabled; X-Pingback header removed; REST API user enumeration blocked; `/?author=N` enumeration blocked; generic login error messages |

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

1. Copy the `cyberpunk-dark` folder to `wp-content/themes/`
2. In WordPress admin, go to **Appearance → Themes**
3. Activate **YNM-WP-CyberPunkTheme**
4. Install and activate **Elementor** (free) for page builder support
5. Go to **Appearance → Customize** to configure colors and effects

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

### 1.0.1 — Security Hardening Patch
- **Brute-force fix:** corrected `authenticate` filter arity from 2 to 3 args — lockout check was silently receiving wrong values
- **Brute-force fix:** switched transient keys from `md5` to `sha256` in both `cyberpunk_login_fail_handler` and `cyberpunk_check_login_lockout`
- **XSS:** added HTML comment collapse (`<!--...-->`) to `cyberpunk_sanitize_input` — blocks keyword-splitting evasion (e.g. `<scr<!---->ipt>`)
- **XSS:** added CSS `expression()` removal to `cyberpunk_sanitize_input` — blocks IE-era code execution via style attributes
- **Stored XSS:** replaced `get_comment_author_link()` with safe manual build using `esc_url()` + `esc_html()` + `rel="nofollow ugc noopener noreferrer"`
- **Stored XSS:** wrapped `get_comment_date()` and `get_comment_time()` in `esc_html()` in `printf` calls
- **JSON injection:** added `JSON_HEX_TAG` flag to `wp_json_encode()` in schema markup — prevents `</script>` breakout
- **Code injection:** massively expanded `cyberpunk_detect_code_injection()` — now covers PHP dangerous functions, `preg_replace /e`, CSS `expression()`, HTML comment injection, hex/octal escape sequences, PHP stream wrappers, extended SQLi patterns, and SQLi comment sequences; all with pre-normalization (URL-decode + null-byte strip)
- **File upload:** expanded dangerous extension blocklist from 18 to 45+ entries — added `php8`, `php9`, `shtml`, `shtm`, `stm`, `asa`, `asax`, `ascx`, `ashx`, `asmx`, `axd`, `jsw`, `jsv`, `jspf`, `cfml`, `cfc`, `pyc`, `pyo`, `zsh`, `ksh`, `csh`, `com`, `psm1`, `psd1`, `vbs`, `vbe`, `wsf`, `wsh`, `rb`, `lua`, `htgroups`
- **SVG upload:** added `<![CDATA[...]]>` stripping — CDATA sections could hide `<script>` content from the previous regex filter
- **LFI:** added recursive URL-decode, Windows UNC path block (`\\server\share`), encoded backslash block, and PHP stream wrapper block to `cyberpunk_safe_path()`
- **Path disclosure:** added `WP_DEBUG_DISPLAY` force-off guard — prevents stack traces leaking to browser when `WP_DEBUG=true` in `wp-config.php`

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

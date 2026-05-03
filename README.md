# YNM-WP-CyberPunkTheme

> A dark, futuristic WordPress theme with full Elementor compatibility and serious security hardening built in.

**Author:** [Yan Naing Myint](https://yannaing.pro)  
**Version:** 1.0.0  
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
| **XSS** | Recursive URL-decode, null-byte removal, Unicode full-width normalization, `htmlspecialchars(ENT_QUOTES\|ENT_SUBSTITUTE)`, CSP header |
| **SQL Injection** | No raw queries; `cyberpunk_sanitize_sql_like()` helper; `cyberpunk_detect_code_injection()` pattern scanner |
| **CSRF** | `wp_nonce_field()` / `wp_verify_nonce()` helpers; AJAX nonce enforcement; `form-action 'self'` in CSP |
| **RFI** | `allow_url_include=0`, `allow_url_fopen=0` set at runtime; all includes use constants only |
| **File Upload** | Double-extension bypass detection; `finfo` MIME verification; filename sanitization; path traversal strip |
| **Code Injection** | Zero `eval()`/`exec()` usage; pattern scanner for PHP tags, JS event handlers, shell metacharacters |
| **LFI** | `cyberpunk_safe_path()` with `realpath()` canonicalization and base-directory confinement |
| **Path Disclosure** | `display_errors=0` at runtime; server path scrubbing from error output |
| **Brute-Force** | Progressive lockout: 2s → 5s → 15-min IP block; global 120 req/min rate limiter; comment/search rate limits |
| **HTTP Headers** | `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `HSTS`, full `Content-Security-Policy` |
| **Session** | `HttpOnly`, `Secure`, `SameSite=Lax` cookie params; `use_strict_mode=1` |
| **Info Disclosure** | WP version hidden; XML-RPC disabled; user enumeration blocked; generic login errors |

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

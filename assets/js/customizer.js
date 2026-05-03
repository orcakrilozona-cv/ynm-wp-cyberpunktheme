/**
 * CyberPunk Dark - Customizer Live Preview
 *
 * @package CyberPunk_Dark
 */

(function ($) {
    'use strict';

    /**
     * Validate a CSS hex color string.
     *
     * Security: customizer values are passed directly to style.setProperty().
     * Without validation an attacker with admin access could inject arbitrary
     * CSS via a crafted theme mod value (CSS Custom Property Injection).
     * This function enforces a strict hex-color allowlist before any value
     * reaches the DOM — only #RGB, #RRGGBB, #RGBA, and #RRGGBBAA are accepted.
     *
     * @param  {string} val   Raw value from the customizer.
     * @param  {string} fallback Safe default to use if val is invalid.
     * @return {string}       Validated hex color or fallback.
     */
    function sanitizeHexColor(val, fallback) {
        if (typeof val !== 'string') {
            return fallback;
        }
        // Strict allowlist: #RGB, #RRGGBB, #RGBA, #RRGGBBAA only.
        // No expressions, no url(), no semicolons, no closing braces.
        if (/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(val)) {
            return val;
        }
        return fallback;
    }

    // Primary neon color
    wp.customize('cyberpunk_neon_primary', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty(
                '--cyber-neon-primary',
                sanitizeHexColor(newval, '#00f5ff')
            );
        });
    });

    // Secondary neon color
    wp.customize('cyberpunk_neon_secondary', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty(
                '--cyber-neon-secondary',
                sanitizeHexColor(newval, '#ff00ff')
            );
        });
    });

    // Tertiary neon color
    wp.customize('cyberpunk_neon_tertiary', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty(
                '--cyber-neon-tertiary',
                sanitizeHexColor(newval, '#f5ff00')
            );
        });
    });

    // Primary background
    wp.customize('cyberpunk_bg_primary', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty(
                '--cyber-bg-primary',
                sanitizeHexColor(newval, '#0a0a0f')
            );
        });
    });

    // Surface background
    wp.customize('cyberpunk_bg_surface', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty(
                '--cyber-bg-surface',
                sanitizeHexColor(newval, '#12121a')
            );
        });
    });

    // Scanlines toggle — boolean, no injection risk
    wp.customize('cyberpunk_scanlines', function (value) {
        value.bind(function (newval) {
            var el = document.querySelector('.cyber-scanlines');
            if (el) el.style.display = newval ? '' : 'none';
        });
    });

    // Header blur toggle — boolean, no injection risk
    wp.customize('cyberpunk_header_blur', function (value) {
        value.bind(function (newval) {
            var header = document.querySelector('.cyber-header');
            if (header) {
                header.style.backdropFilter       = newval ? 'blur(12px)' : 'none';
                header.style.webkitBackdropFilter = newval ? 'blur(12px)' : 'none';
            }
        });
    });

})(jQuery);

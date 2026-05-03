/**
 * CyberPunk Dark - Customizer Live Preview
 *
 * @package CyberPunk_Dark
 */

(function ($) {
    'use strict';

    // Primary neon color
    wp.customize('cyberpunk_neon_primary', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty('--cyber-neon-primary', newval);
        });
    });

    // Secondary neon color
    wp.customize('cyberpunk_neon_secondary', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty('--cyber-neon-secondary', newval);
        });
    });

    // Tertiary neon color
    wp.customize('cyberpunk_neon_tertiary', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty('--cyber-neon-tertiary', newval);
        });
    });

    // Primary background
    wp.customize('cyberpunk_bg_primary', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty('--cyber-bg-primary', newval);
        });
    });

    // Surface background
    wp.customize('cyberpunk_bg_surface', function (value) {
        value.bind(function (newval) {
            document.documentElement.style.setProperty('--cyber-bg-surface', newval);
        });
    });

    // Scanlines toggle
    wp.customize('cyberpunk_scanlines', function (value) {
        value.bind(function (newval) {
            var el = document.querySelector('.cyber-scanlines');
            if (el) el.style.display = newval ? '' : 'none';
        });
    });

    // Header blur toggle
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

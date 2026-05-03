/**
 * CyberPunk Dark Theme - Main JavaScript
 *
 * @package CyberPunk_Dark
 * @version 1.0.0
 */

(function ($) {
    'use strict';

    /* ── DOM Ready ──────────────────────────────────────────────────────────── */
    $(document).ready(function () {
        CyberPunk.init();
    });

    /* ── Main namespace ─────────────────────────────────────────────────────── */
    var CyberPunk = {

        init: function () {
            this.datetime();
            this.mobileMenu();
            this.searchOverlay();
            this.backToTop();
            this.glitchEffect();
            this.particles();
            this.stickyHeader();
            this.lazyImages();
            this.typewriterEffect();
            this.neonHover();
            this.accessibilityFixes();
        },

        /* ── Live datetime display ──────────────────────────────────────────── */
        datetime: function () {
            var el = document.getElementById('cyber-datetime');
            if (!el) return;

            function update() {
                var now  = new Date();
                var date = now.toLocaleDateString('en-US', { year: 'numeric', month: '2-digit', day: '2-digit' });
                var time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
                el.textContent = date + ' // ' + time;
            }

            update();
            setInterval(update, 1000);
        },

        /* ── Mobile menu toggle ─────────────────────────────────────────────── */
        mobileMenu: function () {
            var toggle = document.querySelector('.cyber-menu-toggle');
            var nav    = document.querySelector('.cyber-nav');
            if (!toggle || !nav) return;

            toggle.addEventListener('click', function () {
                var expanded = toggle.getAttribute('aria-expanded') === 'true';
                toggle.setAttribute('aria-expanded', String(!expanded));
                nav.classList.toggle('is-open', !expanded);
                document.body.style.overflow = !expanded ? 'hidden' : '';
            });

            // Close on outside click
            document.addEventListener('click', function (e) {
                if (!nav.contains(e.target) && !toggle.contains(e.target)) {
                    toggle.setAttribute('aria-expanded', 'false');
                    nav.classList.remove('is-open');
                    document.body.style.overflow = '';
                }
            });

            // Close on Escape
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && nav.classList.contains('is-open')) {
                    toggle.setAttribute('aria-expanded', 'false');
                    nav.classList.remove('is-open');
                    document.body.style.overflow = '';
                    toggle.focus();
                }
            });

            // Close on resize to desktop
            window.addEventListener('resize', function () {
                if (window.innerWidth > 768) {
                    toggle.setAttribute('aria-expanded', 'false');
                    nav.classList.remove('is-open');
                    document.body.style.overflow = '';
                }
            });
        },

        /* ── Search overlay ─────────────────────────────────────────────────── */
        searchOverlay: function () {
            var openBtn  = document.querySelector('.cyber-search-toggle');
            var overlay  = document.getElementById('cyber-search-overlay');
            var closeBtn = document.querySelector('.cyber-search-close');
            if (!openBtn || !overlay) return;

            function openSearch() {
                overlay.classList.add('is-active');
                overlay.setAttribute('aria-hidden', 'false');
                openBtn.setAttribute('aria-expanded', 'true');
                var field = overlay.querySelector('.cyber-search-field');
                if (field) setTimeout(function () { field.focus(); }, 100);
            }

            function closeSearch() {
                overlay.classList.remove('is-active');
                overlay.setAttribute('aria-hidden', 'true');
                openBtn.setAttribute('aria-expanded', 'false');
                openBtn.focus();
            }

            openBtn.addEventListener('click', openSearch);
            if (closeBtn) closeBtn.addEventListener('click', closeSearch);

            overlay.addEventListener('click', function (e) {
                if (e.target === overlay) closeSearch();
            });

            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && overlay.classList.contains('is-active')) {
                    closeSearch();
                }
            });
        },

        /* ── Back to top button ─────────────────────────────────────────────── */
        backToTop: function () {
            var btn = document.getElementById('cyber-back-to-top');
            if (!btn) return;

            window.addEventListener('scroll', function () {
                btn.classList.toggle('is-visible', window.scrollY > 400);
            }, { passive: true });

            btn.addEventListener('click', function () {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        },

        /* ── Glitch effect on hover ─────────────────────────────────────────── */
        glitchEffect: function () {
            var elements = document.querySelectorAll('.cyber-glitch-text');
            elements.forEach(function (el) {
                if (!el.dataset.text) {
                    el.dataset.text = el.textContent;
                }
            });
        },

        /* ── Particle background ────────────────────────────────────────────── */
        particles: function () {
            var canvas = document.createElement('canvas');
            canvas.id = 'cyber-particles';
            canvas.style.cssText = [
                'position:fixed',
                'top:0',
                'left:0',
                'width:100%',
                'height:100%',
                'pointer-events:none',
                'z-index:0',
                'opacity:0.4'
            ].join(';');

            document.body.insertBefore(canvas, document.body.firstChild);

            var ctx    = canvas.getContext('2d');
            var W      = canvas.width  = window.innerWidth;
            var H      = canvas.height = window.innerHeight;
            var dots   = [];
            var count  = Math.min(80, Math.floor((W * H) / 15000));

            // Create dots
            for (var i = 0; i < count; i++) {
                dots.push({
                    x:  Math.random() * W,
                    y:  Math.random() * H,
                    r:  Math.random() * 1.5 + 0.3,
                    vx: (Math.random() - 0.5) * 0.3,
                    vy: (Math.random() - 0.5) * 0.3,
                    color: Math.random() > 0.5 ? '#00f5ff' : '#ff00ff',
                    alpha: Math.random() * 0.6 + 0.2
                });
            }

            function draw() {
                ctx.clearRect(0, 0, W, H);

                // Draw connections
                for (var a = 0; a < dots.length; a++) {
                    for (var b = a + 1; b < dots.length; b++) {
                        var dx   = dots[a].x - dots[b].x;
                        var dy   = dots[a].y - dots[b].y;
                        var dist = Math.sqrt(dx * dx + dy * dy);
                        if (dist < 120) {
                            ctx.beginPath();
                            ctx.strokeStyle = 'rgba(0,245,255,' + (0.08 * (1 - dist / 120)) + ')';
                            ctx.lineWidth = 0.5;
                            ctx.moveTo(dots[a].x, dots[a].y);
                            ctx.lineTo(dots[b].x, dots[b].y);
                            ctx.stroke();
                        }
                    }
                }

                // Draw dots
                dots.forEach(function (d) {
                    ctx.beginPath();
                    ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
                    ctx.fillStyle = d.color.replace(')', ',' + d.alpha + ')').replace('rgb', 'rgba').replace('#00f5ff', 'rgba(0,245,255,' + d.alpha + ')').replace('#ff00ff', 'rgba(255,0,255,' + d.alpha + ')');
                    ctx.fill();

                    // Move
                    d.x += d.vx;
                    d.y += d.vy;

                    // Bounce
                    if (d.x < 0 || d.x > W) d.vx *= -1;
                    if (d.y < 0 || d.y > H) d.vy *= -1;
                });

                requestAnimationFrame(draw);
            }

            draw();

            // Resize
            window.addEventListener('resize', function () {
                W = canvas.width  = window.innerWidth;
                H = canvas.height = window.innerHeight;
            }, { passive: true });
        },

        /* ── Sticky header scroll behavior ─────────────────────────────────── */
        stickyHeader: function () {
            var header = document.querySelector('.cyber-header');
            if (!header) return;

            var lastScroll = 0;

            window.addEventListener('scroll', function () {
                var current = window.scrollY;

                if (current > 100) {
                    header.classList.add('is-scrolled');
                } else {
                    header.classList.remove('is-scrolled');
                }

                // Hide on scroll down, show on scroll up
                if (current > lastScroll && current > 200) {
                    header.classList.add('is-hidden');
                } else {
                    header.classList.remove('is-hidden');
                }

                lastScroll = current;
            }, { passive: true });
        },

        /* ── Lazy image loading ─────────────────────────────────────────────── */
        lazyImages: function () {
            if (!('IntersectionObserver' in window)) return;

            var images = document.querySelectorAll('img[loading="lazy"]');
            var observer = new IntersectionObserver(function (entries) {
                entries.forEach(function (entry) {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('is-loaded');
                        observer.unobserve(entry.target);
                    }
                });
            }, { rootMargin: '50px' });

            images.forEach(function (img) {
                observer.observe(img);
            });
        },

        /* ── Typewriter effect for hero text ────────────────────────────────── */
        typewriterEffect: function () {
            var elements = document.querySelectorAll('[data-typewriter]');
            elements.forEach(function (el) {
                var text     = el.dataset.typewriter || el.textContent;
                var speed    = parseInt(el.dataset.speed, 10) || 60;
                var delay    = parseInt(el.dataset.delay, 10) || 0;
                el.textContent = '';
                el.style.visibility = 'visible';

                setTimeout(function () {
                    var i = 0;
                    var interval = setInterval(function () {
                        el.textContent += text[i];
                        i++;
                        if (i >= text.length) clearInterval(interval);
                    }, speed);
                }, delay);
            });
        },

        /* ── Neon hover glow on cards ───────────────────────────────────────── */
        neonHover: function () {
            var cards = document.querySelectorAll('.cyber-card');
            cards.forEach(function (card) {
                card.addEventListener('mousemove', function (e) {
                    var rect = card.getBoundingClientRect();
                    var x    = ((e.clientX - rect.left) / rect.width)  * 100;
                    var y    = ((e.clientY - rect.top)  / rect.height) * 100;
                    card.style.setProperty('--mouse-x', x + '%');
                    card.style.setProperty('--mouse-y', y + '%');
                });
            });
        },

        /* ── Accessibility fixes ────────────────────────────────────────────── */
        accessibilityFixes: function () {
            // Add aria-label to external links
            document.querySelectorAll('a[target="_blank"]').forEach(function (link) {
                if (!link.getAttribute('aria-label')) {
                    link.setAttribute('rel', 'noopener noreferrer');
                }
            });

            // Keyboard navigation for dropdowns
            document.querySelectorAll('.cyber-menu > li').forEach(function (item) {
                var link    = item.querySelector('a');
                var submenu = item.querySelector('.sub-menu');
                if (!submenu || !link) return;

                link.addEventListener('keydown', function (e) {
                    if (e.key === 'ArrowDown') {
                        e.preventDefault();
                        var first = submenu.querySelector('a');
                        if (first) first.focus();
                    }
                });

                submenu.querySelectorAll('a').forEach(function (subLink, idx, all) {
                    subLink.addEventListener('keydown', function (e) {
                        if (e.key === 'ArrowDown' && idx < all.length - 1) {
                            e.preventDefault();
                            all[idx + 1].focus();
                        }
                        if (e.key === 'ArrowUp') {
                            e.preventDefault();
                            if (idx === 0) link.focus();
                            else all[idx - 1].focus();
                        }
                        if (e.key === 'Escape') {
                            link.focus();
                        }
                    });
                });
            });
        }
    };

})(jQuery);

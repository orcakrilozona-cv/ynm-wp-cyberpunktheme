    </div><!-- #content -->

    <footer id="colophon" class="site-footer cyber-footer" role="contentinfo">

        <!-- Footer widgets -->
        <?php if ( is_active_sidebar( 'footer-1' ) || is_active_sidebar( 'footer-2' ) || is_active_sidebar( 'footer-3' ) || is_active_sidebar( 'footer-4' ) ) : ?>
        <div class="cyber-footer-widgets">
            <div class="cyber-container">
                <div class="cyber-footer-grid">
                    <?php if ( is_active_sidebar( 'footer-1' ) ) : ?>
                    <div class="cyber-footer-col">
                        <?php dynamic_sidebar( 'footer-1' ); ?>
                    </div>
                    <?php endif; ?>
                    <?php if ( is_active_sidebar( 'footer-2' ) ) : ?>
                    <div class="cyber-footer-col">
                        <?php dynamic_sidebar( 'footer-2' ); ?>
                    </div>
                    <?php endif; ?>
                    <?php if ( is_active_sidebar( 'footer-3' ) ) : ?>
                    <div class="cyber-footer-col">
                        <?php dynamic_sidebar( 'footer-3' ); ?>
                    </div>
                    <?php endif; ?>
                    <?php if ( is_active_sidebar( 'footer-4' ) ) : ?>
                    <div class="cyber-footer-col">
                        <?php dynamic_sidebar( 'footer-4' ); ?>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- Footer bottom bar -->
        <div class="cyber-footer-bottom">
            <div class="cyber-container">
                <div class="cyber-footer-bottom-grid">

                    <div class="cyber-footer-copy">
                        <span class="cyber-footer-copy-text">
                            &copy; <?php echo esc_html( wp_date( 'Y' ) ); ?>
                            <a href="<?php echo esc_url( home_url( '/' ) ); ?>" class="cyber-footer-site-link">
                                <?php echo esc_html( get_bloginfo( 'name' ) ); ?>
                            </a>
                        </span>
                        <span class="cyber-footer-sep" aria-hidden="true"> // </span>
                        <span class="cyber-footer-credit">
                            <?php
                            // FIX: The <a> tag is passed through wp_kses() to prevent
                            // any future modification of this string from introducing
                            // unsanitized HTML. The href is a hardcoded trusted URL.
                            printf(
                                /* translators: %s: WordPress link */
                                wp_kses(
                                    __( 'Powered by %s', 'cyberpunk-dark' ),
                                    array()
                                ),
                                wp_kses(
                                    '<a href="https://wordpress.org" target="_blank" rel="noopener noreferrer">WordPress</a>',
                                    array(
                                        'a' => array(
                                            'href'   => array(),
                                            'target' => array(),
                                            'rel'    => array(),
                                        ),
                                    )
                                )
                            );
                            ?>
                        </span>
                    </div>

                    <?php if ( has_nav_menu( 'footer' ) ) : ?>
                    <nav class="cyber-footer-nav" aria-label="<?php esc_attr_e( 'Footer Navigation', 'cyberpunk-dark' ); ?>">
                        <?php
                        wp_nav_menu( array(
                            'theme_location' => 'footer',
                            'menu_class'     => 'cyber-footer-menu',
                            'container'      => false,
                            'depth'          => 1,
                        ) );
                        ?>
                    </nav>
                    <?php endif; ?>

                </div><!-- .cyber-footer-bottom-grid -->
            </div><!-- .cyber-container -->
        </div><!-- .cyber-footer-bottom -->

        <!-- Decorative footer line -->
        <div class="cyber-footer-line" aria-hidden="true">
            <div class="cyber-footer-line-inner"></div>
        </div>

    </footer><!-- #colophon -->

</div><!-- #page -->

<!-- Back to top button -->
<button id="cyber-back-to-top" class="cyber-back-to-top" aria-label="<?php esc_attr_e( 'Back to top', 'cyberpunk-dark' ); ?>">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <polyline points="18 15 12 9 6 15"></polyline>
    </svg>
</button>

<?php wp_footer(); ?>
</body>
</html>

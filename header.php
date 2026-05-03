<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="profile" href="https://gmpg.org/xfn/11">
    <?php wp_head(); ?>
</head>

<body <?php body_class(); ?>>
<?php wp_body_open(); ?>

<!-- Scanline overlay -->
<div class="cyber-scanlines" aria-hidden="true"></div>

<!-- Noise texture overlay -->
<div class="cyber-noise" aria-hidden="true"></div>

<div id="page" class="site cyber-site">

    <header id="masthead" class="site-header cyber-header" role="banner">
        <div class="cyber-header-inner">

            <!-- Top bar -->
            <div class="cyber-topbar">
                <div class="cyber-container">
                    <div class="cyber-topbar-left">
                        <span class="cyber-status-indicator" aria-hidden="true"></span>
                        <span class="cyber-topbar-text"><?php echo esc_html( get_bloginfo( 'description' ) ); ?></span>
                    </div>
                    <div class="cyber-topbar-right">
                        <span class="cyber-datetime" id="cyber-datetime" aria-live="polite"></span>
                    </div>
                </div>
            </div>

            <!-- Main header -->
            <div class="cyber-header-main">
                <div class="cyber-container">
                    <div class="cyber-header-grid">

                        <!-- Site branding -->
                        <div class="site-branding cyber-branding">
                            <?php if ( has_custom_logo() ) : ?>
                                <div class="cyber-logo">
                                    <?php the_custom_logo(); ?>
                                </div>
                            <?php else : ?>
                                <div class="cyber-logo-text">
                                    <a href="<?php echo esc_url( home_url( '/' ) ); ?>" rel="home" class="cyber-site-title-link">
                                        <span class="cyber-glitch-text" data-text="<?php bloginfo( 'name' ); ?>"><?php bloginfo( 'name' ); ?></span>
                                    </a>
                                </div>
                            <?php endif; ?>
                        </div>

                        <!-- Primary navigation -->
                        <nav id="site-navigation" class="main-navigation cyber-nav" aria-label="<?php esc_attr_e( 'Primary Navigation', 'cyberpunk-dark' ); ?>">
                            <button class="menu-toggle cyber-menu-toggle" aria-controls="primary-menu" aria-expanded="false">
                                <span class="cyber-hamburger">
                                    <span></span>
                                    <span></span>
                                    <span></span>
                                </span>
                                <span class="screen-reader-text"><?php esc_html_e( 'Menu', 'cyberpunk-dark' ); ?></span>
                            </button>

                            <?php
                            wp_nav_menu( array(
                                'theme_location' => 'primary',
                                'menu_id'        => 'primary-menu',
                                'menu_class'     => 'cyber-menu',
                                'container'      => false,
                                'fallback_cb'    => 'cyberpunk_fallback_menu',
                            ) );
                            ?>
                        </nav>

                        <!-- Header actions -->
                        <div class="cyber-header-actions">
                            <button class="cyber-search-toggle" aria-label="<?php esc_attr_e( 'Toggle Search', 'cyberpunk-dark' ); ?>" aria-expanded="false">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                    <circle cx="11" cy="11" r="8"></circle>
                                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                                </svg>
                            </button>
                        </div>

                    </div><!-- .cyber-header-grid -->
                </div><!-- .cyber-container -->
            </div><!-- .cyber-header-main -->

            <!-- Search overlay -->
            <div class="cyber-search-overlay" id="cyber-search-overlay" role="dialog" aria-label="<?php esc_attr_e( 'Search', 'cyberpunk-dark' ); ?>" aria-hidden="true">
                <div class="cyber-search-inner">
                    <button class="cyber-search-close" aria-label="<?php esc_attr_e( 'Close Search', 'cyberpunk-dark' ); ?>">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                            <line x1="18" y1="6" x2="6" y2="18"></line>
                            <line x1="6" y1="6" x2="18" y2="18"></line>
                        </svg>
                    </button>
                    <?php get_search_form(); ?>
                </div>
            </div>

        </div><!-- .cyber-header-inner -->
    </header><!-- #masthead -->

    <div id="content" class="site-content cyber-content">

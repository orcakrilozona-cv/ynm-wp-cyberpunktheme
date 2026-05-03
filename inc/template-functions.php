<?php
/**
 * Template functions
 *
 * @package CyberPunk_Dark
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Add custom classes to nav menu items
 */
function cyberpunk_nav_menu_css_class( $classes, $item ) {
    if ( $item->current ) {
        $classes[] = 'cyber-menu-active';
    }
    if ( in_array( 'menu-item-has-children', $classes, true ) ) {
        $classes[] = 'cyber-has-dropdown';
    }
    return $classes;
}
add_filter( 'nav_menu_css_class', 'cyberpunk_nav_menu_css_class', 10, 2 );

/**
 * Add cyber-menu-link class to all nav links
 */
function cyberpunk_nav_menu_link_attributes( $atts, $item ) {
    $atts['class'] = isset( $atts['class'] ) ? $atts['class'] . ' cyber-menu-link' : 'cyber-menu-link';
    return $atts;
}
add_filter( 'nav_menu_link_attributes', 'cyberpunk_nav_menu_link_attributes', 10, 2 );

/**
 * Wrap search form
 */
function cyberpunk_search_form( $form ) {
    $form = '<form role="search" method="get" class="search-form cyber-search-form" action="' . esc_url( home_url( '/' ) ) . '">
        <div class="cyber-search-input-wrap">
            <input type="search" class="search-field cyber-search-field" placeholder="' . esc_attr__( 'Search the grid...', 'cyberpunk-dark' ) . '" value="' . esc_attr( get_search_query() ) . '" name="s" aria-label="' . esc_attr__( 'Search', 'cyberpunk-dark' ) . '">
            <button type="submit" class="search-submit cyber-search-submit" aria-label="' . esc_attr__( 'Submit Search', 'cyberpunk-dark' ) . '">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
            </button>
        </div>
    </form>';
    return $form;
}
add_filter( 'get_search_form', 'cyberpunk_search_form' );

/**
 * Elementor page template — full width, no header/footer
 */
function cyberpunk_elementor_canvas_template( $template ) {
    if ( is_singular() && 'elementor_canvas' === get_page_template_slug() ) {
        return $template;
    }
    return $template;
}

/**
 * Add Elementor location support
 */
function cyberpunk_register_elementor_locations( $elementor_theme_manager ) {
    $elementor_theme_manager->register_location( 'header' );
    $elementor_theme_manager->register_location( 'footer' );
    $elementor_theme_manager->register_location( 'single' );
    $elementor_theme_manager->register_location( 'archive' );
}
add_action( 'elementor/theme/register_locations', 'cyberpunk_register_elementor_locations' );

/**
 * Disable admin bar styling on front end.
 * FIX: Use wp_add_inline_style() instead of raw echo to avoid bypassing CSP
 * and to ensure the style is properly enqueued rather than injected directly.
 */
function cyberpunk_admin_bar_style() {
    if ( is_admin_bar_showing() ) {
        wp_add_inline_style( 'cyberpunk-main', '#wpadminbar { font-family: "Rajdhani", sans-serif; }' );
    }
}
add_action( 'wp_enqueue_scripts', 'cyberpunk_admin_bar_style', 30 );

/**
 * Custom image sizes in media library
 */
function cyberpunk_custom_image_sizes( $sizes ) {
    return array_merge( $sizes, array(
        'cyberpunk-featured' => esc_html__( 'CyberPunk Featured', 'cyberpunk-dark' ),
        'cyberpunk-card'     => esc_html__( 'CyberPunk Card', 'cyberpunk-dark' ),
        'cyberpunk-thumb'    => esc_html__( 'CyberPunk Thumb', 'cyberpunk-dark' ),
    ) );
}
add_filter( 'image_size_names_choose', 'cyberpunk_custom_image_sizes' );

/**
 * Preload key assets
 */
function cyberpunk_preload_assets() {
    echo '<link rel="preconnect" href="https://fonts.googleapis.com">' . "\n";
    echo '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' . "\n";
}
add_action( 'wp_head', 'cyberpunk_preload_assets', 1 );

/**
 * Schema markup for posts
 */
function cyberpunk_schema_markup() {
    if ( is_single() ) {
        $schema = array(
            '@context'  => 'https://schema.org',
            '@type'     => 'BlogPosting',
            'headline'  => get_the_title(),
            'datePublished' => get_the_date( 'c' ),
            'dateModified'  => get_the_modified_date( 'c' ),
            'author'    => array(
                '@type' => 'Person',
                'name'  => get_the_author(),
            ),
            'publisher' => array(
                '@type' => 'Organization',
                'name'  => get_bloginfo( 'name' ),
            ),
        );
        // JSON_HEX_TAG encodes < and > as \u003C / \u003E, preventing </script>
        // injection that could break out of the script block context.
        echo '<script type="application/ld+json">' . wp_json_encode( $schema, JSON_HEX_TAG | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES ) . '</script>' . "\n";
    }
}
add_action( 'wp_head', 'cyberpunk_schema_markup' );

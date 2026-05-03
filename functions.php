<?php
/**
 * CyberPunk Dark Theme Functions
 *
 * @package CyberPunk_Dark
 * @version 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Theme version
define( 'CYBERPUNK_VERSION', '1.0.0' );
define( 'CYBERPUNK_DIR', get_template_directory() );
define( 'CYBERPUNK_URI', get_template_directory_uri() );

/**
 * Theme Setup
 */
function cyberpunk_setup() {
    load_theme_textdomain( 'cyberpunk-dark', CYBERPUNK_DIR . '/languages' );

    add_theme_support( 'automatic-feed-links' );
    add_theme_support( 'title-tag' );
    add_theme_support( 'post-thumbnails' );
    add_theme_support( 'html5', array(
        'search-form', 'comment-form', 'comment-list', 'gallery', 'caption', 'style', 'script',
    ) );
    add_theme_support( 'customize-selective-refresh-widgets' );
    add_theme_support( 'wp-block-styles' );
    add_theme_support( 'align-wide' );
    add_theme_support( 'responsive-embeds' );
    add_theme_support( 'editor-styles' );

    // Custom logo
    add_theme_support( 'custom-logo', array(
        'height'      => 60,
        'width'       => 200,
        'flex-height' => true,
        'flex-width'  => true,
    ) );

    // Custom background
    add_theme_support( 'custom-background', array(
        'default-color' => '0a0a0f',
    ) );

    // Post formats
    add_theme_support( 'post-formats', array( 'aside', 'image', 'video', 'quote', 'link', 'gallery', 'audio' ) );

    // Navigation menus
    register_nav_menus( array(
        'primary'   => esc_html__( 'Primary Menu', 'cyberpunk-dark' ),
        'footer'    => esc_html__( 'Footer Menu', 'cyberpunk-dark' ),
        'social'    => esc_html__( 'Social Links Menu', 'cyberpunk-dark' ),
    ) );

    // Image sizes
    add_image_size( 'cyberpunk-featured', 1200, 600, true );
    add_image_size( 'cyberpunk-card', 600, 400, true );
    add_image_size( 'cyberpunk-thumb', 300, 200, true );
}
add_action( 'after_setup_theme', 'cyberpunk_setup' );

/**
 * Content width
 */
function cyberpunk_content_width() {
    $GLOBALS['content_width'] = apply_filters( 'cyberpunk_content_width', 1200 );
}
add_action( 'after_setup_theme', 'cyberpunk_content_width', 0 );

/**
 * Enqueue scripts and styles
 */
function cyberpunk_scripts() {
    // Google Fonts - Orbitron + Share Tech Mono
    wp_enqueue_style(
        'cyberpunk-google-fonts',
        'https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Exo+2:ital,wght@0,100..900;1,100..900&display=swap',
        array(),
        null
    );

    // Main stylesheet
    wp_enqueue_style( 'cyberpunk-style', get_stylesheet_uri(), array(), CYBERPUNK_VERSION );

    // Main CSS
    wp_enqueue_style( 'cyberpunk-main', CYBERPUNK_URI . '/assets/css/main.css', array( 'cyberpunk-style' ), CYBERPUNK_VERSION );

    // Main JS
    wp_enqueue_script( 'cyberpunk-main', CYBERPUNK_URI . '/assets/js/main.js', array( 'jquery' ), CYBERPUNK_VERSION, true );

    // Localize script
    wp_localize_script( 'cyberpunk-main', 'cyberpunkData', array(
        'ajaxUrl' => admin_url( 'admin-ajax.php' ),
        'nonce'   => wp_create_nonce( 'cyberpunk_nonce' ),
        'siteUrl' => get_site_url(),
    ) );

    if ( is_singular() && comments_open() && get_option( 'thread_comments' ) ) {
        wp_enqueue_script( 'comment-reply' );
    }
}
add_action( 'wp_enqueue_scripts', 'cyberpunk_scripts' );

/**
 * Register widget areas
 */
function cyberpunk_widgets_init() {
    $widget_args = array(
        'before_widget' => '<div id="%1$s" class="widget cyber-widget %2$s">',
        'after_widget'  => '</div>',
        'before_title'  => '<h3 class="widget-title cyber-widget-title"><span>',
        'after_title'   => '</span></h3>',
    );

    register_sidebar( array_merge( $widget_args, array(
        'name'        => esc_html__( 'Sidebar', 'cyberpunk-dark' ),
        'id'          => 'sidebar-1',
        'description' => esc_html__( 'Main sidebar widget area.', 'cyberpunk-dark' ),
    ) ) );

    register_sidebar( array_merge( $widget_args, array(
        'name'        => esc_html__( 'Footer Column 1', 'cyberpunk-dark' ),
        'id'          => 'footer-1',
        'description' => esc_html__( 'Footer widget area - column 1.', 'cyberpunk-dark' ),
    ) ) );

    register_sidebar( array_merge( $widget_args, array(
        'name'        => esc_html__( 'Footer Column 2', 'cyberpunk-dark' ),
        'id'          => 'footer-2',
        'description' => esc_html__( 'Footer widget area - column 2.', 'cyberpunk-dark' ),
    ) ) );

    register_sidebar( array_merge( $widget_args, array(
        'name'        => esc_html__( 'Footer Column 3', 'cyberpunk-dark' ),
        'id'          => 'footer-3',
        'description' => esc_html__( 'Footer widget area - column 3.', 'cyberpunk-dark' ),
    ) ) );

    register_sidebar( array_merge( $widget_args, array(
        'name'        => esc_html__( 'Footer Column 4', 'cyberpunk-dark' ),
        'id'          => 'footer-4',
        'description' => esc_html__( 'Footer widget area - column 4.', 'cyberpunk-dark' ),
    ) ) );
}
add_action( 'widgets_init', 'cyberpunk_widgets_init' );

/**
 * Include additional files
 */
require_once CYBERPUNK_DIR . '/inc/security.php';          // Security hardening — load first.
require_once CYBERPUNK_DIR . '/inc/customizer.php';
require_once CYBERPUNK_DIR . '/inc/template-functions.php';
require_once CYBERPUNK_DIR . '/inc/template-tags.php';

// Elementor compatibility — load exactly once via the hook.
// FIX: Removed the early did_action()/defined() check that caused a double
// require_once (and potential "cannot redeclare class" fatal) when Elementor
// was already loaded before this file was parsed.
add_action( 'elementor/loaded', function() {
    static $loaded = false;
    if ( $loaded ) {
        return;
    }
    $loaded = true;
    require_once CYBERPUNK_DIR . '/inc/elementor-compatibility.php';
}, 10 );

/**
 * Elementor compatibility - declare support
 */
function cyberpunk_elementor_support() {
    add_theme_support( 'elementor' );
}
add_action( 'after_setup_theme', 'cyberpunk_elementor_support' );

/**
 * Add body classes
 */
function cyberpunk_body_classes( $classes ) {
    $classes[] = 'cyberpunk-theme';

    if ( is_singular() ) {
        $classes[] = 'cyberpunk-singular';
    }

    if ( ! is_active_sidebar( 'sidebar-1' ) || is_page_template( 'page-templates/full-width.php' ) ) {
        $classes[] = 'no-sidebar';
    } else {
        $classes[] = 'has-sidebar';
    }

    return $classes;
}
add_action( 'body_class', 'cyberpunk_body_classes' );

/**
 * Custom excerpt length
 */
function cyberpunk_excerpt_length( $length ) {
    return 30;
}
add_filter( 'excerpt_length', 'cyberpunk_excerpt_length' );

/**
 * Custom excerpt more
 * FIX: esc_url() applied to get_permalink() to prevent XSS via malformed URLs.
 */
function cyberpunk_excerpt_more( $more ) {
    return '&hellip; <a class="read-more cyber-btn" href="' . esc_url( get_permalink() ) . '">' . esc_html__( 'Read More', 'cyberpunk-dark' ) . '</a>';
}
add_filter( 'excerpt_more', 'cyberpunk_excerpt_more' );

/**
 * Custom comment form fields styling
 */
function cyberpunk_comment_form_defaults( $defaults ) {
    $defaults['class_form']   = 'comment-form cyber-form';
    $defaults['class_submit'] = 'submit cyber-btn cyber-btn-primary';
    return $defaults;
}
add_filter( 'comment_form_defaults', 'cyberpunk_comment_form_defaults' );

/**
 * Pagination
 */
function cyberpunk_pagination() {
    global $wp_query;
    $big = 999999999;
    $pages = paginate_links( array(
        'base'      => str_replace( $big, '%#%', esc_url( get_pagenum_link( $big ) ) ),
        'format'    => '?paged=%#%',
        'current'   => max( 1, get_query_var( 'paged' ) ),
        'total'     => $wp_query->max_num_pages,
        'type'      => 'array',
        'prev_text' => '&laquo; ' . esc_html__( 'Prev', 'cyberpunk-dark' ),
        'next_text' => esc_html__( 'Next', 'cyberpunk-dark' ) . ' &raquo;',
    ) );

    if ( is_array( $pages ) ) {
        // paginate_links() returns trusted HTML (anchors + spans with numeric content).
        // wp_kses restricts to the exact tags/attributes it produces.
        $allowed_pagination = array(
            'a'    => array( 'href' => array(), 'class' => array(), 'aria-current' => array() ),
            'span' => array( 'class' => array(), 'aria-current' => array() ),
        );
        echo '<nav class="cyber-pagination" aria-label="' . esc_attr__( 'Posts navigation', 'cyberpunk-dark' ) . '"><ul>';
        foreach ( $pages as $page ) {
            echo '<li>' . wp_kses( $page, $allowed_pagination ) . '</li>';
        }
        echo '</ul></nav>';
    }
}

/**
 * Editor color palette
 */
function cyberpunk_editor_color_palette() {
    add_theme_support( 'editor-color-palette', array(
        array( 'name' => esc_html__( 'Neon Cyan',    'cyberpunk-dark' ), 'slug' => 'neon-cyan',    'color' => '#00f5ff' ),
        array( 'name' => esc_html__( 'Neon Magenta', 'cyberpunk-dark' ), 'slug' => 'neon-magenta', 'color' => '#ff00ff' ),
        array( 'name' => esc_html__( 'Neon Yellow',  'cyberpunk-dark' ), 'slug' => 'neon-yellow',  'color' => '#f5ff00' ),
        array( 'name' => esc_html__( 'Neon Green',   'cyberpunk-dark' ), 'slug' => 'neon-green',   'color' => '#00ff41' ),
        array( 'name' => esc_html__( 'Dark BG',      'cyberpunk-dark' ), 'slug' => 'dark-bg',      'color' => '#0a0a0f' ),
        array( 'name' => esc_html__( 'Dark Surface', 'cyberpunk-dark' ), 'slug' => 'dark-surface', 'color' => '#12121a' ),
        array( 'name' => esc_html__( 'Dark Card',    'cyberpunk-dark' ), 'slug' => 'dark-card',    'color' => '#1a1a2e' ),
        array( 'name' => esc_html__( 'Text Primary', 'cyberpunk-dark' ), 'slug' => 'text-primary', 'color' => '#e0e0e0' ),
    ) );
}
add_action( 'after_setup_theme', 'cyberpunk_editor_color_palette' );

/**
 * Enqueue editor styles
 */
function cyberpunk_add_editor_styles() {
    add_editor_style( array(
        'https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Rajdhani:wght@400;600&display=swap',
        'assets/css/editor-style.css',
    ) );
}
add_action( 'after_setup_theme', 'cyberpunk_add_editor_styles' );

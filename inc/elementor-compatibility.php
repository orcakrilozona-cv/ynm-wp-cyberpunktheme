<?php
/**
 * Elementor Compatibility
 *
 * @package CyberPunk_Dark
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Main Elementor compatibility class
 */
class CyberPunk_Elementor_Compatibility {

    /**
     * Constructor
     */
    public function __construct() {
        add_action( 'elementor/widgets/register', array( $this, 'register_widgets' ) );
        add_action( 'elementor/elements/categories_registered', array( $this, 'register_category' ) );
        add_action( 'elementor/frontend/after_enqueue_styles', array( $this, 'enqueue_elementor_styles' ) );
        add_action( 'elementor/editor/after_enqueue_styles', array( $this, 'enqueue_editor_styles' ) );
        add_filter( 'elementor/fonts/additional_fonts', array( $this, 'add_fonts' ) );
        add_action( 'elementor/kit/register_tabs', array( $this, 'register_kit_tabs' ) );
    }

    /**
     * Register custom Elementor widgets
     */
    public function register_widgets( $widgets_manager ) {
        // Load widget files — validate each resolved path stays inside the
        // expected directory to prevent path traversal via symlinks or crafted
        // filenames returned by glob() on misconfigured filesystems.
        $widget_dir   = realpath( CYBERPUNK_DIR . '/elementor-widgets' );
        $widget_files = $widget_dir ? glob( $widget_dir . '/*.php' ) : array();

        if ( $widget_files ) {
            foreach ( $widget_files as $file ) {
                // Canonicalize and confirm the file is still inside widget_dir.
                $real = realpath( $file );
                if ( false === $real || 0 !== strpos( $real, $widget_dir . DIRECTORY_SEPARATOR ) ) {
                    continue; // Skip anything that escaped the expected directory.
                }
                require_once $real;
            }
        }
    }

    /**
     * Register custom widget category
     */
    public function register_category( $elements_manager ) {
        $elements_manager->add_category( 'cyberpunk', array(
            'title' => esc_html__( 'CyberPunk Dark', 'cyberpunk-dark' ),
            'icon'  => 'fa fa-bolt',
        ) );
    }

    /**
     * Enqueue Elementor-specific styles
     */
    public function enqueue_elementor_styles() {
        wp_enqueue_style(
            'cyberpunk-elementor',
            CYBERPUNK_URI . '/assets/css/elementor.css',
            array(),
            CYBERPUNK_VERSION
        );
    }

    /**
     * Enqueue editor styles
     */
    public function enqueue_editor_styles() {
        wp_enqueue_style(
            'cyberpunk-elementor-editor',
            CYBERPUNK_URI . '/assets/css/elementor-editor.css',
            array(),
            CYBERPUNK_VERSION
        );
    }

    /**
     * Add cyberpunk fonts to Elementor font list
     */
    public function add_fonts( $fonts ) {
        $fonts['Orbitron']      = 'googlefonts';
        $fonts['Share Tech Mono'] = 'googlefonts';
        $fonts['Rajdhani']      = 'googlefonts';
        $fonts['Exo 2']         = 'googlefonts';
        return $fonts;
    }

    /**
     * Register kit tabs (global settings)
     */
    public function register_kit_tabs( $kit ) {
        // Placeholder for future kit tab registration
    }
}

// Initialize
new CyberPunk_Elementor_Compatibility();

/**
 * Override header with Elementor header if set
 */
function cyberpunk_elementor_do_header() {
    $did_location = false;
    if ( function_exists( 'elementor_theme_do_location' ) ) {
        $did_location = elementor_theme_do_location( 'header' );
    }
    return $did_location;
}

/**
 * Override footer with Elementor footer if set
 */
function cyberpunk_elementor_do_footer() {
    $did_location = false;
    if ( function_exists( 'elementor_theme_do_location' ) ) {
        $did_location = elementor_theme_do_location( 'footer' );
    }
    return $did_location;
}

/**
 * Override single with Elementor single if set
 */
function cyberpunk_elementor_do_single() {
    $did_location = false;
    if ( function_exists( 'elementor_theme_do_location' ) ) {
        $did_location = elementor_theme_do_location( 'single' );
    }
    return $did_location;
}

/**
 * Override archive with Elementor archive if set
 */
function cyberpunk_elementor_do_archive() {
    $did_location = false;
    if ( function_exists( 'elementor_theme_do_location' ) ) {
        $did_location = elementor_theme_do_location( 'archive' );
    }
    return $did_location;
}

/**
 * Add Elementor global CSS variables to match theme
 */
function cyberpunk_elementor_global_css() {
    if ( ! defined( 'ELEMENTOR_VERSION' ) ) {
        return;
    }
    $css = '
    .elementor-section,
    .e-container,
    .e-con {
        --cyber-neon-primary: var(--cyber-neon-primary, #00f5ff);
        --cyber-neon-secondary: var(--cyber-neon-secondary, #ff00ff);
        --cyber-neon-tertiary: var(--cyber-neon-tertiary, #f5ff00);
    }
    /* Elementor button overrides */
    .elementor-button {
        font-family: "Rajdhani", sans-serif;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        border-radius: 0;
        transition: all 0.3s ease;
    }
    .elementor-button-wrapper .elementor-button:hover {
        box-shadow: 0 0 20px var(--cyber-neon-primary);
    }
    /* Elementor heading overrides */
    .elementor-heading-title {
        font-family: "Orbitron", sans-serif;
    }
    /* Elementor form overrides */
    .elementor-form .elementor-field-group input,
    .elementor-form .elementor-field-group textarea,
    .elementor-form .elementor-field-group select {
        background: rgba(0, 245, 255, 0.05);
        border: 1px solid rgba(0, 245, 255, 0.3);
        color: #e0e0e0;
        border-radius: 0;
        font-family: "Share Tech Mono", monospace;
    }
    .elementor-form .elementor-field-group input:focus,
    .elementor-form .elementor-field-group textarea:focus {
        border-color: var(--cyber-neon-primary);
        box-shadow: 0 0 10px rgba(0, 245, 255, 0.2);
        outline: none;
    }
    ';
    wp_add_inline_style( 'cyberpunk-main', $css );
}
add_action( 'wp_enqueue_scripts', 'cyberpunk_elementor_global_css', 25 );

<?php
/**
 * Theme Customizer
 *
 * @package CyberPunk_Dark
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Register customizer settings
 */
function cyberpunk_customize_register( $wp_customize ) {

    // ── Colors Panel ──────────────────────────────────────────────
    $wp_customize->add_panel( 'cyberpunk_colors', array(
        'title'    => esc_html__( 'CyberPunk Colors', 'cyberpunk-dark' ),
        'priority' => 30,
    ) );

    // Neon accent color
    $wp_customize->add_section( 'cyberpunk_accent', array(
        'title' => esc_html__( 'Accent Colors', 'cyberpunk-dark' ),
        'panel' => 'cyberpunk_colors',
    ) );

    $wp_customize->add_setting( 'cyberpunk_neon_primary', array(
        'default'           => '#00f5ff',
        'sanitize_callback' => 'sanitize_hex_color',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( new WP_Customize_Color_Control( $wp_customize, 'cyberpunk_neon_primary', array(
        'label'   => esc_html__( 'Primary Neon (Cyan)', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_accent',
    ) ) );

    $wp_customize->add_setting( 'cyberpunk_neon_secondary', array(
        'default'           => '#ff00ff',
        'sanitize_callback' => 'sanitize_hex_color',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( new WP_Customize_Color_Control( $wp_customize, 'cyberpunk_neon_secondary', array(
        'label'   => esc_html__( 'Secondary Neon (Magenta)', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_accent',
    ) ) );

    $wp_customize->add_setting( 'cyberpunk_neon_tertiary', array(
        'default'           => '#f5ff00',
        'sanitize_callback' => 'sanitize_hex_color',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( new WP_Customize_Color_Control( $wp_customize, 'cyberpunk_neon_tertiary', array(
        'label'   => esc_html__( 'Tertiary Neon (Yellow)', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_accent',
    ) ) );

    // Background colors
    $wp_customize->add_section( 'cyberpunk_backgrounds', array(
        'title' => esc_html__( 'Background Colors', 'cyberpunk-dark' ),
        'panel' => 'cyberpunk_colors',
    ) );

    $wp_customize->add_setting( 'cyberpunk_bg_primary', array(
        'default'           => '#0a0a0f',
        'sanitize_callback' => 'sanitize_hex_color',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( new WP_Customize_Color_Control( $wp_customize, 'cyberpunk_bg_primary', array(
        'label'   => esc_html__( 'Primary Background', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_backgrounds',
    ) ) );

    $wp_customize->add_setting( 'cyberpunk_bg_surface', array(
        'default'           => '#12121a',
        'sanitize_callback' => 'sanitize_hex_color',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( new WP_Customize_Color_Control( $wp_customize, 'cyberpunk_bg_surface', array(
        'label'   => esc_html__( 'Surface Background', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_backgrounds',
    ) ) );

    // ── Header Panel ──────────────────────────────────────────────
    $wp_customize->add_section( 'cyberpunk_header', array(
        'title'    => esc_html__( 'Header Options', 'cyberpunk-dark' ),
        'priority' => 40,
    ) );

    $wp_customize->add_setting( 'cyberpunk_sticky_header', array(
        'default'           => true,
        'sanitize_callback' => 'cyberpunk_sanitize_checkbox',
        'transport'         => 'refresh',
    ) );
    $wp_customize->add_control( 'cyberpunk_sticky_header', array(
        'label'   => esc_html__( 'Sticky Header', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_header',
        'type'    => 'checkbox',
    ) );

    $wp_customize->add_setting( 'cyberpunk_header_blur', array(
        'default'           => true,
        'sanitize_callback' => 'cyberpunk_sanitize_checkbox',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( 'cyberpunk_header_blur', array(
        'label'   => esc_html__( 'Header Backdrop Blur', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_header',
        'type'    => 'checkbox',
    ) );

    // ── Effects Panel ─────────────────────────────────────────────
    $wp_customize->add_section( 'cyberpunk_effects', array(
        'title'    => esc_html__( 'Visual Effects', 'cyberpunk-dark' ),
        'priority' => 50,
    ) );

    $wp_customize->add_setting( 'cyberpunk_scanlines', array(
        'default'           => true,
        'sanitize_callback' => 'cyberpunk_sanitize_checkbox',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( 'cyberpunk_scanlines', array(
        'label'   => esc_html__( 'Scanline Overlay', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_effects',
        'type'    => 'checkbox',
    ) );

    $wp_customize->add_setting( 'cyberpunk_glitch_logo', array(
        'default'           => true,
        'sanitize_callback' => 'cyberpunk_sanitize_checkbox',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( 'cyberpunk_glitch_logo', array(
        'label'   => esc_html__( 'Glitch Effect on Logo', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_effects',
        'type'    => 'checkbox',
    ) );

    $wp_customize->add_setting( 'cyberpunk_particles', array(
        'default'           => true,
        'sanitize_callback' => 'cyberpunk_sanitize_checkbox',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( 'cyberpunk_particles', array(
        'label'   => esc_html__( 'Particle Background Effect', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_effects',
        'type'    => 'checkbox',
    ) );

    // ── Footer Section ────────────────────────────────────────────
    $wp_customize->add_section( 'cyberpunk_footer', array(
        'title'    => esc_html__( 'Footer Options', 'cyberpunk-dark' ),
        'priority' => 60,
    ) );

    $wp_customize->add_setting( 'cyberpunk_footer_text', array(
        'default'           => '',
        'sanitize_callback' => 'wp_kses_post',
        'transport'         => 'postMessage',
    ) );
    $wp_customize->add_control( 'cyberpunk_footer_text', array(
        'label'   => esc_html__( 'Footer Custom Text', 'cyberpunk-dark' ),
        'section' => 'cyberpunk_footer',
        'type'    => 'textarea',
    ) );
}
add_action( 'customize_register', 'cyberpunk_customize_register' );

/**
 * Sanitize checkbox
 */
function cyberpunk_sanitize_checkbox( $checked ) {
    return ( isset( $checked ) && true === $checked ) ? true : false;
}

/**
 * Sanitize a hex color with a mandatory fallback.
 *
 * sanitize_hex_color() returns '' (empty string) for invalid input, which
 * would produce broken CSS like `--cyber-neon-primary: ;` and could be
 * exploited to inject a CSS value by storing a crafted theme mod before
 * the sanitize_callback fires (e.g. via direct DB manipulation or a race).
 * This wrapper enforces a safe default so the CSS property is always valid.
 *
 * @param  string $value    Raw color value from get_theme_mod().
 * @param  string $fallback Safe hex color to use if $value is invalid.
 * @return string           Valid hex color string.
 */
function cyberpunk_sanitize_hex_color_with_fallback( $value, $fallback ) {
    $sanitized = sanitize_hex_color( $value );
    return ( '' !== $sanitized && null !== $sanitized ) ? $sanitized : $fallback;
}

function cyberpunk_customizer_css() {
    $neon_primary   = get_theme_mod( 'cyberpunk_neon_primary',   '#00f5ff' );
    $neon_secondary = get_theme_mod( 'cyberpunk_neon_secondary', '#ff00ff' );
    $neon_tertiary  = get_theme_mod( 'cyberpunk_neon_tertiary',  '#f5ff00' );
    $bg_primary     = get_theme_mod( 'cyberpunk_bg_primary',     '#0a0a0f' );
    $bg_surface     = get_theme_mod( 'cyberpunk_bg_surface',     '#12121a' );
    $scanlines      = get_theme_mod( 'cyberpunk_scanlines',      true );
    $header_blur    = get_theme_mod( 'cyberpunk_header_blur',    true );

    // FIX: Use wrapper that enforces fallback — sanitize_hex_color() alone
    // returns '' on invalid input, which produces broken/injectable CSS.
    $css = ':root {';
    $css .= '--cyber-neon-primary: '   . cyberpunk_sanitize_hex_color_with_fallback( $neon_primary,   '#00f5ff' ) . ';';
    $css .= '--cyber-neon-secondary: ' . cyberpunk_sanitize_hex_color_with_fallback( $neon_secondary, '#ff00ff' ) . ';';
    $css .= '--cyber-neon-tertiary: '  . cyberpunk_sanitize_hex_color_with_fallback( $neon_tertiary,  '#f5ff00' ) . ';';
    $css .= '--cyber-bg-primary: '     . cyberpunk_sanitize_hex_color_with_fallback( $bg_primary,     '#0a0a0f' ) . ';';
    $css .= '--cyber-bg-surface: '     . cyberpunk_sanitize_hex_color_with_fallback( $bg_surface,     '#12121a' ) . ';';
    $css .= '}';

    if ( ! $scanlines ) {
        $css .= '.cyber-scanlines { display: none; }';
    }

    if ( ! $header_blur ) {
        $css .= '.cyber-header { backdrop-filter: none; -webkit-backdrop-filter: none; }';
    }

    wp_add_inline_style( 'cyberpunk-main', $css );
}
add_action( 'wp_enqueue_scripts', 'cyberpunk_customizer_css', 20 );

/**
 * Customizer live preview JS
 */
function cyberpunk_customize_preview_js() {
    wp_enqueue_script(
        'cyberpunk-customizer',
        CYBERPUNK_URI . '/assets/js/customizer.js',
        array( 'customize-preview' ),
        CYBERPUNK_VERSION,
        true
    );
}
add_action( 'customize_preview_init', 'cyberpunk_customize_preview_js' );

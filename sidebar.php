<?php
/**
 * Sidebar template
 *
 * @package CyberPunk_Dark
 */

if ( ! is_active_sidebar( 'sidebar-1' ) ) {
    return;
}
?>

<aside id="secondary" class="widget-area cyber-sidebar" role="complementary" aria-label="<?php esc_attr_e( 'Sidebar', 'cyberpunk-dark' ); ?>">
    <div class="cyber-sidebar-inner">
        <?php dynamic_sidebar( 'sidebar-1' ); ?>
    </div>
</aside>

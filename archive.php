<?php
/**
 * Archive template
 *
 * @package CyberPunk_Dark
 */

get_header();
?>

<div class="cyber-container">
    <div id="primary" class="content-area cyber-primary <?php echo is_active_sidebar( 'sidebar-1' ) ? 'has-sidebar' : 'full-width'; ?>">
        <main id="main" class="site-main cyber-main" role="main">

            <?php if ( have_posts() ) : ?>

                <header class="page-header cyber-page-header cyber-archive-header">
                    <div class="cyber-archive-header-inner">
                        <?php
                        the_archive_title( '<h1 class="page-title cyber-page-title cyber-glitch-text" data-text="' . esc_attr( wp_strip_all_tags( get_the_archive_title() ) ) . '">', '</h1>' );
                        the_archive_description( '<div class="archive-description cyber-archive-desc">', '</div>' );
                        ?>
                    </div>
                </header>

                <div class="cyber-posts-grid">
                    <?php while ( have_posts() ) : the_post(); ?>
                        <?php
                        // Sanitize post type to a slug before using as a template-part suffix
                        // to prevent path traversal / LFI via a crafted post type name.
                        $post_type_slug = sanitize_key( get_post_type() );
                        get_template_part( 'template-parts/content', $post_type_slug );
                        ?>
                    <?php endwhile; ?>
                </div>

                <?php cyberpunk_pagination(); ?>

            <?php else : ?>

                <?php get_template_part( 'template-parts/content', 'none' ); ?>

            <?php endif; ?>

        </main>
    </div>

    <?php get_sidebar(); ?>
</div>

<?php get_footer(); ?>

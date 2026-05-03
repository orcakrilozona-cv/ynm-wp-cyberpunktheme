<?php
/**
 * Main template file
 *
 * @package CyberPunk_Dark
 */

get_header();
?>

<div class="cyber-container">
    <div id="primary" class="content-area cyber-primary <?php echo is_active_sidebar( 'sidebar-1' ) ? 'has-sidebar' : 'full-width'; ?>">
        <main id="main" class="site-main cyber-main" role="main">

            <?php if ( have_posts() ) : ?>

                <?php if ( is_home() && ! is_front_page() ) : ?>
                    <header class="page-header cyber-page-header">
                        <h1 class="page-title cyber-page-title">
                            <?php single_post_title(); ?>
                        </h1>
                    </header>
                <?php endif; ?>

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

        </main><!-- #main -->
    </div><!-- #primary -->

    <?php get_sidebar(); ?>

</div><!-- .cyber-container -->

<?php get_footer(); ?>

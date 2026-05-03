<?php
/**
 * Page template
 *
 * @package CyberPunk_Dark
 */

get_header();
?>

<div class="cyber-container">
    <div id="primary" class="content-area cyber-primary cyber-page <?php echo is_active_sidebar( 'sidebar-1' ) ? 'has-sidebar' : 'full-width'; ?>">
        <main id="main" class="site-main cyber-main" role="main">

            <?php while ( have_posts() ) : the_post(); ?>

                <article id="post-<?php the_ID(); ?>" <?php post_class( 'cyber-article cyber-page-article' ); ?>>

                    <header class="entry-header cyber-entry-header">
                        <?php the_title( '<h1 class="entry-title cyber-entry-title">', '</h1>' ); ?>
                    </header>

                    <?php if ( has_post_thumbnail() ) : ?>
                    <div class="post-thumbnail cyber-featured-image">
                        <div class="cyber-image-wrapper">
                            <?php the_post_thumbnail( 'cyberpunk-featured', array( 'alt' => get_the_title() ) ); ?>
                            <div class="cyber-image-overlay" aria-hidden="true"></div>
                        </div>
                    </div>
                    <?php endif; ?>

                    <div class="entry-content cyber-entry-content">
                        <?php
                        the_content();
                        wp_link_pages( array(
                            'before'      => '<div class="page-links cyber-page-links">' . esc_html__( 'Pages:', 'cyberpunk-dark' ),
                            'after'       => '</div>',
                            'link_before' => '<span class="cyber-page-link">',
                            'link_after'  => '</span>',
                        ) );
                        ?>
                    </div>

                    <?php if ( get_edit_post_link() ) : ?>
                    <footer class="entry-footer cyber-entry-footer">
                        <?php edit_post_link( esc_html__( 'Edit Page', 'cyberpunk-dark' ), '<span class="edit-link cyber-edit-link">', '</span>' ); ?>
                    </footer>
                    <?php endif; ?>

                </article>

                <?php if ( comments_open() || get_comments_number() ) : ?>
                    <?php comments_template(); ?>
                <?php endif; ?>

            <?php endwhile; ?>

        </main>
    </div>

    <?php get_sidebar(); ?>
</div>

<?php get_footer(); ?>

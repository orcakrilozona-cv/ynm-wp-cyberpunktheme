<?php
/**
 * Single post template
 *
 * @package CyberPunk_Dark
 */

get_header();
?>

<div class="cyber-container">
    <div id="primary" class="content-area cyber-primary cyber-single <?php echo is_active_sidebar( 'sidebar-1' ) ? 'has-sidebar' : 'full-width'; ?>">
        <main id="main" class="site-main cyber-main" role="main">

            <?php while ( have_posts() ) : the_post(); ?>

                <article id="post-<?php the_ID(); ?>" <?php post_class( 'cyber-article cyber-single-post' ); ?>>

                    <!-- Post header -->
                    <header class="entry-header cyber-entry-header">
                        <?php cyberpunk_post_categories(); ?>
                        <h1 class="entry-title cyber-entry-title"><?php echo esc_html( get_the_title() ); ?></h1>
                        <div class="entry-meta cyber-entry-meta">
                            <?php cyberpunk_post_meta(); ?>
                        </div>
                    </header>

                    <!-- Featured image -->
                    <?php if ( has_post_thumbnail() ) : ?>
                    <div class="post-thumbnail cyber-featured-image">
                        <div class="cyber-image-wrapper">
                            <?php the_post_thumbnail( 'cyberpunk-featured', array( 'alt' => get_the_title() ) ); ?>
                            <div class="cyber-image-overlay" aria-hidden="true"></div>
                        </div>
                    </div>
                    <?php endif; ?>

                    <!-- Post content -->
                    <div class="entry-content cyber-entry-content">
                        <?php
                        the_content( sprintf(
                            wp_kses(
                                /* translators: %s: Name of current post. */
                                __( 'Continue reading<span class="screen-reader-text"> "%s"</span>', 'cyberpunk-dark' ),
                                array( 'span' => array( 'class' => array() ) )
                            ),
                            wp_kses_post( get_the_title() )
                        ) );

                        wp_link_pages( array(
                            'before'      => '<div class="page-links cyber-page-links">' . esc_html__( 'Pages:', 'cyberpunk-dark' ),
                            'after'       => '</div>',
                            'link_before' => '<span class="cyber-page-link">',
                            'link_after'  => '</span>',
                        ) );
                        ?>
                    </div>

                    <!-- Post footer -->
                    <footer class="entry-footer cyber-entry-footer">
                        <?php cyberpunk_post_tags(); ?>
                    </footer>

                </article>

                <!-- Post navigation -->
                <nav class="navigation post-navigation cyber-post-nav" aria-label="<?php esc_attr_e( 'Post navigation', 'cyberpunk-dark' ); ?>">
                    <div class="nav-links cyber-nav-links">
                        <div class="nav-previous cyber-nav-prev">
                            <?php previous_post_link( '%link', '<span class="nav-label">' . esc_html__( '&laquo; Previous', 'cyberpunk-dark' ) . '</span><span class="nav-title">%title</span>' ); ?>
                        </div>
                        <div class="nav-next cyber-nav-next">
                            <?php next_post_link( '%link', '<span class="nav-label">' . esc_html__( 'Next &raquo;', 'cyberpunk-dark' ) . '</span><span class="nav-title">%title</span>' ); ?>
                        </div>
                    </div>
                </nav>

                <!-- Author bio -->
                <?php if ( get_the_author_meta( 'description' ) ) : ?>
                <div class="author-bio cyber-author-bio">
                    <div class="cyber-author-avatar">
                        <?php echo get_avatar( get_the_author_meta( 'ID' ), 80, '', get_the_author(), array( 'class' => 'cyber-avatar' ) ); ?>
                    </div>
                    <div class="cyber-author-info">
                        <h3 class="cyber-author-name">
                            <a href="<?php echo esc_url( get_author_posts_url( get_the_author_meta( 'ID' ) ) ); ?>">
                                <?php the_author(); ?>
                            </a>
                        </h3>
                        <p class="cyber-author-desc"><?php echo esc_html( get_the_author_meta( 'description' ) ); ?></p>
                    </div>
                </div>
                <?php endif; ?>

                <!-- Comments -->
                <?php
                if ( comments_open() || get_comments_number() ) {
                    comments_template();
                }
                ?>

            <?php endwhile; ?>

        </main>
    </div>

    <?php get_sidebar(); ?>
</div>

<?php get_footer(); ?>

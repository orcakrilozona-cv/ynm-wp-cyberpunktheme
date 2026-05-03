<?php
/**
 * Search results template
 *
 * @package CyberPunk_Dark
 */

get_header();
?>

<div class="cyber-container">
    <div id="primary" class="content-area cyber-primary <?php echo is_active_sidebar( 'sidebar-1' ) ? 'has-sidebar' : 'full-width'; ?>">
        <main id="main" class="site-main cyber-main" role="main">

            <header class="page-header cyber-page-header cyber-search-header">
                <h1 class="page-title cyber-page-title">
                    <?php
                    printf(
                        /* translators: %s: search query */
                        esc_html__( 'Search Results: %s', 'cyberpunk-dark' ),
                        '<span class="cyber-search-term">' . esc_html( get_search_query() ) . '</span>'
                    );
                    ?>
                </h1>
                <div class="cyber-search-form-wrap">
                    <?php get_search_form(); ?>
                </div>
            </header>

            <?php if ( have_posts() ) : ?>

                <div class="cyber-posts-grid">
                    <?php while ( have_posts() ) : the_post(); ?>
                        <?php get_template_part( 'template-parts/content', 'search' ); ?>
                    <?php endwhile; ?>
                </div>

                <?php cyberpunk_pagination(); ?>

            <?php else : ?>

                <div class="cyber-no-results">
                    <div class="cyber-no-results-inner">
                        <div class="cyber-no-results-icon" aria-hidden="true">
                            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                                <circle cx="11" cy="11" r="8"></circle>
                                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                                <line x1="8" y1="11" x2="14" y2="11"></line>
                            </svg>
                        </div>
                        <h2 class="cyber-no-results-title">
                            <?php esc_html_e( 'No signals found', 'cyberpunk-dark' ); ?>
                        </h2>
                        <p class="cyber-no-results-text">
                            <?php esc_html_e( 'Your search returned no results. Try different keywords or browse the archive.', 'cyberpunk-dark' ); ?>
                        </p>
                    </div>
                </div>

                <?php get_template_part( 'template-parts/content', 'none' ); ?>

            <?php endif; ?>

        </main>
    </div>

    <?php get_sidebar(); ?>
</div>

<?php get_footer(); ?>

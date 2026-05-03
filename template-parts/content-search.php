<?php
/**
 * Search result content template part
 *
 * @package CyberPunk_Dark
 */
?>

<article id="post-<?php the_ID(); ?>" <?php post_class( 'cyber-card cyber-post-card cyber-search-result' ); ?>>

    <div class="cyber-card-body">
        <header class="entry-header cyber-card-header">
            <?php cyberpunk_post_categories(); ?>
            <?php the_title( '<h2 class="entry-title cyber-card-title"><a href="' . esc_url( get_permalink() ) . '" rel="bookmark">', '</a></h2>' ); ?>
            <div class="entry-meta cyber-card-meta">
                <?php cyberpunk_post_meta(); ?>
            </div>
        </header>

        <div class="entry-summary cyber-card-excerpt">
            <?php the_excerpt(); ?>
        </div>

        <footer class="entry-footer cyber-card-footer">
            <a href="<?php the_permalink(); ?>" class="cyber-btn cyber-btn-outline cyber-read-more">
                <span><?php esc_html_e( 'Access File', 'cyberpunk-dark' ); ?></span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <line x1="5" y1="12" x2="19" y2="12"></line>
                    <polyline points="12 5 19 12 12 19"></polyline>
                </svg>
            </a>
            <span class="cyber-search-type">
                <?php echo esc_html( get_post_type_object( get_post_type() )->labels->singular_name ); ?>
            </span>
        </footer>
    </div>

</article>

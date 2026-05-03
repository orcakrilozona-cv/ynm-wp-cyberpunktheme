<?php
/**
 * Default content template part
 *
 * @package CyberPunk_Dark
 */
?>

<article id="post-<?php the_ID(); ?>" <?php post_class( 'cyber-card cyber-post-card' ); ?>>

    <?php if ( has_post_thumbnail() ) : ?>
    <div class="cyber-card-image">
        <a href="<?php the_permalink(); ?>" tabindex="-1" aria-hidden="true">
            <?php the_post_thumbnail( 'cyberpunk-card', array( 'alt' => '' ) ); ?>
            <div class="cyber-card-image-overlay" aria-hidden="true"></div>
        </a>
        <?php cyberpunk_post_categories(); ?>
    </div>
    <?php else : ?>
    <div class="cyber-card-no-image">
        <?php cyberpunk_post_categories(); ?>
    </div>
    <?php endif; ?>

    <div class="cyber-card-body">
        <header class="entry-header cyber-card-header">
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
        </footer>
    </div>

</article>

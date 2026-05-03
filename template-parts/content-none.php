<?php
/**
 * No content template part
 *
 * @package CyberPunk_Dark
 */
?>

<section class="no-results not-found cyber-no-results">
    <div class="cyber-no-results-inner">
        <div class="cyber-no-results-icon" aria-hidden="true">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>
        </div>
        <header class="page-header cyber-page-header">
            <h1 class="page-title cyber-page-title">
                <?php esc_html_e( 'No Data Found', 'cyberpunk-dark' ); ?>
            </h1>
        </header>
        <div class="page-content cyber-no-results-content">
            <?php if ( is_home() && current_user_can( 'publish_posts' ) ) : ?>
                <p>
                    <?php
                    printf(
                        wp_kses(
                            /* translators: %s: link to new post */
                            __( 'Ready to publish your first post? <a href="%s">Get started here</a>.', 'cyberpunk-dark' ),
                            array( 'a' => array( 'href' => array() ) )
                        ),
                        esc_url( admin_url( 'post-new.php' ) )
                    );
                    ?>
                </p>
            <?php elseif ( is_search() ) : ?>
                <p><?php esc_html_e( 'No transmissions matched your query. Try different search parameters.', 'cyberpunk-dark' ); ?></p>
                <?php get_search_form(); ?>
            <?php else : ?>
                <p><?php esc_html_e( 'This sector of the grid appears to be empty. Try navigating to a different node.', 'cyberpunk-dark' ); ?></p>
                <a href="<?php echo esc_url( home_url( '/' ) ); ?>" class="cyber-btn cyber-btn-primary">
                    <?php esc_html_e( 'Return to Base', 'cyberpunk-dark' ); ?>
                </a>
            <?php endif; ?>
        </div>
    </div>
</section>

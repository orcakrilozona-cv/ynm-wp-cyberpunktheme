<?php
/**
 * 404 template
 *
 * @package CyberPunk_Dark
 */

get_header();
?>

<div class="cyber-container">
    <div id="primary" class="content-area cyber-primary full-width">
        <main id="main" class="site-main cyber-main" role="main">

            <section class="error-404 not-found cyber-404">
                <div class="cyber-404-inner">

                    <div class="cyber-404-code" aria-hidden="true">
                        <span class="cyber-glitch-text" data-text="404">404</span>
                    </div>

                    <header class="page-header cyber-page-header">
                        <h1 class="page-title cyber-page-title">
                            <?php esc_html_e( 'Signal Lost', 'cyberpunk-dark' ); ?>
                        </h1>
                        <p class="cyber-404-subtitle">
                            <?php esc_html_e( 'The page you are looking for has been disconnected from the grid.', 'cyberpunk-dark' ); ?>
                        </p>
                    </header>

                    <div class="page-content cyber-404-content">
                        <div class="cyber-404-terminal">
                            <div class="cyber-terminal-bar" aria-hidden="true">
                                <span></span><span></span><span></span>
                            </div>
                            <div class="cyber-terminal-body">
                                <p class="cyber-terminal-line"><span class="cyber-prompt" aria-hidden="true">&gt;</span> <span class="cyber-cmd">locate --path <span class="cyber-404-url"><?php echo esc_html( cyberpunk_sanitize_input( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ) ); ?></span></span></p>
                                <p class="cyber-terminal-line cyber-terminal-error"><span class="cyber-prompt" aria-hidden="true">&gt;</span> ERROR: Node not found in network topology</p>
                                <p class="cyber-terminal-line"><span class="cyber-prompt" aria-hidden="true">&gt;</span> Suggested actions:</p>
                            </div>
                        </div>

                        <div class="cyber-404-actions">
                            <a href="<?php echo esc_url( home_url( '/' ) ); ?>" class="cyber-btn cyber-btn-primary">
                                <?php esc_html_e( 'Return to Base', 'cyberpunk-dark' ); ?>
                            </a>
                            <div class="cyber-404-search">
                                <p><?php esc_html_e( 'Or search the grid:', 'cyberpunk-dark' ); ?></p>
                                <?php get_search_form(); ?>
                            </div>
                        </div>

                    </div>
                </div>
            </section>

        </main>
    </div>
</div>

<?php get_footer(); ?>

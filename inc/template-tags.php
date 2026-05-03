<?php
/**
 * Template tags
 *
 * @package CyberPunk_Dark
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Post meta output
 */
function cyberpunk_post_meta() {
    $time_string = '<time class="entry-date published updated" datetime="%1$s">%2$s</time>';
    if ( get_the_time( 'U' ) !== get_the_modified_time( 'U' ) ) {
        $time_string = '<time class="entry-date published" datetime="%1$s">%2$s</time><time class="updated" datetime="%3$s">%4$s</time>';
    }

    $time_string = sprintf(
        $time_string,
        esc_attr( get_the_date( DATE_W3C ) ),
        esc_html( get_the_date() ),
        esc_attr( get_the_modified_date( DATE_W3C ) ),
        esc_html( get_the_modified_date() )
    );

    echo '<span class="posted-on cyber-meta-date">';
    echo '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>';
    echo '<a href="' . esc_url( get_permalink() ) . '" rel="bookmark">' . $time_string . '</a>';
    echo '</span>';

    echo '<span class="byline cyber-meta-author">';
    echo '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>';
    echo '<a href="' . esc_url( get_author_posts_url( get_the_author_meta( 'ID' ) ) ) . '">' . esc_html( get_the_author() ) . '</a>';
    echo '</span>';

    if ( ! is_single() && ! post_password_required() && ( comments_open() || get_comments_number() ) ) {
        echo '<span class="comments-link cyber-meta-comments">';
        echo '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>';
        comments_popup_link(
            esc_html__( '0', 'cyberpunk-dark' ),
            esc_html__( '1', 'cyberpunk-dark' ),
            esc_html__( '%', 'cyberpunk-dark' )
        );
        echo '</span>';
    }

    $reading_time = cyberpunk_reading_time();
    if ( $reading_time ) {
        echo '<span class="cyber-meta-reading-time">';
        echo '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>';
        echo esc_html( $reading_time );
        echo '</span>';
    }
}

/**
 * Post categories
 */
function cyberpunk_post_categories() {
    $categories = get_the_category();
    if ( empty( $categories ) ) {
        return;
    }
    echo '<div class="cyber-categories">';
    foreach ( array_slice( $categories, 0, 2 ) as $cat ) {
        echo '<a href="' . esc_url( get_category_link( $cat->term_id ) ) . '" class="cyber-category-badge">' . esc_html( $cat->name ) . '</a>';
    }
    echo '</div>';
}

/**
 * Post tags
 */
function cyberpunk_post_tags() {
    $tags = get_the_tags();
    if ( empty( $tags ) ) {
        return;
    }
    echo '<div class="cyber-tags">';
    echo '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"></path><line x1="7" y1="7" x2="7.01" y2="7"></line></svg>';
    foreach ( $tags as $tag ) {
        echo '<a href="' . esc_url( get_tag_link( $tag->term_id ) ) . '" class="cyber-tag">#' . esc_html( $tag->name ) . '</a>';
    }
    echo '</div>';
}

/**
 * Estimated reading time
 */
function cyberpunk_reading_time() {
    $content    = get_post_field( 'post_content', get_the_ID() );
    $word_count = str_word_count( strip_tags( $content ) );
    $minutes    = (int) ceil( $word_count / 200 );
    if ( $minutes < 1 ) {
        return false;
    }
    return sprintf(
        /* translators: %d: minutes */
        _n( '%d min read', '%d min read', $minutes, 'cyberpunk-dark' ),
        $minutes
    );
}

/**
 * Fallback menu
 */
function cyberpunk_fallback_menu() {
    echo '<ul id="primary-menu" class="cyber-menu">';
    echo '<li><a href="' . esc_url( home_url( '/' ) ) . '">' . esc_html__( 'Home', 'cyberpunk-dark' ) . '</a></li>';
    if ( current_user_can( 'manage_options' ) ) {
        echo '<li><a href="' . esc_url( admin_url( 'nav-menus.php' ) ) . '">' . esc_html__( 'Add Menu', 'cyberpunk-dark' ) . '</a></li>';
    }
    echo '</ul>';
}

/**
 * Comment callback
 */
function cyberpunk_comment_callback( $comment, $args, $depth ) {
    $tag = ( 'div' === $args['style'] ) ? 'div' : 'li';
    ?>
    <<?php echo esc_attr( $tag ); ?> id="comment-<?php comment_ID(); ?>" <?php comment_class( 'cyber-comment', $comment ); ?>>
        <article id="div-comment-<?php comment_ID(); ?>" class="comment-body cyber-comment-body">
            <footer class="comment-meta cyber-comment-meta">
                <div class="comment-author vcard cyber-comment-author">
                    <?php echo get_avatar( $comment, $args['avatar_size'], '', '', array( 'class' => 'cyber-comment-avatar' ) ); ?>
                    <div class="cyber-comment-author-info">
                        <?php
                        // get_comment_author_link() returns an <a> whose href is the
                        // user-supplied comment_author_url — not run through esc_url().
                        // Build the author display safely instead.
                        $author_url  = get_comment_author_url( $comment );
                        $author_name = get_comment_author( $comment );
                        if ( $author_url && 'http://' !== $author_url ) {
                            printf(
                                '<b class="fn"><a href="%s" rel="nofollow ugc noopener noreferrer" target="_blank">%s</a></b>',
                                esc_url( $author_url ),
                                esc_html( $author_name )
                            );
                        } else {
                            printf( '<b class="fn">%s</b>', esc_html( $author_name ) );
                        }
                        ?>
                        <div class="comment-metadata cyber-comment-date">
                            <a href="<?php echo esc_url( get_comment_link( $comment, $args ) ); ?>">
                                <time datetime="<?php comment_time( 'c' ); ?>">
                                    <?php
                                    printf(
                                        /* translators: 1: date, 2: time */
                                        esc_html__( '%1$s at %2$s', 'cyberpunk-dark' ),
                                        esc_html( get_comment_date( '', $comment ) ),
                                        esc_html( get_comment_time() )
                                    );
                                    ?>
                                </time>
                            </a>
                            <?php edit_comment_link( esc_html__( 'Edit', 'cyberpunk-dark' ), '<span class="edit-link cyber-edit-link">', '</span>' ); ?>
                        </div>
                    </div>
                </div>
            </footer>

            <div class="comment-content cyber-comment-content">
                <?php if ( '0' === $comment->comment_approved ) : ?>
                    <p class="comment-awaiting-moderation cyber-moderation">
                        <?php esc_html_e( 'Transmission pending clearance.', 'cyberpunk-dark' ); ?>
                    </p>
                <?php endif; ?>
                <?php comment_text(); ?>
            </div>

            <?php
            comment_reply_link( array_merge( $args, array(
                'add_below' => 'div-comment',
                'depth'     => $depth,
                'max_depth' => $args['max_depth'],
                'before'    => '<div class="reply cyber-reply">',
                'after'     => '</div>',
            ) ) );
            ?>
        </article>
    <?php
}

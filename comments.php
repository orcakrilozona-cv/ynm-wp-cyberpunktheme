<?php
/**
 * Comments template
 *
 * @package CyberPunk_Dark
 */

if ( post_password_required() ) {
    return;
}
?>

<div id="comments" class="comments-area cyber-comments">

    <?php if ( have_comments() ) : ?>

        <h2 class="comments-title cyber-comments-title">
            <?php
            $comment_count = get_comments_number();
            if ( '1' === $comment_count ) {
                printf(
                    /* translators: %s: post title */
                    esc_html__( 'One transmission on &ldquo;%s&rdquo;', 'cyberpunk-dark' ),
                    '<span>' . wp_kses_post( get_the_title() ) . '</span>'
                );
            } else {
                printf(
                    /* translators: 1: comment count, 2: post title */
                    esc_html( _nx( '%1$s transmission on &ldquo;%2$s&rdquo;', '%1$s transmissions on &ldquo;%2$s&rdquo;', $comment_count, 'comments title', 'cyberpunk-dark' ) ),
                    number_format_i18n( $comment_count ),
                    '<span>' . wp_kses_post( get_the_title() ) . '</span>'
                );
            }
            ?>
        </h2>

        <ol class="comment-list cyber-comment-list">
            <?php
            wp_list_comments( array(
                'style'       => 'ol',
                'short_ping'  => true,
                'avatar_size' => 50,
                'callback'    => 'cyberpunk_comment_callback',
            ) );
            ?>
        </ol>

        <?php the_comments_navigation( array(
            'prev_text' => esc_html__( '&laquo; Older transmissions', 'cyberpunk-dark' ),
            'next_text' => esc_html__( 'Newer transmissions &raquo;', 'cyberpunk-dark' ),
        ) ); ?>

    <?php endif; ?>

    <?php if ( ! comments_open() && get_comments_number() && post_type_supports( get_post_type(), 'comments' ) ) : ?>
        <p class="no-comments cyber-no-comments">
            <?php esc_html_e( 'Transmissions are closed.', 'cyberpunk-dark' ); ?>
        </p>
    <?php endif; ?>

    <?php
    comment_form( array(
        'title_reply'          => esc_html__( 'Send a Transmission', 'cyberpunk-dark' ),
        'title_reply_to'       => esc_html__( 'Reply to %s', 'cyberpunk-dark' ),
        'title_reply_before'   => '<h3 id="reply-title" class="comment-reply-title cyber-reply-title">',
        'title_reply_after'    => '</h3>',
        'cancel_reply_link'    => esc_html__( 'Cancel', 'cyberpunk-dark' ),
        'label_submit'         => esc_html__( 'Transmit', 'cyberpunk-dark' ),
        'submit_button'        => '<input name="%1$s" type="submit" id="%2$s" class="%3$s cyber-btn cyber-btn-primary" value="%4$s">',
        'class_container'      => 'comment-respond cyber-comment-respond',
        'fields'               => array(
            'author' => '<p class="comment-form-author cyber-form-field"><label for="author">' . esc_html__( 'Handle', 'cyberpunk-dark' ) . ' <span class="required" aria-hidden="true">*</span></label><input id="author" name="author" type="text" value="' . esc_attr( isset( $commenter['comment_author'] ) ? $commenter['comment_author'] : '' ) . '" size="30" maxlength="245" autocomplete="name" required></p>',
            'email'  => '<p class="comment-form-email cyber-form-field"><label for="email">' . esc_html__( 'Encrypted Channel (Email)', 'cyberpunk-dark' ) . ' <span class="required" aria-hidden="true">*</span></label><input id="email" name="email" type="email" value="' . esc_attr( isset( $commenter['comment_author_email'] ) ? $commenter['comment_author_email'] : '' ) . '" size="30" maxlength="100" autocomplete="email" required></p>',
            'url'    => '<p class="comment-form-url cyber-form-field"><label for="url">' . esc_html__( 'Node Address (URL)', 'cyberpunk-dark' ) . '</label><input id="url" name="url" type="url" value="' . esc_attr( isset( $commenter['comment_author_url'] ) ? $commenter['comment_author_url'] : '' ) . '" size="30" maxlength="200" autocomplete="url"></p>',
        ),
        'comment_field'        => '<p class="comment-form-comment cyber-form-field"><label for="comment">' . esc_html__( 'Message', 'cyberpunk-dark' ) . ' <span class="required" aria-hidden="true">*</span></label><textarea id="comment" name="comment" cols="45" rows="8" maxlength="65525" required></textarea></p>',
    ) );
    ?>

</div><!-- #comments -->

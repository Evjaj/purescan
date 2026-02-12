<?php
/**
 * PureScan Email Notifier
 *
 * Handles sending HTML email notifications upon scheduled scan completion.
 * Includes translatable subject, body, and template with dynamic data.
 *
 * @package PureScan
 */
namespace PureScan;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Email_Notifier {
    /**
     * Send completion email if configured and applicable.
     *
     * Checks settings, prepares data, and sends HTML email with scan summary.
     * Marks email as sent in state to prevent duplicates.
     *
     * @param array $state Current scan state array.
     */
    public static function send_scan_complete_email( array $state ): void {
        if ( ! empty( $state['email_sent'] ) ) {
            return;
        }

        $settings = \PureScan\Settings\Settings_Handler::get();

        if ( empty( $settings['scheduled_scan_send_email'] ) ) {
            return;
        }

        $to = get_option( 'admin_email' );

        if ( ! is_email( $to ) ) {
            return;
        }

        $site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
        $site_url  = home_url();
        $admin_url = admin_url( 'admin.php?page=purescan&tab=deep-scan' );
        $settings_url = admin_url( 'admin.php?page=purescan&tab=settings' );
        $unsubscribe_url = $settings_url . '#email-notifications';

        $host = preg_replace( '/^www\./i', '', wp_parse_url( $site_url, PHP_URL_HOST ) );

        $suspicious_count = (int) ( $state['suspicious'] ?? 0 );
        $scanned_count    = number_format_i18n( (int) ( $state['scanned'] ?? 0 ) );
        $completed_at     = date_i18n( 'F j, Y \a\t H:i', strtotime( $state['completed'] ?? current_time( 'mysql' ) ) );

        // Subject line with conditional plural handling
        if ( $suspicious_count > 0 ) {
            // translators: %1$d = number of detected issues, %2$s = site hostname
            $translated_part = __( 'Scan Completed – %1$d Issue(s) Detected on %2$s', 'purescan' );
        
            $subject = sprintf( '[PureScan Alert] ' . $translated_part, $suspicious_count, $host );
        } else {
            // translators: %s = site hostname
            $translated_part = __( 'Scan Completed – No Issues Found on %s', 'purescan' );
        
            $subject = sprintf( '[PureScan Alert] ' . $translated_part, $host );
        }

        $body = self::get_email_template( [
            'site_name'        => $site_name,
            'site_url'         => $site_url,
            'admin_url'        => $admin_url,
            'suspicious_count' => $suspicious_count,
            'scanned_count'    => $scanned_count,
            'completed_at'     => $completed_at,
            'is_clean'         => ( $suspicious_count === 0 ),
            'unsubscribe_url'  => $unsubscribe_url,
        ] );

        $from_email = self::detect_from_email();

        $headers = [
            'From: ' . esc_html( $site_name ) . ' <' . sanitize_email( $from_email ) . '>',
            'Content-Type: text/html; charset=UTF-8',
        ];

        add_filter( 'wp_mail_content_type', [ __CLASS__, 'force_html_content_type' ] );
        $sent = wp_mail( $to, $subject, $body, $headers );
        remove_filter( 'wp_mail_content_type', [ __CLASS__, 'force_html_content_type' ] );

        if ( $sent ) {
            $state['email_sent'] = true;
            update_option( 'purescan_state', $state, false );
        }
    }

    /**
     * Force HTML content type for wp_mail.
     *
     * @return string Content type 'text/html'.
     */
    public static function force_html_content_type(): string {
        return 'text/html';
    }

    /**
     * Detect a safe "From" email address.
     *
     * Uses wordpress@domain.com format.
     *
     * @return string Generated email address.
     */
    private static function detect_from_email(): string {
        $domain = preg_replace( '/^www\./', '', wp_parse_url( home_url(), PHP_URL_HOST ) );
        return 'wordpress@' . $domain;
    }

    /**
     * Generate the full HTML email template.
     *
     * Builds a responsive, styled email with dynamic content.
     *
     * @param array $data {
     *     Template variables.
     *
     *     @type string $site_name        Site name.
     *     @type string $site_url         Site URL.
     *     @type string $admin_url        Admin scan URL.
     *     @type int    $suspicious_count Number of suspicious files.
     *     @type string $scanned_count    Formatted scanned file count.
     *     @type string $completed_at     Completion timestamp.
     *     @type bool   $is_clean         Whether scan was clean.
     *     @type string $unsubscribe_url  Settings URL for unsubscribing.
     * }
     *
     * @return string Complete HTML email body.
     */
    private static function get_email_template( array $data ): string {
        $is_clean = ! empty( $data['is_clean'] );

        $title = $is_clean
            ? esc_html__( 'Scan Completed Successfully', 'purescan' )
            : esc_html__( 'Security Scan Alert', 'purescan' );

        if ( $is_clean ) {
            // translators: %1$s = site name, %2$s = completion time
            $intro = sprintf( esc_html__( 'This email was sent from your website "%1$s" by the PureScan plugin at %2$s.', 'purescan' ), $data['site_name'], $data['completed_at'] );
        } else {
            // translators: %1$s = site name, %2$s = completion time
            $intro = sprintf( esc_html__( 'Attention: The scan detected potential issues on "%1$s" at %2$s.', 'purescan' ), $data['site_name'], $data['completed_at'] );
        }

        if ( $is_clean ) {
            $message = esc_html__( 'No suspicious files or issues were detected during the scheduled scan.', 'purescan' );
        } else {
            // translators: %d = number of suspicious files
            $message = sprintf( _n( '%d suspicious file detected during the scan.', '%d suspicious files detected during the scan.', $data['suspicious_count'], 'purescan' ), $data['suspicious_count'] );
        }

        $button_text = esc_html__( 'View Scan Details', 'purescan' );

        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title><?php echo esc_html( $title ); ?></title>
            <style>
                body {font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f7f7f7; color: #111;}
                .container {max-width: 600px; margin: 20px auto; padding: 20px; background: #fff; border: 1px solid #ddd;}
                h1 {font-size: 16px; margin-bottom: 10px;}
                p {font-size: 14px; margin-bottom: 10px; line-height: 1.5;}
                a.btn {display: inline-block; padding: 8px 14px; background: #0073aa; color: #fff; text-decoration: none; border-radius: 4px; margin: 10px 0;}
                .stats {margin: 15px 0; padding: 10px; background: #f9f9f9; border: 1px solid #eee;}
                .stats p {margin: 5px 0;}
                .footer {font-size: 12px; color: #666; margin-top: 20px;}
                .footer a {color: #0073aa;}
            </style>
        </head>
        <body>
            <div class="container">
                <h1><?php echo esc_html( $title ); ?></h1>
                <p><?php echo esc_html( $intro ); ?></p>
                <p><?php echo esc_html( $message ); ?></p>
                <div class="stats">
                    <p><strong><?php esc_html_e( 'Scan Completed At:', 'purescan' ); ?></strong> <?php echo esc_html( $data['completed_at'] ); ?></p>
                    <p><strong><?php esc_html_e( 'Files Scanned:', 'purescan' ); ?></strong> <?php echo esc_html( $data['scanned_count'] ); ?></p>
                    <p><strong><?php esc_html_e( 'Issues Detected:', 'purescan' ); ?></strong> <?php echo esc_html( $data['suspicious_count'] ); ?></p>
                </div>
                <p>
                    <a href="<?php echo esc_url( $data['admin_url'] ); ?>" class="btn">
                        <?php echo esc_html( $button_text ); ?>
                    </a>
                </p>
                <div class="footer">
                    <?php echo esc_html( $data['site_name'] ); ?> | <?php echo esc_url( $data['site_url'] ); ?><br>
                    <?php esc_html_e( 'This is an automated message generated by the PureScan security plugin.', 'purescan' ); ?><br>
                    <a href="<?php echo esc_url( $data['unsubscribe_url'] ); ?>">
                        <?php esc_html_e( 'Manage email notification settings (turn off scan emails)', 'purescan' ); ?>
                    </a>
                </div>
            </div>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }
}
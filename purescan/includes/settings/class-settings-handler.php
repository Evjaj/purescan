<?php
/**
 * PureScan Settings Handler
 * Manages plugin options with defaults, validation, and smart OpenRouter key/model selection.
 *
 * @package PureScan\Settings
 */
namespace PureScan\Settings;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Settings_Handler {
    const OPTION_NAME = PURESCAN_OPTION;

    /**
     * Default settings
     */
    public static function get_defaults() {
        return [
            'max_files'                  => 500000,
            'max_read_mb'                => 5,
            'include_paths'              => '',
            'exclude_paths'              => "wp-content/uploads\nwp-content/cache\nwp-content/backup",
            'openrouter_api_key'         => '',
            'openrouter_model'           => '', // Selected model in manual mode
            'openrouter_connected'       => false,
            'api_source'                 => 'external', // 'external' or 'manual'
            'ai_deep_scan_enabled'       => false,
            'admin_token'                => wp_generate_uuid4(),
            'scheduled_scan_enabled'     => false,
            'scheduled_scan_frequency'   => 'daily', // daily | weekly | monthly
            'scheduled_scan_day'         => 'monday',
            'scheduled_scan_date'        => '1',
            'scheduled_scan_time'        => '02:00',
            'scheduled_scan_send_email'  => true,
            'external_scan_enabled'      => false,
            'database_deep_scan_enabled' => false, // Disabled by default
            'ai_features_enabled'        => false, // Disabled by default
        ];
    }

    /**
     * Get current settings with defaults applied
     */
    public static function get() {
        $defaults = self::get_defaults();
        $saved    = get_option( self::OPTION_NAME, [] );

        if ( empty( $saved['admin_token'] ) ) {
            $saved['admin_token'] = wp_generate_uuid4();
        }

        // Pro is active only if the PureScan Pro addon is installed and active
        $is_pro = defined( 'PURESCAN_PRO_ACTIVE' ) && PURESCAN_PRO_ACTIVE;

        if ( ! $is_pro ) {
            $pro_keys = [
                'external_scan_enabled',
                'ai_deep_scan_enabled',
                'scheduled_scan_enabled',
                'database_deep_scan_enabled',
            ];

            $need_update = false;
            foreach ( $pro_keys as $key ) {
                if ( ! empty( $saved[ $key ] ) ) {
                    $saved[ $key ] = false;
                    $need_update   = true;
                }
            }

            if ( $need_update ) {
                update_option( self::OPTION_NAME, $saved );
            }
        }

        return wp_parse_args( $saved, $defaults );
    }

    public static function fetch_external_api_key() {
        return false;
    }

    /**
     * Save settings via AJAX
     */
    public static function save_settings() {
        check_ajax_referer( PURESCAN_NONCE, 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die();
        }

        // Reset all settings to defaults
        if ( ! empty( $_POST['reset'] ) ) {
            delete_option( self::OPTION_NAME );
            wp_clear_scheduled_hook( 'purescan_scheduled_scan' );
            wp_send_json_success( [ 'message' => __( 'Settings reset to defaults.', 'purescan' ) ] );
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Settings array is manually sanitized in sanitize_settings() below.
        $input = wp_unslash( $_POST['settings'] ?? [] );

        if ( ! is_array( $input ) ) {
            wp_send_json_error( 'Invalid data format' );
        }

        $sanitized = self::sanitize_settings( $input );
        $validated = self::validate_settings( $sanitized );

        // Pro check – force Pro features off in free version
        $is_pro = defined( 'PURESCAN_PRO_ACTIVE' ) && PURESCAN_PRO_ACTIVE;

        if ( ! $is_pro ) {
            $validated['scheduled_scan_enabled']     = false;
            $validated['external_scan_enabled']      = false;
            $validated['database_deep_scan_enabled'] = false;
            $validated['ai_deep_scan_enabled']       = false;
        }

        if ( is_wp_error( $validated ) ) {
            wp_send_json_error( $validated->get_error_message() );
        }

        if ( empty( $validated['ai_features_enabled'] ) ) {
            $validated['ai_deep_scan_enabled'] = false;
        }

        // Save the new settings
        update_option( self::OPTION_NAME, $validated );

        // ==================================================================
        // Scheduled Automatic Scan – Cron Management (FIXED & RELIABLE)
        // ==================================================================

        // Always clear any existing scheduled event to prevent duplicates or conflicts
        wp_clear_scheduled_hook( 'purescan_scheduled_scan' );

        // Only schedule if automatic scans are enabled (and Pro is active – already enforced above)
        if ( ! empty( $validated['scheduled_scan_enabled'] ) ) {
            $next_timestamp = self::calculate_next_scheduled_time( $validated );

            // Ensure the next run is in the future
            if ( $next_timestamp && $next_timestamp > time() ) {
                // Convert local server time to UTC for wp-cron (required!)
                $next_utc = get_gmt_from_date( date_i18n( 'Y-m-d H:i:00', $next_timestamp ), 'U' );

                // Use SINGLE event – this is the correct way for daily/weekly/monthly schedules
                wp_schedule_single_event( $next_utc, 'purescan_scheduled_scan' );
            }
        }

        wp_send_json_success( [ 'message' => __( 'Settings saved successfully.', 'purescan' ) ] );
    }

    /**
     * Calculate the exact next run timestamp based on frequency, day, date, and time
     *
     * @param array $settings Validated settings array
     * @return int|false Unix timestamp of next run, or false on failure
     */
    public static function calculate_next_scheduled_time( $settings ) {
        $frequency = $settings['scheduled_scan_frequency'] ?? 'daily';

        // Support both "HH" (old) and "HH:MM" (new) formats
        $time_parts = explode( ':', ( $settings['scheduled_scan_time'] ?? '02:00' ) );
        $hour       = (int) ( $time_parts[0] ?? 2 );
        $minute     = (int) ( $time_parts[1] ?? 0 );

        $target_time = sprintf( '%02d:%02d', $hour, $minute );
        $now         = current_time( 'timestamp' );

        switch ( $frequency ) {
            case 'daily':
                $today        = current_time( 'Y-m-d' );
                $today_target = strtotime( "{$today} {$target_time}:00" );

                if ( $today_target > $now ) {
                    return $today_target;
                }

                return strtotime( '+1 day ' . $target_time . ':00', $now );

            case 'weekly':
                $day_name = $settings['scheduled_scan_day'] ?? 'monday';
                $days_map = [
                    'monday'    => 'Monday',
                    'tuesday'   => 'Tuesday',
                    'wednesday' => 'Wednesday',
                    'thursday'  => 'Thursday',
                    'friday'    => 'Friday',
                    'saturday'  => 'Saturday',
                    'sunday'    => 'Sunday',
                ];
                $target_day = $days_map[ $day_name ] ?? 'Monday';

                $candidate = strtotime( "next {$target_day} {$target_time}:00", $now );

                if ( strtolower( date_i18n( 'l', $now ) ) === strtolower( $target_day ) && $candidate > $now ) {
                    // Today is the target day and time hasn't passed → use today
                } elseif ( strtolower( date_i18n( 'l', $now ) ) === strtolower( $target_day ) && $candidate <= $now ) {
                    $candidate = strtotime( '+1 week', $candidate );
                }

                return $candidate;

            case 'monthly':
                $day_of_month = max( 1, min( 31, (int) ( $settings['scheduled_scan_date'] ?? 1 ) ) );

                $current_month = (int) current_time( 'n' );
                $current_year  = (int) current_time( 'Y' );

                $target_month = $current_month + 1;
                $target_year  = $current_year;
                if ( $target_month > 12 ) {
                    $target_month = 1;
                    $target_year++;
                }

                $last_day_of_target_month = cal_days_in_month( CAL_GREGORIAN, $target_month, $target_year );
                $actual_day               = min( $day_of_month, $last_day_of_target_month );

                $candidate = mktime( $hour, $minute, 0, $target_month, $actual_day, $target_year );

                if ( $candidate <= $now ) {
                    $target_month++;
                    if ( $target_month > 12 ) {
                        $target_month = 1;
                        $target_year++;
                    }
                    $last_day_next    = cal_days_in_month( CAL_GREGORIAN, $target_month, $target_year );
                    $actual_day_next  = min( $day_of_month, $last_day_next );
                    $candidate        = mktime( $hour, $minute, 0, $target_month, $actual_day_next, $target_year );
                }

                return $candidate;

            default:
                return strtotime( "tomorrow {$target_time}:00", $now );
        }
    }

    /**
     * Callback executed by the scheduled cron event
     * ONLY sets a lightweight flag – no direct scanning occurs here.
     * This makes it fully shared-hosting friendly and avoids any timeout or overload issues.
     */
    public static function run_scheduled_scan_callback() {
        $settings = self::get();

        if ( empty( $settings['scheduled_scan_enabled'] ) ) {
            return;
        }

        $state = get_option( PURESCAN_STATE, [] );

        // If a scan is already running → mark as missed
        if ( ! empty( $state['status'] ) && $state['status'] === 'running' ) {
            update_option( 'purescan_last_scheduled_missed', true, false );
            return;
        }

        // Clear any previous missed flag on successful trigger
        delete_option( 'purescan_last_scheduled_missed' );

        // Monthly frequency: handle "31st" gracefully in shorter months
        if ( $settings['scheduled_scan_frequency'] === 'monthly' ) {
            $today_day    = (int) date_i18n( 'j' );
            $last_day     = (int) date_i18n( 't' );
            $target_day   = (int) $settings['scheduled_scan_date'];
            $effective_day = min( $target_day, $last_day );

            if ( $today_day !== $effective_day ) {
                return;
            }
        }

        // Set the background flag – this triggers opportunistic execution
        update_option( 'purescan_background_flag', time(), false );

        // Re-schedule the next run ONLY if no scan is currently running
        if ( empty( $state['status'] ) || $state['status'] !== 'running' ) {
            $next_timestamp = self::calculate_next_scheduled_time( $settings );
            if ( $next_timestamp && $next_timestamp > time() ) {
                $next_utc = get_gmt_from_date( date_i18n( 'Y-m-d H:i:00', $next_timestamp ), 'U' );
                wp_schedule_single_event( $next_utc, 'purescan_scheduled_scan' );
            }
        }
    }

    /**
     * Test OpenRouter connection — Professional & strict verification with distinct prompts
     */
    public static function test_openrouter_connection() {
        check_ajax_referer( PURESCAN_NONCE, 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Unauthorized' );
        }

        $source = sanitize_text_field( wp_unslash( $_POST['source'] ?? 'external' ) );

        if ( $source === 'manual' ) {
            $key   = trim( sanitize_text_field( wp_unslash( $_POST['api_key'] ?? '' ) ) );
            $model = sanitize_text_field( wp_unslash( $_POST['model'] ?? '' ) );

            if ( empty( $key ) || empty( $model ) ) {
                wp_send_json_error( 'API key and model are required.' );
            }

            // Distinct prompt for Manual mode
            $expected = 'Manual OpenRouter API key verified successfully. Your personal key is working perfectly.';
            $prompt   = 'Respond with ONLY this exact sentence and nothing else: "' . $expected . '"';

            $response = wp_remote_post(
                'https://openrouter.ai/api/v1/chat/completions',
                [
                    'timeout'  => 60,
                    'headers'  => [
                        'Authorization' => 'Bearer ' . $key,
                        'HTTP-Referer' => home_url(),
                        'X-Title'      => 'PureScan',
                        'Content-Type' => 'application/json',
                    ],
                    'body'     => wp_json_encode(
                        [
                            'model'       => $model,
                            'messages'    => [ [ 'role' => 'user', 'content' => $prompt ] ],
                            'temperature' => 0.1,
                        ]
                    ),
                ]
            );

            if ( is_wp_error( $response ) ) {
                wp_send_json_error( 'Network error: ' . $response->get_error_message() );
            }

            $code = wp_remote_retrieve_response_code( $response );
            $body = json_decode( wp_remote_retrieve_body( $response ), true );

            if ( $code !== 200 ) {
                $msg = $body['error']['message'] ?? 'Unknown error (HTTP ' . $code . ')';
                if ( $code === 429 ) {
                    $msg = 'Rate limit reached. Please try again later.';
                }
                if ( $code === 401 ) {
                    $msg = 'Invalid or revoked API key.';
                }
                wp_send_json_error( '<strong>Connection failed:</strong><br>' . $msg );
            }

            $reply = trim( $body['choices'][0]['message']['content'] ?? '' );
            if ( $reply !== $expected ) {
                wp_send_json_error( '<strong>Test failed:</strong><br>AI did not respond exactly as expected.' );
            }

            wp_send_json_success(
                [
                    'ai_response' => $reply,
                    'source'      => 'manual',
                    'model'       => $model,
                ]
            );

        } else {
            // External mode – force fresh key selection
            delete_option( 'purescan_active_external_key' );

            $client = new \PureScan\AI_Client();
            if ( ! $client->is_connected() ) {
                wp_send_json_error( 'No working keys available from server.' );
            }

            // Distinct prompt for External mode
            $expected = 'External server fallback key verified successfully. PureScan default integration is active.';
            $prompt   = 'Respond with ONLY this exact sentence and nothing else: "' . $expected . '"';

            $result = $client->chat(
                [
                    [ 'role' => 'user', 'content' => $prompt ],
                ],
                null,
                0.1
            );

            if ( is_wp_error( $result ) ) {
                $msg = $result->get_error_message();
                if ( str_contains( $msg, '429' ) ) {
                    $msg = 'Rate limit reached on all keys.';
                }
                wp_send_json_error( '<strong>Connection failed:</strong><br>' . $msg );
            }

            $reply = trim( $result );
            if ( $reply !== $expected ) {
                wp_send_json_error( '<strong>Test failed:</strong><br>AI did not respond exactly as expected.' );
            }

            wp_send_json_success(
                [
                    'ai_response' => $reply,
                    'source'      => 'external',
                    'model'       => $client->get_current_model(),
                ]
            );
        }
    }

    /**
     * Sanitize incoming settings
     */
    private static function sanitize_settings( $input ) {
        $sanitized = [];

        // Max files to scan
        $max_files_input = trim( $input['max_files'] ?? '' );
        if ( $max_files_input === '' || $max_files_input === '0' ) {
            $sanitized['max_files'] = 0;
        } else {
            $sanitized['max_files'] = max( 100, absint( $max_files_input ) );
        }

        $sanitized['max_read_mb']     = absint( $input['max_read_mb'] ?? 5 );
        $sanitized['include_paths']   = sanitize_textarea_field( $input['include_paths'] ?? '' );
        $sanitized['exclude_paths']   = sanitize_textarea_field( $input['exclude_paths'] ?? '' );
        $sanitized['openrouter_connected'] = ! empty( $input['openrouter_connected'] );
        $sanitized['ai_deep_scan_enabled'] = ! empty( $input['ai_deep_scan_enabled'] );
        $sanitized['ai_features_enabled']  = ! empty( $input['ai_features_enabled'] );
        $sanitized['openrouter_api_key']   = trim( sanitize_text_field( $input['openrouter_api_key'] ?? '' ) );
        $sanitized['openrouter_model']     = sanitize_text_field( $input['openrouter_model'] ?? '' );
        $sanitized['api_source'] = in_array( $input['api_source'] ?? '', [ 'manual', 'external' ] ) ? $input['api_source'] : 'external';

        // Scheduled scan settings
        $sanitized['scheduled_scan_enabled']    = ! empty( $input['scheduled_scan_enabled'] );
        $sanitized['scheduled_scan_send_email'] = ! empty( $input['scheduled_scan_send_email'] );

        $sanitized['scheduled_scan_frequency'] = in_array( $input['scheduled_scan_frequency'] ?? '', [ 'daily', 'weekly', 'monthly' ] )
            ? $input['scheduled_scan_frequency']
            : 'daily';

        $valid_days = [ 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday' ];
        $sanitized['scheduled_scan_day'] = in_array( $input['scheduled_scan_day'] ?? '', $valid_days )
            ? $input['scheduled_scan_day']
            : 'monday';

        $day_of_month                    = absint( $input['scheduled_scan_date'] ?? 1 );
        $sanitized['scheduled_scan_date'] = ( $day_of_month >= 1 && $day_of_month <= 31 ) ? $day_of_month : 1;

        // Handle separate hour and minute fields
        $hour                             = max( 0, min( 23, absint( $input['scheduled_scan_hour'] ?? 2 ) ) );
        $minute                           = max( 0, min( 59, absint( $input['scheduled_scan_minute'] ?? 0 ) ) );

        $sanitized['scheduled_scan_time'] = sprintf( '%02d:%02d', $hour, $minute );

        // Admin token
        $current                          = get_option( self::OPTION_NAME, [] );
        $sanitized['admin_token']         = $current['admin_token'] ?? wp_generate_uuid4();

        // External scan toggle
        $sanitized['external_scan_enabled']      = ! empty( $input['external_scan_enabled'] );
        $sanitized['database_deep_scan_enabled'] = ! empty( $input['database_deep_scan_enabled'] );

        return $sanitized;
    }

    /**
     * Validate settings
     */
    private static function validate_settings( $settings ) {
        $errors = new \WP_Error();

        if ( ! empty( $settings['max_files'] ) && $settings['max_files'] < 100 ) {
            $errors->add( 'max_files', __( 'Maximum files must be at least 100 or left empty for unlimited.', 'purescan' ) );
        }
        if ( $settings['max_read_mb'] < 1 || $settings['max_read_mb'] > 50 ) {
            $errors->add( 'max_read_mb', __( 'Maximum file read size must be between 1 and 50 MB.', 'purescan' ) );
        }

        if ( ! empty( $settings['openrouter_connected'] ) ) {
            if ( $settings['api_source'] === 'manual' ) {
                if ( empty( trim( $settings['openrouter_api_key'] ) ) ) {
                    $errors->add( 'openrouter_api_key', __( 'API key is required in Manual mode.', 'purescan' ) );
                }
                if ( empty( trim( $settings['openrouter_model'] ) ) ) {
                    $errors->add( 'openrouter_model', __( 'You must select an AI model.', 'purescan' ) );
                }
            }
        } else {
            if ( ( $settings['api_source'] ?? 'external' ) === 'manual' ) {
                $errors->add( 'connection_test_required', __( 'Please test your API connection successfully before saving.', 'purescan' ) );
            }
        }

        return $errors->has_errors() ? $errors : $settings;
    }

    /**
     * Reset all settings to defaults
     */
    public static function reset_to_defaults() {
        delete_option( self::OPTION_NAME );
        return self::get();
    }
}
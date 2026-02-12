<?php
/**
 * PureScan Live Search UI
 *
 * Renders the Live Search tab with real-time file search,
 * instant results, and unified scan result display (identical to Deep Scan).
 *
 * @package PureScan\Search
 */

namespace PureScan\Search;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Search_UI {
    /**
     * Render the content for the Live Search tab.
     *
     * Displays the search input, results list, hints, and scan result container.
     * All visible text is fully translatable and properly escaped.
     */
    public static function render(): void {
        ?>
        <div class="purescan-card">
            <h2 class="purescan-section-title"><?php esc_html_e( 'Live Search', 'purescan' ); ?></h2>
            <p class="purescan-description">
                <?php esc_html_e( 'Search files by name or path in real-time. Click any file to scan it instantly.', 'purescan' ); ?>
            </p>

            <!-- Search Input -->
            <div class="purescan-search-container">
                <input
                    type="text"
                    id="purescan-live-search"
                    placeholder="<?php esc_attr_e( 'Type to search files...', 'purescan' ); ?>"
                    class="purescan-search-input"
                    autocomplete="off"
                >
                <div id="purescan-search-spinner" class="purescan-spinner" style="display:none;"></div>
            </div>

            <!-- Results List (file matches) -->
            <div id="purescan-search-results" class="purescan-search-results" style="display:none;">
                <div class="purescan-results-header">
                    <span id="purescan-results-count">0</span> <?php esc_html_e( 'files found', 'purescan' ); ?>
                    <span id="purescan-truncated-warning" style="display:none;color:#f59e0b;">
                        <?php esc_html_e( '(Showing first 50 results – refine your search for more)', 'purescan' ); ?>
                    </span>
                </div>
                <div id="purescan-results-list"></div>
            </div>

            <!-- No Results Message -->
            <div id="purescan-no-results" class="purescan-no-results" style="display:none;">
                <?php esc_html_e( 'No files found. Try a different search term.', 'purescan' ); ?>
            </div>

            <!-- Minimum Length Hint -->
            <div id="purescan-min-length" class="purescan-hint">
                <?php
                // translators: %d = minimum number of characters required for search
                $translated_hint = esc_html__( 'Enter at least %d characters to search.', 'purescan' );
            
                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- The string is already safely escaped with esc_html__(), and the placeholder value is escaped below.
                printf( $translated_hint, esc_html( (int) Search_Engine::MIN_QUERY_LENGTH ) );
                ?>
            </div>

            <!-- Unified Scan Result for Selected File -->
            <div id="purescan-live-search-scan-result" style="margin-top:40px;display:none;">
                <h3 class="purescan-section-title"><?php esc_html_e( 'Scan Result for Selected File', 'purescan' ); ?></h3>
                <div id="purescan-live-search-finding-container">
                    <!-- Finding HTML injected via AJAX (matches Deep Scan rendering) -->
                </div>
            </div>
        </div>
        <?php
    }
}
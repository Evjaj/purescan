<?php
/**
 * PureScan File Differences Viewer
 *
 * All visible texts are translatable using WordPress translation functions with proper escaping.
 *
 * @package PureScan
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once ABSPATH . WPINC . '/Text/Diff.php';
require_once ABSPATH . WPINC . '/Text/Diff/Renderer.php';
require_once ABSPATH . WPINC . '/Text/Diff/Renderer/inline.php';
require_once PURESCAN_DIR . 'includes/diff-renderer-table.php';

/**
 * Render the file differences viewer.
 *
 * Compares the current file content with the official version (PureScan plugin or WordPress core)
 * and displays a clean, side-by-side diff with fixed-width line numbers.
 *
 * @param string $file_path       Relative path to the file (from site root).
 * @param string $current_content Current content of the file on the site.
 */
function purescan_render_file_diff( string $file_path, string $current_content ): void {
	// Normalize PureScan plugin paths for consistent handling.
	if ( strpos( $file_path, 'PureScan/' ) === 0 ) {
		$file_path = 'wp-content/plugins/purescan/' . str_replace( 'PureScan/', '', $file_path );
	}

	$full_path      = ABSPATH . ltrim( $file_path, '/' );
	$is_plugin_file = strpos( $file_path, 'wp-content/plugins/purescan/' ) === 0;

	$filename = esc_html( basename( $file_path ) );
	$filesize = size_format( filesize( $full_path ) );
	$modified = date_i18n( 'M j, Y @ H:i', filemtime( $full_path ) );

	// Retrieve official (original) file content.
	$official_content = '';

	if ( $is_plugin_file ) {
		// PureScan plugin file – fetch from official server with token.
		$rel_path       = str_replace( 'wp-content/plugins/purescan/', '', $file_path );
		$token_response = wp_remote_get( 'https://www.evjaj.com/purescan-get-token', [ 'timeout' => 15 ] );

		if ( ! is_wp_error( $token_response ) && wp_remote_retrieve_response_code( $token_response ) === 200 ) {
			$token_data = json_decode( wp_remote_retrieve_body( $token_response ), true );

			if ( ! empty( $token_data['token'] ) && ! empty( $token_data['expires'] ) ) {
				$official_url = 'https://www.evjaj.com/purescan-official-file?file=' . urlencode( $rel_path );
				$response     = wp_remote_get(
					$official_url,
					[
						'timeout' => 30,
						'headers' => [
							'X-PureScan-Token'    => $token_data['token'],
							'X-PureScan-Expires' => $token_data['expires'],
						],
					]
				);

				if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
					$official_content = wp_remote_retrieve_body( $response );
				}
			}
		}
	} else {
		// WordPress core file – fetch from official SVN.
		$wp_version   = get_bloginfo( 'version' );
		$official_url = "https://core.svn.wordpress.org/tags/{$wp_version}/" . ltrim( $file_path, '/' );
		$response     = wp_remote_get( $official_url, [ 'timeout' => 30 ] );

		if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
			$official_content = wp_remote_retrieve_body( $response );
		}
	}

	if ( empty( $official_content ) ) {
		wp_die(
			esc_html__( 'PureScan: Unable to retrieve the official version of this file for comparison.', 'purescan' ),
			'',
			[ 'response' => 404 ]
		);
	}

	// Compute diff.
	$original_lines = explode( "\n", $official_content );
	$current_lines  = explode( "\n", $current_content );

	$diff     = new Text_Diff( 'auto', [ $original_lines, $current_lines ] );
	$renderer = new PureScan_Text_Diff_Renderer_Table();
	$diff_html = $renderer->render( $diff );

	// Translatable titles and notes (escaped for output).
	$left_title  = $is_plugin_file
		? esc_html__( 'Original PureScan Version', 'purescan' )
		: esc_html__( 'Original WordPress Version', 'purescan' );

	$footer_note = $is_plugin_file
		? esc_html__( 'File Comparison with Official PureScan Release', 'purescan' )
		: esc_html__( 'File Comparison with Official WordPress Core', 'purescan' );
	?>

	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<title><?php echo esc_html( $filename ); ?> - <?php esc_html_e( 'File Differences', 'purescan' ); ?> - PureScan</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<style>
			body {
				margin: 0;
				font-family: system-ui, -apple-system, sans-serif;
				background: #fafafa;
				color: #24292e;
				line-height: 1.6;
			}
			.container {
				max-width: 1800px;
				margin: 20px auto;
				background: #fff;
				border: 1px solid #d0d7de;
				border-radius: 12px;
				overflow: hidden;
				box-shadow: 0 10px 30px rgba(0,0,0,.08);
			}
			.header {
				padding: 30px 40px;
				background: #f6f8fa;
				border-bottom: 1px solid #d0d7de;
			}
			.title {
				font-size: 28px;
				font-weight: 600;
				margin: 0;
				display: flex;
				align-items: center;
				gap: 12px;
			}
			.info {
				margin-top: 12px;
				font-size: 15px;
				color: #555;
			}
			.legend {
				margin: 20px 40px;
				padding: 16px;
				background: #fffbeb;
				border: 1px solid #f0b72a;
				border-radius: 8px;
				font-size: 15px;
				line-height: 1.6;
			}
			table.diff {
				width: 100%;
				border-collapse: collapse;
				table-layout: fixed;
				font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
				font-size: 14.2px;
			}
			table.diff th {
				padding: 14px;
				text-align: center;
				font-weight: 600;
				background: #f6f8fa;
				border-bottom: 3px solid #d0d7de;
				position: sticky;
				top: 0;
				z-index: 10;
			}
			col.line-old, col.line-new { width: 55px; }
			col.code-old, col.code-new { width: calc(50% - 55px); }
			tr.deleted-row td { background: #ffebe9 !important; }
			tr.added-row td { background: #e6ffec !important; }
			tr.changed-row td { background: #fff8c5 !important; }
			td.empty { opacity: 0.7; }
			.code.context { background: transparent; }
			.code.deleted { background: #ffebe9; border-left: 4px solid #cf222e; }
			.code.added { background: #e6ffec; border-left: 4px solid #1a7f37; }
			.code.changed-old, .code.changed-new { background: #fff8c5; border-left: 4px solid #9a6700; }
			.code.empty { background: #f0f0f0; opacity: .7; }
			td.line-num {
				width: 55px !important;
				min-width: 55px !important;
				max-width: 55px !important;
				background: #f6f8fa;
				color: #656d76;
				text-align: right;
				padding: 6px 10px 6px 0 !important;
				font-size: 13px;
				user-select: none;
				border-right: 1px solid #e1e4e8;
				font-family: ui-monospace, monospace;
			}
			td.code {
				padding: 6px 14px !important;
				word-break: break-all;
				font-family: ui-monospace, SFMono-Regular, "Fira Code", Menlo, monospace;
				font-size: 14px;
				line-height: 1.5;
			}
			td.deleted { background: #ffeef0 !important; }
			td.added { background: #e6ffed !important; }
			del {
				background: #fdd;
				color: #d73a49;
				padding: 0 3px;
				border-radius: 3px;
				text-decoration: none;
			}
			ins {
				background: #d4f8db;
				color: #22863a;
				padding: 0 3px;
				border-radius: 3px;
				text-decoration: none;
			}
			.footer {
				text-align: center;
				padding: 30px;
				color: #fff;
				font-size: 14px;
				background: #10b981;
				border-top: 1px solid #eaecef;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<div class="header">
				<h1 class="title">
					<span class="purescan-logo-svg" style="display: inline-block; width: 40px; height: 40px; flex-shrink: 0; margin-right: 12px;">
						<svg width="36" height="40" viewBox="0 0 33 36" fill="none" xmlns="http://www.w3.org/2000/svg">
							<path fill-rule="evenodd" clip-rule="evenodd" d="M16.5 0C17.1481 0 17.7936 0.196512 18.4117 0.427599C19.0489 0.66583 19.8436 1.01621 20.8214 1.44642C22.228 2.06531 23.986 2.74204 25.9758 3.30267C27.4628 3.72162 28.6843 4.06407 29.6104 4.42003C30.5263 4.77206 31.411 5.2274 32.0147 6.01954C32.5966 6.78324 32.8109 7.6648 32.9076 8.56946C33.0021 9.45453 33 10.5632 33 11.8785V16.6559C33 21.7851 30.6622 25.8444 27.8586 28.8547C25.2403 31.6661 22.1573 33.6305 19.9832 34.8061L19.5609 35.0306C18.5987 35.5339 17.765 36 16.5 36C15.235 36 14.4013 35.5339 13.4391 35.0306C11.2558 33.8885 7.93423 31.8534 5.14136 28.8547C2.38158 25.8914 0.0732929 21.9116 0.00183327 16.8954L9.12162e-06 16.6559V11.4075C-4.84578e-06 10.1081 -0.00267048 9.09713 0.0957767 8.31122C0.206005 7.43137 0.453228 6.7182 0.985655 6.01954C1.58934 5.22744 2.47399 4.77205 3.38988 4.42003C4.31602 4.06409 5.53733 3.72159 7.02418 3.30267C9.014 2.74203 10.772 2.06532 12.1786 1.44642L12.8782 1.13936C13.544 0.848206 14.1104 0.606265 14.5883 0.427599C15.2064 0.196513 15.8519 2.24081e-06 16.5 0ZM16.5 17.9998H3.1804C3.53413 21.5171 5.25027 24.4224 7.42884 26.7616C9.88968 29.4038 12.8726 31.2453 14.892 32.3017C15.814 32.784 16.0627 32.8911 16.365 32.9104L16.5 32.9143V17.9998H29.8196C29.8637 17.5614 29.8868 17.1134 29.8868 16.6559V11.8785C29.8868 10.4949 29.8848 9.5791 29.8117 8.89461C29.7495 8.31282 29.6489 8.06109 29.5651 7.92912L29.5305 7.8794C29.4632 7.79112 29.2535 7.59242 28.4846 7.29691C27.726 7.00534 26.6717 6.70675 25.1246 6.27085C22.9684 5.66337 21.0715 4.93253 19.5582 4.26665C18.5455 3.82109 17.847 3.5144 17.313 3.31472C16.829 3.13379 16.6123 3.09399 16.5283 3.08691L16.5 3.08571V17.9998ZM5.9151 7.81702C4.71154 7.81703 3.73586 8.78409 3.73586 9.97701C3.73586 11.1699 4.71154 12.137 5.9151 12.137C7.11866 12.137 8.09435 11.1699 8.09435 9.97701C8.09435 8.78408 7.11866 7.81702 5.9151 7.81702Z" fill="#10B981"/>
						</svg>
					</span>
					<div style="display:flex; flex-direction:column; justify-content:center;">
						<span style="font-size:28px; line-height:1.2; font-weight:600;">PureScan</span>
						<span style="font-size:15px; color:#6b7280; font-weight:500; margin-top:2px;">
							<?php esc_html_e( 'File Differences', 'purescan' ); ?> • v<?php echo esc_html( PURESCAN_VERSION ); ?>
						</span>
					</div>
				</h1>
				<div class="info">
					<strong><?php esc_html_e( 'File:', 'purescan' ); ?></strong> <?php echo esc_html( $file_path ); ?><br>
					<strong><?php esc_html_e( 'Size:', 'purescan' ); ?></strong> <?php echo esc_html( $filesize ); ?> •
					<strong><?php esc_html_e( 'Last Modified:', 'purescan' ); ?></strong> <?php echo esc_html( $modified ); ?>
				</div>
			</div>

			<div class="legend">
				<strong><?php esc_html_e( 'Left column:', 'purescan' ); ?></strong> <?php echo esc_html( $left_title ); ?> &nbsp;&nbsp;|&nbsp;&nbsp;
				<strong><?php esc_html_e( 'Right column:', 'purescan' ); ?></strong> <?php esc_html_e( 'Your current file', 'purescan' ); ?><br><br>
				<span style="color:#d73a49;"><?php esc_html_e( 'Red = Removed', 'purescan' ); ?></span> •
				<span style="color:#22863a;"><?php esc_html_e( 'Green = Added', 'purescan' ); ?></span> •
				<span style="color:#9a6700;"><?php esc_html_e( 'Yellow = Changed', 'purescan' ); ?></span>
			</div>

			<table class="diff">
				<colgroup>
					<col class="line-old">
					<col class="code-old">
					<col class="line-new">
					<col class="code-new">
				</colgroup>
				<thead>
					<tr>
						<th colspan="2"><?php echo esc_html( $left_title ); ?></th>
						<th colspan="2"><?php esc_html_e( 'Your Current File', 'purescan' ); ?></th>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Line', 'purescan' ); ?></th>
						<th><?php esc_html_e( 'Code', 'purescan' ); ?></th>
						<th><?php esc_html_e( 'Line', 'purescan' ); ?></th>
						<th><?php esc_html_e( 'Code', 'purescan' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $diff_html is safely generated by trusted WordPress core Text_Diff classes and a custom renderer that only outputs structural HTML (table, tr, td, del, ins) with pre-escaped content.
					echo $diff_html;
					?>
				</tbody>
			</table>

			<div class="footer">
				<span style="display: inline-block; width: 20px; height: 20px; vertical-align: -4px; margin-right: 8px;">
					<svg width="18" height="20" viewBox="0 0 18 20" fill="none" xmlns="http://www.w3.org/2000/svg">
						<path fill-rule="evenodd" clip-rule="evenodd" d="M9 0C9.35351 0 9.70561 0.109174 10.0427 0.237555C10.3903 0.369906 10.8238 0.564559 11.3571 0.803569C12.1243 1.14739 13.0833 1.52336 14.1686 1.83482C14.9797 2.06756 15.646 2.25781 16.1511 2.45557C16.6507 2.65114 17.1333 2.90411 17.4625 3.34419C17.78 3.76847 17.8969 4.25822 17.9496 4.76081C18.0012 5.25252 18 5.86845 18 6.59914V9.25327C18 12.1028 16.7248 14.358 15.1956 16.0304C13.7674 17.5923 12.0858 18.6836 10.8999 19.3367L10.6696 19.4614C10.1448 19.7411 9.68999 20 9 20C8.31001 20 7.85524 19.7411 7.33041 19.4614C6.13953 18.8269 4.32776 17.6963 2.80438 16.0304C1.29904 14.3841 0.0399779 12.1731 0.000999963 9.38636L4.97543e-06 9.25327V6.33748C-2.64315e-06 5.61561 -0.00145663 5.05396 0.0522418 4.61734C0.112366 4.12854 0.247215 3.73233 0.53763 3.34419C0.866911 2.90413 1.34945 2.65114 1.84902 2.45557C2.35419 2.25783 3.02036 2.06755 3.83137 1.83482C4.91673 1.52335 5.87563 1.1474 6.64288 0.803569L7.02445 0.632978C7.38762 0.471226 7.6966 0.336814 7.95725 0.237555C8.29439 0.109174 8.6465 1.24489e-06 9 0ZM9 9.99992H1.73477C1.92771 11.954 2.86378 13.568 4.05209 14.8675C5.39437 16.3355 7.0214 17.3585 8.12292 17.9454C8.62584 18.2133 8.76146 18.2728 8.92637 18.2835L9 18.2857V9.99992H16.2652C16.2893 9.75633 16.3019 9.50747 16.3019 9.25327V6.59914C16.3019 5.83052 16.3008 5.32172 16.2609 4.94145C16.227 4.61824 16.1721 4.47838 16.1264 4.40507L16.1075 4.37744C16.0708 4.3284 15.9565 4.21801 15.5371 4.05384C15.1233 3.89186 14.5482 3.72597 13.7043 3.48381C12.5282 3.14632 11.4936 2.74029 10.6681 2.37036C10.1157 2.12283 9.73474 1.95244 9.44343 1.84151C9.17946 1.74099 9.06125 1.71888 9.01542 1.71495L9 1.71428V9.99992ZM3.22642 4.34279C2.56993 4.34279 2.03774 4.88005 2.03774 5.54279C2.03774 6.20552 2.56993 6.74278 3.22642 6.74278C3.88291 6.74278 4.4151 6.20553 4.4151 5.54279C4.4151 4.88005 3.88291 4.34279 3.22642 4.34279Z" fill="white"/>
					</svg>
				</span>
				PureScan • v<?php echo esc_html( PURESCAN_VERSION ); ?> • <?php echo esc_html( $footer_note ); ?>
			</div>
		</div>
	</body>
	</html>
	<?php
}
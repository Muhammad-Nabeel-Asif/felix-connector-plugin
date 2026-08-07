<?php
/**
 * Felix Connector Runner — optional CLI entry point for server cron.
 *
 * The connector runs automatically via WP-Cron. This file is only needed
 * for advanced setups (high-reliability, low-traffic sites, or when
 * DISABLE_WP_CRON is set). It bootstraps WordPress, then runs the full
 * long-window poll loop.
 *
 * Usage in crontab:
 *   every-30-min * * * * /usr/bin/php /path/to/.../runner.php >/dev/null 2>&1
 *
 * @package FelixConnector
 */

// Prevent web access.
if ( php_sapi_name() !== 'cli' ) {
	http_response_code( 403 );
	exit( 'CLI only' );
}

// Find wp-load.php.
$wp_load_path = false;
$search_dir   = dirname( __DIR__ ); // wp-content/plugins/

for ( $i = 0; $i < 6; $i++ ) {
	$candidate = $search_dir . '/wp-load.php';
	if ( file_exists( $candidate ) ) {
		$wp_load_path = $candidate;
		break;
	}
	$search_dir = dirname( $search_dir );
}

if ( ! $wp_load_path ) {
	// Allow override via environment variable.
	$env_path = getenv( 'WP_LOAD_PATH' );
	if ( $env_path && file_exists( $env_path . '/wp-load.php' ) ) {
		$wp_load_path = $env_path . '/wp-load.php';
	}
}

if ( ! $wp_load_path ) {
	fwrite( STDERR, "Felix Runner: Could not find wp-load.php. Set WP_LOAD_PATH env var.\n" );
	fwrite( STDERR, "  Example: WP_LOAD_PATH=/var/www/html php runner.php\n" );
	exit( 1 );
}

// Bootstrap WordPress (this loads all active plugins including this one).
require_once $wp_load_path;

// Verify the plugin loaded correctly.
if ( ! class_exists( 'Felix_Runner' ) ) {
	fwrite( STDERR, "Felix Runner: Plugin class not found after WP bootstrap.\n" );
	exit( 1 );
}

// Run.
$runner = new Felix_Runner();
$runner->run();

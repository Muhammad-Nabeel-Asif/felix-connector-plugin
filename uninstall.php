<?php
/**
 * Uninstall Felix Connector — clean up all data.
 *
 * @package FelixConnector
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Delete all options.
$options = array(
	'felix_store_id',
	'felix_generation',
	'felix_paired',
	'felix_host_profile',
	'felix_key_manifest',
	'felix_plugin_keypair',
	'felix_poll_endpoint',
	'felix_result_endpoint',
	'felix_push_endpoint',
	'felix_kill_switches',
	'felix_runner_heartbeat',
	'felix_runner_lease',
	'felix_seen_nonces',
	'felix_liveness_state',
);

foreach ( $options as $option ) {
	delete_option( $option );
}

// Delete the command ledger table.
global $wpdb;
$table_name = $wpdb->prefix . 'felix_connector_commands';
// phpcs:ignore WordPress.DB.PreparedSQL
$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );

// Clear scheduled events.
	wp_clear_scheduled_hook( 'felix_connector_watchdog' );

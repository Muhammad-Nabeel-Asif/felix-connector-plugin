<?php
/**
 * Plugin Name:       Felix Connector
 * Plugin URI:        https://agentfelix.ai
 * Description:       Connects your WooCommerce store to Felix (agentfelix.ai). Felix executes commands locally via outbound-only communication — your store's host firewall is never bypassed.
 * Version:           0.1.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            Felix
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       felix-connector
 *
 * @package FelixConnector
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// CLI runner entry point — loaded outside WP context by cron.
if ( defined( 'FELIX_RUNNER_MODE' ) && FELIX_RUNNER_MODE ) {
	require_once __DIR__ . '/includes/class-felix-runner.php';
	$runner = new Felix_Runner();
	$runner->run();
	exit;
}

define( 'FELIX_CONNECTOR_VERSION', '0.1.0' );
define( 'FELIX_CONNECTOR_PLUGIN_FILE', __FILE__ );
define( 'FELIX_CONNECTOR_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'FELIX_CONNECTOR_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// Option key constants.
define( 'FELIX_OPT_STORE_ID', 'felix_store_id' );
define( 'FELIX_OPT_GENERATION', 'felix_generation' );
define( 'FELIX_OPT_PAIRED', 'felix_paired' );
define( 'FELIX_OPT_HOST_PROFILE', 'felix_host_profile' );
define( 'FELIX_OPT_KEY_MANIFEST', 'felix_key_manifest' );
define( 'FELIX_OPT_PLUGIN_KEYPAIR', 'felix_plugin_keypair' );
define( 'FELIX_OPT_POLL_ENDPOINT', 'felix_poll_endpoint' );
define( 'FELIX_OPT_RESULT_ENDPOINT', 'felix_result_endpoint' );
define( 'FELIX_OPT_PUSH_ENDPOINT', 'felix_push_endpoint' );
define( 'FELIX_OPT_KILL_SWITCHES', 'felix_kill_switches' );
define( 'FELIX_OPT_RUNNER_HEARTBEAT', 'felix_runner_heartbeat' );
define( 'FELIX_OPT_RUNNER_LEASE', 'felix_runner_lease' );
define( 'FELIX_OPT_SEEN_NONCES', 'felix_seen_nonces' );
define( 'FELIX_OPT_LIVENESS_STATE', 'felix_liveness_state' );

// Default API base (configurable via filter).
if ( ! defined( 'FELIX_API_BASE' ) ) {
	define( 'FELIX_API_BASE', 'https://api.agentfelix.ai' );
}

// Protocol version.
define( 'FELIX_PROTOCOL_VERSION', 1 );

require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-crypto.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-ledger.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-handlers.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-settings.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-pairing.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-runner.php';

/**
 * Activation hook — generate keypair, create command ledger table.
 */
function felix_connector_activate() {
	// Generate Ed25519 keypair if not present.
	if ( ! get_option( FELIX_OPT_PLUGIN_KEYPAIR ) ) {
		$keypair = Felix_Crypto::generate_identity();
		update_option( FELIX_OPT_PLUGIN_KEYPAIR, $keypair, false );
	}

	// Create command ledger table.
	Felix_Command_Ledger::create_table();

	// Mark as not yet paired.
	if ( ! get_option( FELIX_OPT_PAIRED ) ) {
		update_option( FELIX_OPT_PAIRED, false, false );
	}

	// Default kill switches — all enabled (none killed).
	if ( ! get_option( FELIX_OPT_KILL_SWITCHES ) ) {
		update_option( FELIX_OPT_KILL_SWITCHES, array(), false );
	}

	// Schedule wp-cron watchdog.
	if ( ! wp_next_scheduled( 'felix_connector_watchdog' ) ) {
		wp_schedule_event( time(), 'five_minutes', 'felix_connector_watchdog' );
	}
}
register_activation_hook( __FILE__, 'felix_connector_activate' );

/**
 * Add "Settings" link on the Plugins list page.
 */
function felix_connector_add_settings_link( $links ) {
	$settings_link = '<a href="' . esc_url( admin_url( 'admin.php?page=felix-connector' ) ) . '">' . __( 'Settings', 'felix-connector' ) . '</a>';
	array_unshift( $links, $settings_link );
	return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'felix_connector_add_settings_link' );

/**
 * Deactivation hook — clean up schedules.
 */
function felix_connector_deactivate() {
	$timestamp = wp_next_scheduled( 'felix_connector_watchdog' );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, 'felix_connector_watchdog' );
	}
}
register_deactivation_hook( __FILE__, 'felix_connector_deactivate' );

/**
 * wp-cron watchdog — best-effort diagnostics only.
 * Reports heartbeat staleness outbound to Felix. Never executes commands.
 */
function felix_connector_watchdog() {
	if ( ! get_option( FELIX_OPT_PAIRED ) ) {
		return;
	}

	$heartbeat = get_option( FELIX_OPT_RUNNER_HEARTBEAT, 0 );
	$stale_seconds = time() - intval( $heartbeat );

	// Only report if stale beyond threshold.
	$host_profile = get_option( FELIX_OPT_HOST_PROFILE, array() );
	$cron_interval = $host_profile['cronInterval'] ?? 1800;
	$stale_threshold = $cron_interval + 120; // One cron window + margin.

	if ( $stale_seconds > $stale_threshold ) {
		// Report staleness to Felix (best-effort, fire-and-forget).
		$store_id = get_option( FELIX_OPT_STORE_ID );
		$generation = get_option( FELIX_OPT_GENERATION, 1 );

		if ( $store_id ) {
			wp_remote_post(
				FELIX_API_BASE . '/connector/heartbeat',
				array(
					'headers' => array( 'Content-Type' => 'application/json' ),
					'body'    => wp_json_encode(
						array(
							'protocolVersion' => FELIX_PROTOCOL_VERSION,
							'storeId'         => $store_id,
							'generation'      => $generation,
							'staleSeconds'    => $stale_seconds,
							'source'          => 'wp_cron_watchdog',
						)
					),
					'timeout' => 10,
				)
			);
		}
	}
}
add_action( 'felix_connector_watchdog', 'felix_connector_watchdog' );

// Add custom cron schedule.
add_filter(
	'cron_schedules',
	function ( $schedules ) {
		$schedules['five_minutes'] = array(
			'interval' => 300,
			'display'  => __( 'Every 5 Minutes', 'felix-connector' ),
		);
		return $schedules;
	}
);

// Initialize settings page.
new Felix_Settings();

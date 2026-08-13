<?php
/**
 * Plugin Name:       Felix Connector
 * Plugin URI:        https://agentfelix.ai
 * Description:       Connects your WooCommerce store to Felix (agentfelix.ai). Felix executes commands locally via outbound-only communication — your store's host firewall is never bypassed.
 * Version:           0.4.3
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

// --- Constants & class loading (shared by every entry path) ------------------
// These MUST load before the CLI short-circuit below: Felix_Runner now depends
// on the shared processor/handlers/ledger/crypto/pairing classes and on the
// option/protocol constants at runtime.
define( 'FELIX_CONNECTOR_VERSION', '0.4.3' );
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
define( 'FELIX_OPT_LAST_POLL_ERROR', 'felix_last_poll_error' );

// Default API base (configurable via filter).
if ( ! defined( 'FELIX_API_BASE' ) ) {
	define( 'FELIX_API_BASE', 'https://api.agentfelix.ai' );
}

// Protocol version.
//
// Protocol v2 extends the v1 poll-auth signature with two extra signed fields
// (plugin version + capability list) and is advertised via the
// X-Felix-Protocol-Version header. The command envelope shape itself is
// unchanged from v1, so v1 consumers of the envelope still work; only the
// poll-auth verifier needs to know the extended signing string.
define( 'FELIX_PROTOCOL_VERSION', 2 );

// Pairing-code format (must stay in lockstep with the Felix backend).
//
// The backend mints an 8-character code from a 32-symbol UNAMBIGUOUS alphabet
// (0/O and 1/I/L removed so a hand-typed code can't be misread) and displays it
// grouped as XXXX-XXXX for easy transcription. The hyphen is purely cosmetic:
// the plugin normalizes the operator's input back to the canonical 8-character
// form before submitting, so the backend compares an exact, ungrouped string.
// Eight symbols × 5 bits = 40 bits of entropy (a 1024× larger space than the
// prior six-character code).
define( 'FELIX_PAIRING_CODE_LENGTH', 8 );
define( 'FELIX_PAIRING_CODE_ALPHABET', 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' );

require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-crypto.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-ledger.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-handlers.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-processor.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-settings.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-pairing.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-runner.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-rest.php';

// CLI runner short-circuit — run a single poll window then exit. Reached when
// FELIX_RUNNER_MODE is defined before this plugin file loads (e.g. a minimal
// server cron). Constants and all classes are loaded above, so the runner's
// shared-processor pipeline is available here just like in the WP-Cron path.
if ( defined( 'FELIX_RUNNER_MODE' ) && FELIX_RUNNER_MODE ) {
	$runner = new Felix_Runner();
	$runner->run();
	exit;
}

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

/**
 * Activation hook — generate keypair, create command ledger table, schedule WP-Cron.
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

	// Schedule WP-Cron runner event.
	if ( ! wp_next_scheduled( 'felix_connector_cron' ) ) {
		wp_schedule_event( time(), 'five_minutes', 'felix_connector_cron' );
	}

	// Schedule watchdog (keep existing).
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
 * Deactivation hook — clean up all scheduled events.
 */
function felix_connector_deactivate() {
	// Clear WP-Cron runner event.
	$cron_timestamp = wp_next_scheduled( 'felix_connector_cron' );
	if ( $cron_timestamp ) {
		wp_unschedule_event( $cron_timestamp, 'felix_connector_cron' );
	}
	wp_clear_scheduled_hook( 'felix_connector_cron' );

	// Clear watchdog event.
	$watchdog_timestamp = wp_next_scheduled( 'felix_connector_watchdog' );
	if ( $watchdog_timestamp ) {
		wp_unschedule_event( $watchdog_timestamp, 'felix_connector_watchdog' );
	}
	wp_clear_scheduled_hook( 'felix_connector_watchdog' );
}
register_deactivation_hook( __FILE__, 'felix_connector_deactivate' );

/**
 * Self-healing: ensure WP-Cron event is registered on every init.
 * Catches cases where the event was lost (manual unschedule, migration, etc.).
 */
function felix_connector_ensure_cron_scheduled() {
	if ( ! wp_next_scheduled( 'felix_connector_cron' ) ) {
		wp_schedule_event( time(), 'five_minutes', 'felix_connector_cron' );
	}
}
add_action( 'init', 'felix_connector_ensure_cron_scheduled' );

/**
 * WP-Cron runner callback — short bounded poll cycle.
 *
 * Fires every 5 minutes via WP-Cron (triggered by site traffic).
 * Shares the same flock + DB-lease mutex as the external CLI runner,
 * so both can coexist without double-executing commands.
 */
function felix_connector_cron_runner() {
	if ( ! get_option( FELIX_OPT_PAIRED ) ) {
		return;
	}

	$runner = new Felix_Runner();
	$runner->run_wp_cron();
}
add_action( 'felix_connector_cron', 'felix_connector_cron_runner' );

/**
 * One-shot short check-in for the admin "Check in now" button and post-pair.
 *
 * Same verify → reserve → execute pipeline as WP-Cron, but a single short
 * poll so the settings page does not hang for a full 50s cycle.
 *
 * @return string success|error|skipped
 */
function felix_connector_checkin_now() {
	if ( ! get_option( FELIX_OPT_PAIRED ) ) {
		return 'skipped';
	}

	if ( function_exists( 'set_time_limit' ) ) {
		set_time_limit( 30 );
	}

	$runner = new Felix_Runner();
	return $runner->run_checkin();
}

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
		// Report staleness to Felix (best-effort, fire-and-forget). SIGNED per
		// the v2 raw-body contract so the backend authenticates the heartbeat:
		// the signature binds `timestamp\nrawBody`, and the keyId/timestamp/
		// protocol headers are sent so the backend can verify + enforce
		// freshness. An unsigned heartbeat is rejected (401) by the backend.
		$store_id   = get_option( FELIX_OPT_STORE_ID );
		$generation = get_option( FELIX_OPT_GENERATION, 1 );

		if ( $store_id ) {
			$body = array(
				'protocolVersion' => FELIX_PROTOCOL_VERSION,
				'storeId'         => $store_id,
				'generation'      => $generation,
				'staleSeconds'    => $stale_seconds,
				'source'          => 'wp_cron_watchdog',
			);
			$body_json = wp_json_encode( $body );

			$headers = array( 'Content-Type' => 'application/json' );
			$keypair = Felix_Pairing::get_keypair();
			if ( $keypair && isset( $keypair['encryptedSecret'] ) ) {
				$secret = Felix_Crypto::get_secret_key( $keypair['encryptedSecret'] );
				if ( $secret ) {
					$timestamp = (string) ( time() * 1000 );
					$sig       = Felix_Crypto::sign( $timestamp . "\n" . $body_json, $secret );
					$headers['X-Felix-Plugin-Sig']       = $sig;
					$headers['X-Felix-Plugin-KeyId']     = $keypair['publicKey'];
					$headers['X-Felix-Timestamp']        = $timestamp;
					$headers['X-Felix-Protocol-Version'] = (string) FELIX_PROTOCOL_VERSION;
					sodium_memzero( $secret );
				}
			}

			wp_remote_post(
				FELIX_API_BASE . '/connector/heartbeat',
				array(
					'headers' => $headers,
					'body'    => $body_json,
					'timeout' => 10,
				)
			);
		}
	}
}
add_action( 'felix_connector_watchdog', 'felix_connector_watchdog' );

// Initialize settings page.
new Felix_Settings();

// Register the inbound direct command delivery REST endpoint.
new Felix_REST();

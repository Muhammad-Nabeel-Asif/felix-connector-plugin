<?php
/**
 * Behavioral tests for the Felix Connector command pipeline (v0.4.0).
 *
 * Covers: signature verification, envelope validation, write-authority
 * enforcement, deterministic atomic reservation, idempotent redelivery,
 * never-steal-a-crashed-reservation, reserved→terminal guard, and the
 * unconfirmed-on-persistence-failure contract. Also exercises the direct
 * REST endpoint transport.
 *
 * Run: php tests/run.php
 *
 * @package FelixConnector
 */

require_once __DIR__ . '/bootstrap.php';

// --- Test fixture constants --------------------------------------------------
define( 'TEST_STORE_ID', 'store-abc-123' );
define( 'TEST_GEN', 7 );
define( 'TEST_KEY_ID', 'key-backend-1' );
define( 'LEDGER_TABLE', $GLOBALS['wpdb']->prefix . 'felix_connector_commands' );

// --- Assertion helpers -------------------------------------------------------
$GLOBALS['__pass'] = 0;
$GLOBALS['__fail'] = 0;

function pass( $label ) {
	$GLOBALS['__pass']++;
	echo "  \033[32m✓\033[0m $label\n";
}

function fail( $label, $detail = '' ) {
	$GLOBALS['__fail']++;
	echo "  \033[31m✗\033[0m $label" . ( '' !== $detail ? " :: $detail" : '' ) . "\n";
}

function expect( $label, $cond ) {
	if ( $cond ) {
		pass( $label );
	} else {
		fail( $label );
	}
	return (bool) $cond;
}

function expect_eq( $label, $actual, $expected ) {
	// Loose comparison is intentional for scalar status strings; use a strict
	// fallback for arrays/objects via json.
	$ok = ( is_array( $expected ) || is_object( $expected ) )
		? ( wp_json_encode( $actual ) === wp_json_encode( $expected ) )
		: ( (string) $actual === (string) $expected );
	if ( $ok ) {
		pass( $label );
	} else {
		fail( $label, 'expected [' . var_export( $expected, true ) . '] got [' . var_export( $actual, true ) . ']' );
	}
	return $ok;
}

// --- Fixture helpers ---------------------------------------------------------

/**
 * Reset all global state so test groups are isolated.
 */
function reset_state() {
	global $wpdb;
	$wpdb->reset_all();
	$GLOBALS['__felix_options']     = array();
	$GLOBALS['__felix_handler_calls'] = 0;

	update_option( FELIX_OPT_STORE_ID, TEST_STORE_ID );
	update_option( FELIX_OPT_GENERATION, TEST_GEN );
	update_option( FELIX_OPT_PAIRED, true );
	update_option( FELIX_OPT_KILL_SWITCHES, array() );
	update_option( FELIX_OPT_SEEN_NONCES, array() );
}

function make_backend_key() {
	$kp       = Felix_Crypto::generate_identity();
	$secret   = Felix_Crypto::get_secret_key( $kp['encryptedSecret'] );
	$manifest = array(
		'keys' => array(
			array(
				'keyId'     => TEST_KEY_ID,
				'publicKey' => $kp['publicKey'],
			),
		),
	);
	update_option( FELIX_OPT_KEY_MANIFEST, $manifest );
	return $secret;
}

function make_envelope( $overrides = array() ) {
	return array_merge(
		array(
			'commandId'         => 'cmd-' . bin2hex( random_bytes( 6 ) ),
			'type'              => 'ping',
			'storeId'           => TEST_STORE_ID,
			'generation'        => TEST_GEN,
			'issuedAt'          => date( 'c' ),
			'ttlSeconds'        => 120,
			'nonce'             => 'nonce-' . bin2hex( random_bytes( 6 ) ),
			'keyId'             => TEST_KEY_ID,
			'args'              => array(),
			'authorizationBasis' => array(
				'kind'   => 'graduated_rule',
				'ruleId' => 'connector-read',
			),
		),
		$overrides
	);
}

/**
 * Build (raw_body, envelope) with a valid Ed25519 signature over the
 * signature-less canonical form.
 */
function sign_envelope( $envelope, $secret ) {
	unset( $envelope['signature'] );
	$canonical            = wp_json_encode( $envelope );
	$envelope['signature'] = Felix_Crypto::sign( $canonical, $secret );
	return array( wp_json_encode( $envelope ), $envelope );
}

// =============================================================================
// TEST GROUPS
// =============================================================================

function test_authorize_unit() {
	echo "\n[authorize unit policy]\n";

	// Write family + connector-read => denied.
	$r = Felix_Command_Handlers::authorize( 'order_write', array( 'kind' => 'graduated_rule', 'ruleId' => 'connector-read' ) );
	expect( 'write + connector-read denied', ! $r['ok'] && 'insufficient_authorization' === $r['code'] );

	// Read family + connector-read => allowed.
	$r = Felix_Command_Handlers::authorize( 'order_read', array( 'kind' => 'graduated_rule', 'ruleId' => 'connector-read' ) );
	expect( 'read + connector-read allowed', $r['ok'] );

	// Write family + approval => allowed (concrete write authority).
	$r = Felix_Command_Handlers::authorize( 'order_write', array( 'kind' => 'approval' ) );
	expect( 'write + approval allowed', $r['ok'] );

	// Write family + non-read graduated rule => allowed.
	$r = Felix_Command_Handlers::authorize( 'order_write', array( 'kind' => 'graduated_rule', 'ruleId' => 'connector-write' ) );
	expect( 'write + non-read graduated rule allowed', $r['ok'] );

	// Missing basis => denied.
	$r = Felix_Command_Handlers::authorize( 'order_read', null );
	expect( 'missing basis denied', ! $r['ok'] && 'missing_authorization' === $r['code'] );

	// graduated_rule without ruleId => denied.
	$r = Felix_Command_Handlers::authorize( 'order_read', array( 'kind' => 'graduated_rule' ) );
	expect( 'graduated_rule without ruleId denied', ! $r['ok'] && 'missing_rule_id' === $r['code'] );

	// Unknown kind => denied.
	$r = Felix_Command_Handlers::authorize( 'order_read', array( 'kind' => 'bogus' ) );
	expect( 'unknown kind denied', ! $r['ok'] && 'unknown_authorization_kind' === $r['code'] );

	// Family classification sanity.
	expect( 'ping is read family', Felix_Command_Handlers::is_read_family( Felix_Command_Handlers::family_for( 'ping' ) ) );
	expect( 'update_order_status is write family', ! Felix_Command_Handlers::is_read_family( Felix_Command_Handlers::family_for( 'update_order_status' ) ) );
}

function test_signature_and_envelope() {
	echo "\n[signature + envelope validation]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	// Unknown keyId.
	$env        = make_envelope( array( 'keyId' => 'nope' ) );
	list($raw)  = sign_envelope( $env, $secret );
	$t          = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'unknown keyId rejected', $t['status'], 'rejected' );
	expect_eq( 'unknown keyId code', $t['error']['code'], 'unknown_key' );

	// Missing signature.
	$env        = make_envelope();
	unset( $env['signature'] );
	$raw        = wp_json_encode( $env );
	$t          = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'missing signature rejected', $t['error']['code'], 'signature_missing' );

	// Tampered body => invalid signature.
	$env        = make_envelope();
	list($raw)  = sign_envelope( $env, $secret );
	$tampered   = json_decode( $raw, true );
	$tampered['args'] = array( 'sneaky' => true ); // change after signing
	$t          = $proc->process( wp_json_encode( $tampered ), $tampered );
	expect_eq( 'tampered body rejected', $t['error']['code'], 'signature_invalid' );

	// Store mismatch.
	$env        = make_envelope( array( 'storeId' => 'wrong-store' ) );
	list($raw)  = sign_envelope( $env, $secret );
	$t          = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'store mismatch rejected', $t['error']['code'], 'store_mismatch' );

	// Generation mismatch.
	$env        = make_envelope( array( 'generation' => 999 ) );
	list($raw)  = sign_envelope( $env, $secret );
	$t          = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'generation mismatch rejected', $t['error']['code'], 'generation_mismatch' );

	// TTL expired.
	$env        = make_envelope(
		array(
			'issuedAt'   => gmdate( 'c', time() - 600 ),
			'ttlSeconds' => 60,
		)
	);
	list($raw)  = sign_envelope( $env, $secret );
	$t          = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'expired TTL rejected', $t['error']['code'], 'ttl_expired' );
}

function test_write_authority_via_processor() {
	echo "\n[write-authority enforcement via processor]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	// A write command with only connector-read authority must be rejected
	// BEFORE reservation / execution.
	$env        = make_envelope(
		array(
			'type'               => 'update_order_status',
			'authorizationBasis' => array( 'kind' => 'graduated_rule', 'ruleId' => 'connector-read' ),
		)
	);
	list($raw)  = sign_envelope( $env, $secret );
	$before     = $GLOBALS['__felix_handler_calls'];
	$t          = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'write denied w/o authority', $t['status'], 'rejected' );
	expect_eq( 'insufficient_authorization code', $t['error']['code'], 'insufficient_authorization' );
	expect( 'handler did not run on auth reject', $GLOBALS['__felix_handler_calls'] === $before );
	// No ledger row should have been created for a pre-reservation reject.
	expect( 'no reservation row on auth reject', Felix_Command_Ledger::get( $env['commandId'] ) === null );

	// Same write command WITH approval evidence is accepted for execution
	// (the handler would then run; we only assert it passes the auth gate).
	$env2       = make_envelope(
		array(
			'type'               => 'update_order_status',
			'authorizationBasis' => array( 'kind' => 'approval', 'approvalId' => 'ap-1' ),
		)
	);
	list($raw2) = sign_envelope( $env2, $secret );
	$t2         = $proc->process( $raw2, json_decode( $raw2, true ) );
	// It will fail later (no WooCommerce) but must NOT be insufficient_authorization.
	expect( 'write with approval passes auth gate', ! ( 'rejected' === $t2['status'] && 'insufficient_authorization' === $t2['error']['code'] ) );
}

function test_atomic_reservation_and_dedup() {
	echo "\n[deterministic atomic reservation + idempotent redelivery]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	// Reserve() determinism: first wins, second is a duplicate.
	$r1 = Felix_Command_Ledger::reserve( 'rid-1', 'ping' );
	expect_eq( 'first reserve wins', $r1['status'], 'reserved' );
	$r2 = Felix_Command_Ledger::reserve( 'rid-1', 'ping' );
	expect_eq( 'second reserve is duplicate', $r2['status'], 'duplicate' );

	// Happy path: a read command executes exactly once.
	$env       = make_envelope();
	list($raw) = sign_envelope( $env, $secret );
	$t1        = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'first delivery done', $t1['status'], 'done' );
	expect( 'first delivery ran handler', $GLOBALS['__felix_handler_calls'] === 1 );
	expect( 'first delivery not alreadyExecuted', empty( $t1['alreadyExecuted'] ) );

	// Redelivery returns the STORED terminal result without re-executing.
	$calls_before = $GLOBALS['__felix_handler_calls'];
	$t2           = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'redelivery done', $t2['status'], 'done' );
	expect( 'redelivery marked alreadyExecuted', ! empty( $t2['alreadyExecuted'] ) );
	expect( 'redelivery did not re-run handler', $GLOBALS['__felix_handler_calls'] === $calls_before );
	expect_eq( 'redelivery returns same pong', $t2['result']['pong'], true );
}

function test_never_steal_crashed_reservation() {
	echo "\n[never steal a crashed reservation]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	// Simulate a process that reserved then crashed: a 'reserved' row exists
	// with no terminal result.
	$env       = make_envelope();
	$GLOBALS['wpdb']->seed_row(
		LEDGER_TABLE,
		array(
			'id'           => $env['commandId'],
			'type'         => 'ping',
			'status'       => 'reserved',
			'executed_at'  => current_time( 'mysql' ),
		)
	);

	list($raw) = sign_envelope( $env, $secret );
	$before    = $GLOBALS['__felix_handler_calls'];
	$t         = $proc->process( $raw, json_decode( $raw, true ) );

	expect_eq( 'crashed reservation => conflict (not executed)', $t['status'], 'rejected' );
	expect_eq( 'reservation_conflict code', $t['error']['code'], 'reservation_conflict' );
	expect( 'handler NOT run on crashed reservation', $GLOBALS['__felix_handler_calls'] === $before );

	// The crashed 'reserved' row must remain untouched (not stolen).
	$row = Felix_Command_Ledger::get( $env['commandId'] );
	expect_eq( 'crashed reservation row left as reserved', $row->status, 'reserved' );
}

function test_terminal_update_only_from_reserved() {
	echo "\n[terminal update only from reserved]\n";
	reset_state();

	// A row already in a terminal state cannot be re-transitioned.
	$GLOBALS['wpdb']->seed_row(
		LEDGER_TABLE,
		array(
			'id'          => 'done-row',
			'type'        => 'ping',
			'status'      => 'done',
			'executed_at' => current_time( 'mysql' ),
		)
	);
	$ok = Felix_Command_Ledger::mark_terminal( 'done-row', 'failed', null, array( 'code' => 'x', 'message' => 'y' ) );
	expect( 'mark_terminal refused on already-terminal row', ! $ok );
	$row = Felix_Command_Ledger::get( 'done-row' );
	expect_eq( 'terminal row unchanged', $row->status, 'done' );

	// A reserved row transitions correctly.
	$GLOBALS['wpdb']->seed_row(
		LEDGER_TABLE,
		array(
			'id'          => 'reserved-row',
			'type'        => 'ping',
			'status'      => 'reserved',
			'executed_at' => current_time( 'mysql' ),
		)
	);
	$ok = Felix_Command_Ledger::mark_terminal( 'reserved-row', 'done', array( 'pong' => true ) );
	expect( 'mark_terminal succeeds on reserved row', $ok );
	$row = Felix_Command_Ledger::get( 'reserved-row' );
	expect_eq( 'reserved row became done', $row->status, 'done' );
}

function test_unconfirmed_on_persistence_failure() {
	echo "\n[unconfirmed on terminal-persistence failure]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	// A valid read command executes, but the terminal UPDATE fails.
	$env                  = make_envelope();
	list($raw)            = sign_envelope( $env, $secret );
	$GLOBALS['wpdb']->fail_updates = true;

	$before = $GLOBALS['__felix_handler_calls'];
	$t      = $proc->process( $raw, json_decode( $raw, true ) );
	$GLOBALS['wpdb']->fail_updates = false;

	expect( 'handler ran despite persistence failure', $GLOBALS['__felix_handler_calls'] > $before );
	expect_eq( 'unconfirmed surfaced (not a false done)', $t['status'], 'unconfirmed' );
	expect_eq( 'persistence_failed error code', $t['error']['code'], 'persistence_failed' );
	expect_eq( 'no result payload on unconfirmed', $t['result'], null );
}

function test_nonce_replay() {
	echo "\n[nonce replay protection]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	$shared_nonce = 'nonce-shared';

	// First command with the nonce executes.
	$env1      = make_envelope( array( 'nonce' => $shared_nonce ) );
	list($raw1) = sign_envelope( $env1, $secret );
	$t1        = $proc->process( $raw1, json_decode( $raw1, true ) );
	expect_eq( 'first nonce use executes', $t1['status'], 'done' );

	// A SECOND, different command reusing the same nonce is rejected.
	$env2      = make_envelope( array( 'nonce' => $shared_nonce ) );
	list($raw2) = sign_envelope( $env2, $secret );
	$before    = $GLOBALS['__felix_handler_calls'];
	$t2        = $proc->process( $raw2, json_decode( $raw2, true ) );
	expect_eq( 'replayed nonce rejected', $t2['status'], 'rejected' );
	expect_eq( 'nonce_seen code', $t2['error']['code'], 'nonce_seen' );
	expect( 'handler did not run on replayed nonce', $GLOBALS['__felix_handler_calls'] === $before );
}

/**
 * Minimal fake of WP_REST_Request for direct endpoint tests.
 */
final class Fake_REST_Request {
	private $body;
	public function __construct( $body ) {
		$this->body = $body;
	}
	public function get_body() {
		return $this->body;
	}
}

function test_rest_endpoint() {
	echo "\n[direct REST endpoint transport]\n";

	// Unpaired store => 404, endpoint not revealed.
	reset_state();
	update_option( FELIX_OPT_PAIRED, false );
	$rest   = new Felix_REST();
	$resp   = $rest->handle_command( new Fake_REST_Request( '{}' ) );
	expect_eq( 'unpaired => 404', $resp->get_status(), 404 );

	// Paired, malformed body => 400.
	reset_state();
	make_backend_key();
	$rest   = new Felix_REST();
	$resp   = $rest->handle_command( new Fake_REST_Request( 'not-json' ) );
	expect_eq( 'malformed body => 400', $resp->get_status(), 400 );

	// Paired, valid signed ping => 200 done (delegates to processor).
	reset_state();
	$secret = make_backend_key();
	$env    = make_envelope();
	list($raw) = sign_envelope( $env, $secret );
	$rest   = new Felix_REST();
	$resp   = $rest->handle_command( new Fake_REST_Request( $raw ) );
	expect_eq( 'valid ping => 200', $resp->get_status(), 200 );
	expect_eq( 'valid ping => done', $resp->get_data()['status'], 'done' );

	// A rejected command maps to 422 (unprocessable).
	reset_state();
	$secret = make_backend_key();
	$env    = make_envelope( array( 'storeId' => 'wrong' ) );
	list($raw) = sign_envelope( $env, $secret );
	$rest   = new Felix_REST();
	$resp   = $rest->handle_command( new Fake_REST_Request( $raw ) );
	expect_eq( 'rejected envelope => 422', $resp->get_status(), 422 );
}

function test_poll_capability_advertised() {
	echo "\n[poll capability/version advertisement]\n";
	$caps = Felix_Runner::capability_list();
	expect( 'directCommandV1 advertised', in_array( 'directCommandV1', $caps, true ) );
	expect_eq( 'protocol version is 2 (v2 signature)', FELIX_PROTOCOL_VERSION, 2 );
}

// The runner class is only loaded via felix-connector.php (not in the test
// bootstrap), but capability_list is referenced statically. Load it safely.
if ( ! class_exists( 'Felix_Runner' ) ) {
	require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-runner.php';
}

// =============================================================================
// RUN
// =============================================================================

echo "Felix Connector v" . FELIX_CONNECTOR_VERSION . " — behavioral tests\n";
echo str_repeat( '=', 60 ) . "\n";

test_authorize_unit();
test_signature_and_envelope();
test_write_authority_via_processor();
test_atomic_reservation_and_dedup();
test_never_steal_crashed_reservation();
test_terminal_update_only_from_reserved();
test_unconfirmed_on_persistence_failure();
test_nonce_replay();
test_rest_endpoint();
test_poll_capability_advertised();

echo str_repeat( '=', 60 ) . "\n";
$total = $GLOBALS['__pass'] + $GLOBALS['__fail'];
echo sprintf( "%d tests, %d passed, %d failed\n", $total, $GLOBALS['__pass'], $GLOBALS['__fail'] );

if ( $GLOBALS['__fail'] > 0 ) {
	exit( 1 );
}
exit( 0 );

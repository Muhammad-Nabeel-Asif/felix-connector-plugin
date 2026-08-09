<?php
/**
 * Behavioral tests for the Felix Connector command pipeline (v0.4.1).
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
	if ( function_exists( 'felix_reset_wc' ) ) {
		felix_reset_wc();
	}

	update_option( FELIX_OPT_STORE_ID, TEST_STORE_ID );
	update_option( FELIX_OPT_GENERATION, TEST_GEN );
	update_option( FELIX_OPT_PAIRED, true );
	update_option( FELIX_OPT_KILL_SWITCHES, array() );
	update_option( FELIX_OPT_SEEN_NONCES, array() );
}

/**
 * Shared authorization bases for the handler tests.
 */
function read_basis() {
	return array( 'kind' => 'graduated_rule', 'ruleId' => 'connector-read' );
}
function write_basis() {
	return array( 'kind' => 'approval', 'approvalId' => 'ap-test' );
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
 * signature-less CANONICAL form (recursively sorted keys + wp_json_encode
 * escaping). This matches the backend's canonicalCommandJson() byte contract.
 */
function sign_envelope( $envelope, $secret ) {
	unset( $envelope['signature'] );
	$canonical            = Felix_Crypto::canonical_json( $envelope );
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

// =============================================================================
// COLD-AUDIT REMEDIATION TESTS
// =============================================================================

/**
 * #4 — recursive canonical JSON byte contract (slash + unicode + sorted keys).
 * The plugin's canonical_json MUST produce bytes identical to the backend's
 * canonicalCommandJson() so Ed25519 signatures verify cross-language.
 */
function test_canonical_json_contract() {
	echo "\n[canonical JSON contract (#4)]\n";

	// Sorted keys + slash escaping + unicode escaping.
	$out = Felix_Crypto::canonical_json(
		array(
			'b'    => 1,
			'a'    => 'https://shop.example.com',
			'name' => 'José',
		)
	);
	expect( 'keys sorted ascending (a before b before name)', strpos( $out, '"a"' ) < strpos( $out, '"b"' ) && strpos( $out, '"b"' ) < strpos( $out, '"name"' ) );
	expect( 'forward slashes escaped (\/)', false !== strpos( $out, 'https:\/\/shop.example.com' ) );
	expect( 'non-ASCII escaped (\\u00e9)', false !== strpos( $out, 'Jos\u00e9' ) );

	// Exact byte-for-byte match for a reordered object.
	$got = Felix_Crypto::canonical_json( array( 'z' => 1, 'a' => 2 ) );
	expect_eq( 'reordered {z,a} canonicalizes to {"a":2,"z":1}', $got, '{"a":2,"z":1}' );

	// Nested object keys sorted recursively.
	$nested = Felix_Crypto::canonical_json( array( 'outer' => array( 'z' => 1, 'a' => 2 ) ) );
	expect( 'nested keys sorted', false !== strpos( $nested, '{"a":2,"z":1}' ) );

	// Arrays preserve element order (NOT sorted).
	$arr = Felix_Crypto::canonical_json( array( 'list' => array( 3, 1, 2 ) ) );
	expect_eq( 'array order preserved', $arr, '{"list":[3,1,2]}' );

	// P0 cross-repo fixture: a representative command envelope (ISO date + URL
	// + nested objects) canonicalizes to an EXACT byte string. The backend's
	// canonicalCommandJson() MUST produce the IDENTICAL bytes (pinned in
	// connector-outbound.service.spec.ts). Any drift breaks Ed25519 verification.
	$envelope = array(
		'protocolVersion'     => 1,
		'commandId'           => 'cmd-123',
		'storeId'             => 'store-abc',
		'generation'          => 7,
		'type'                => 'search_orders',
		'args'                => array( 'email' => 'jose@example.com', 'url' => 'https://shop.example.com/p' ),
		'authorizationBasis'  => array( 'kind' => 'graduated_rule', 'ruleId' => 'connector-read' ),
		'issuedAt'            => '2026-01-15T12:30:00.000Z',
		'ttlSeconds'          => 120,
		'nonce'               => 'nonce-abc',
		'keyId'               => 'cmd-sign-v1',
	);
	$expected = '{"args":{"email":"jose@example.com","url":"https:\/\/shop.example.com\/p"},"authorizationBasis":{"kind":"graduated_rule","ruleId":"connector-read"},"commandId":"cmd-123","generation":7,"issuedAt":"2026-01-15T12:30:00.000Z","keyId":"cmd-sign-v1","nonce":"nonce-abc","protocolVersion":1,"storeId":"store-abc","ttlSeconds":120,"type":"search_orders"}';
	expect_eq( 'cross-repo fixture vector matches backend byte-for-byte', Felix_Crypto::canonical_json( $envelope ), $expected );
}

/**
 * #4 v2 — the versioned canonical byte contract: object-vs-array identity
 * ({}) vs []) + ECMAScript finite-number formatting. The PHP encoder
 * reproduces the SAME pinned bytes the Node backend produces, and verifies the
 * Node-produced Ed25519 signatures with libsodium. A signature made by Node
 * only verifies under PHP when the canonical bytes are byte-identical — so a
 * passing run here is proof that backend-produced bytes are PHP-verified.
 *
 * The fixture (tests/canonical-fixtures.json) is generated by the backend's
 * scripts/generate-canonical-fixtures.cjs with a deterministic Ed25519
 * keypair; the backend spec asserts the same vector.
 */
function test_canonical_json_contract_v2_signed_fixtures() {
	echo "\n[canonical JSON contract v2 — signed fixtures (cross-language proof)]\n";

	$fixture_path = __DIR__ . '/canonical-fixtures.json';
	$fixture      = json_decode( file_get_contents( $fixture_path ), true );
	expect( 'canonical-fixtures.json present + decoded', is_array( $fixture ) && isset( $fixture['cases'] ) );

	// Contract version MUST match the backend (drift fails fast).
	expect_eq( 'contractVersion matches backend (2)', $fixture['contractVersion'], Felix_Crypto::CANONICAL_CONTRACT_VERSION );
	expect_eq( 'contractVersion is 2', $fixture['contractVersion'], 2 );

	// The PHP encoder MUST preserve object-vs-array identity: {} renders {},
	// [] renders []. (This is the PHP json_decode associative divergence the
	// contract closes — verify_command_signature decodes with objects
	// preserved so an empty object stays a stdClass, not a collapsed array.)
	expect_eq( 'empty object {} (stdClass)', Felix_Crypto::canonical_json( new stdClass() ), '{}' );
	expect_eq( 'empty array []', Felix_Crypto::canonical_json( array() ), '[]' );
	expect_eq( 'mixed {obj:{},arr:[]} identity preserved', Felix_Crypto::canonical_json( (object) array( 'obj' => new stdClass(), 'arr' => array() ) ), '{"arr":[],"obj":{}}' );

	// Exponent floats: PHP's 1.0e-7 dtoa form MUST normalize to the backend's
	// ECMAScript 1e-7 form.
	expect_eq( '1e-7 (not 1.0e-7)', Felix_Crypto::canonical_json( 1e-7 ), '1e-7' );
	expect_eq( '5e-8', Felix_Crypto::canonical_json( 5e-8 ), '5e-8' );
	expect_eq( '1.5e-7', Felix_Crypto::canonical_json( 1.5e-7 ), '1.5e-7' );
	expect_eq( '1e+21 (huge exponent)', Felix_Crypto::canonical_json( 1e21 ), '1e+21' );
	expect_eq( '1e20 → 100000000000000000000 (no exponent)', Felix_Crypto::canonical_json( 1.0e20 ), '100000000000000000000' );
	expect_eq( '0.000001 (micro)', Felix_Crypto::canonical_json( 0.000001 ), '0.000001' );

	// Integers, negative, zero.
	expect_eq( '42', Felix_Crypto::canonical_json( 42 ), '42' );
	expect_eq( '-7', Felix_Crypto::canonical_json( -7 ), '-7' );
	expect_eq( '0', Felix_Crypto::canonical_json( 0 ), '0' );
	expect_eq( '-0.0 → 0', Felix_Crypto::canonical_json( -0.0 ), '0' );
	expect_eq( '-3.14', Felix_Crypto::canonical_json( -3.14 ), '-3.14' );

	// Fail-closed: non-finite numbers are REJECTED (no bytes, no verify).
	expect( 'INF rejected (fail-closed)', false === Felix_Crypto::canonical_json( INF ) );
	expect( 'NAN rejected (fail-closed)', false === Felix_Crypto::canonical_json( NAN ) );
	expect( 'nested INF rejected (fail-closed propagates)', false === Felix_Crypto::canonical_json( (object) array( 'x' => INF ) ) );

	// The definitive cross-language proof: for every fixture case the PHP
	// encoder reproduces the pinned bytes AND libsodium verifies the
	// NODE-produced signature over those bytes.
	$pub_b64 = $fixture['publicKeyB64'];
	foreach ( $fixture['cases'] as $c ) {
		$decoded = json_decode( $c['input'], false ); // objects preserved (stdClass)
		$bytes   = Felix_Crypto::canonical_json( $decoded );
		expect_eq( "[{$c['name']}] PHP encoder === pinned bytes", $bytes, $c['expected'] );

		$sig_raw = base64_decode( $c['signature'], true );
		$pub_raw = base64_decode( $pub_b64, true );
		$ok      = sodium_crypto_sign_verify_detached( $sig_raw, $c['expected'], $pub_raw );
		expect( "[{$c['name']}] NODE-produced Ed25519 signature verifies in PHP (cross-language bytes identical)", $ok );
	}
}

/**
 * #4 — a signed envelope with a URL + non-ASCII args verifies after the wire
 * re-serialization (the real cross-language path: backend signs canonical, the
 * raw body carries whatever order, plugin re-canonicalizes + verifies).
 */
function test_signature_with_url_and_unicode() {
	echo "\n[signature survives URL slash + unicode args (#4)]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	$env = make_envelope(
		array(
			'args' => array(
				'storeUrl' => 'https://shop.example.com/path',
				'customer' => 'José Müller',
			),
		)
	);
	list( $raw ) = sign_envelope( $env, $secret );
	// Simulate the wire re-serializing the body in a DIFFERENT key order (as a
	// real HTTP layer might): decode, shuffle a key to the end, re-encode. The
	// signature must still verify because canonical_json sorts keys.
	$shuffled         = json_decode( $raw, true );
	$args             = $shuffled['args'];
	$customer         = $args['customer'];
	unset( $args['customer'] );
	$args['customer'] = $customer;
	$shuffled['args'] = $args;
	$rewired          = wp_json_encode( $shuffled );

	$t = $proc->process( $rewired, json_decode( $rewired, true ) );
	expect_eq( 'URL+unicode envelope with reordered args verifies + executes', $t['status'], 'done' );
}

/**
 * #3 — a stale (crashed) reservation is reconciled to honest `unconfirmed` on
 * the next redelivery, not an indefinite reservation_conflict loop.
 */
function test_stale_reservation_reconciled() {
	echo "\n[stale reservation reconciled to unconfirmed (#3)]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	// Seed a STALE reserved row (created 10 min ago → beyond the 120s lease).
	$env = make_envelope();
	$GLOBALS['wpdb']->seed_row(
		LEDGER_TABLE,
		array(
			'id'          => $env['commandId'],
			'type'        => 'ping',
			'status'      => 'reserved',
			'executed_at' => current_time( 'mysql' ),
			'created_at'  => gmdate( 'Y-m-d H:i:s', time() - 600 ),
		)
	);

	list( $raw ) = sign_envelope( $env, $secret );
	$before      = $GLOBALS['__felix_handler_calls'];
	$t           = $proc->process( $raw, json_decode( $raw, true ) );

	// The stale reservation is reconciled to unconfirmed (honest terminal),
	// returned as an already-executed idempotent result. The handler must NOT
	// re-run (the prior execution's outcome is unknown).
	expect_eq( 'stale reservation => unconfirmed (honest)', $t['status'], 'unconfirmed' );
	expect( 'stale reservation did not re-run handler', $GLOBALS['__felix_handler_calls'] === $before );

	// The row is now unconfirmed in the ledger.
	$row = Felix_Command_Ledger::get( $env['commandId'] );
	expect_eq( 'ledger row reconciled to unconfirmed', $row->status, 'unconfirmed' );

	// A SECOND redelivery returns the stored unconfirmed (idempotent).
	$t2 = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'second redelivery returns stored unconfirmed', $t2['status'], 'unconfirmed' );
}

/**
 * #3 — a FRESH reservation (still in-flight) is NOT reconciled; it stays a
 * reservation_conflict (the crash heuristic must not steal a live claimant).
 */
function test_fresh_reservation_not_reconciled() {
	echo "\n[fresh reservation stays conflict (#3)]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	$env = make_envelope();
	$GLOBALS['wpdb']->seed_row(
		LEDGER_TABLE,
		array(
			'id'          => $env['commandId'],
			'type'        => 'ping',
			'status'      => 'reserved',
			'executed_at' => current_time( 'mysql' ),
			'created_at'  => gmdate( 'Y-m-d H:i:s', time() - 5 ), // 5s ago — fresh
		)
	);

	list( $raw ) = sign_envelope( $env, $secret );
	$t           = $proc->process( $raw, json_decode( $raw, true ) );
	expect_eq( 'fresh reservation => reservation_conflict', $t['error']['code'], 'reservation_conflict' );
	$row = Felix_Command_Ledger::get( $env['commandId'] );
	expect_eq( 'fresh reservation row left as reserved', $row->status, 'reserved' );
}

/**
 * Fresh reservation_conflict is NONTERMINAL: the poll path must preserve the
 * command and re-run the idempotent processor without re-executing the
 * handler, retrieving the LATER stored terminal once the in-flight execution
 * finishes — and never post a terminal 'rejected'. This is the contract the
 * runner's await_reserved_terminal() retry relies on.
 */
function test_fresh_conflict_then_later_terminal_retrieval() {
	echo "\n[fresh reservation_conflict then later terminal retrieval (nonterminal)]\n";
	reset_state();
	$secret = make_backend_key();
	$proc   = new Felix_Command_Processor();

	// Seed a FRESH reserved row — another execution holds the reservation and
	// is still running (created moments ago, well within the 120s lease).
	$env = make_envelope();
	$GLOBALS['wpdb']->seed_row(
		LEDGER_TABLE,
		array(
			'id'          => $env['commandId'],
			'type'        => 'ping',
			'status'      => 'reserved',
			'executed_at' => current_time( 'mysql' ),
			'created_at'  => gmdate( 'Y-m-d H:i:s', time() - 3 ), // 3s ago — fresh
		)
	);

	list( $raw ) = sign_envelope( $env, $secret );

	// First delivery while the reservation is live → reservation_conflict
	// (NONTERMINAL). The handler must NOT run.
	$before = $GLOBALS['__felix_handler_calls'];
	$t      = $proc->process( $raw, json_decode( $raw, true ) );

	expect( 'fresh conflict classified nonterminal', Felix_Command_Processor::is_reservation_conflict( $t ) );
	expect_eq( 'fresh conflict => reservation_conflict code', $t['error']['code'], 'reservation_conflict' );
	expect( 'handler NOT run on fresh conflict', $GLOBALS['__felix_handler_calls'] === $before );

	// The poll runner would retry here. Simulate the in-flight execution
	// reaching its terminal state: mark the reserved row done (the original
	// handler completed). This is exactly what the holder's mark_terminal()
	// does once the side-effecting work finishes.
	Felix_Command_Ledger::mark_terminal(
		$env['commandId'],
		'done',
		array( 'pong' => true )
	);

	// Retry (the same command, idempotent processor): the now-stored terminal
	// is retrieved WITHOUT re-executing the handler.
	$calls_before = $GLOBALS['__felix_handler_calls'];
	$t2           = $proc->process( $raw, json_decode( $raw, true ) );

	expect( 'later retrieval no longer a reservation_conflict', ! Felix_Command_Processor::is_reservation_conflict( $t2 ) );
	expect_eq( 'later retrieval returns stored terminal done', $t2['status'], 'done' );
	expect( 'later retrieval marked alreadyExecuted (idempotent)', ! empty( $t2['alreadyExecuted'] ) );
	expect( 'later retrieval did NOT re-run handler', $GLOBALS['__felix_handler_calls'] === $calls_before );
	expect_eq( 'later retrieval returns stored pong', $t2['result']['pong'], true );

	// REST transport maps a FRESH conflict to 409 (nonterminal) using the same
	// shared predicate — proving the classification is consistent across both
	// transports (REST 409 + poll retry/defer, never a posted terminal rejected).
	reset_state();
	$secret2 = make_backend_key();
	$env2    = make_envelope();
	$GLOBALS['wpdb']->seed_row(
		LEDGER_TABLE,
		array(
			'id'          => $env2['commandId'],
			'type'        => 'ping',
			'status'      => 'reserved',
			'executed_at' => current_time( 'mysql' ),
			'created_at'  => gmdate( 'Y-m-d H:i:s', time() - 2 ),
		)
	);
	list( $raw2 ) = sign_envelope( $env2, $secret2 );
	$resp = ( new Felix_REST() )->handle_command( new Fake_REST_Request( $raw2 ) );
	expect_eq( 'REST maps fresh conflict => 409 (nonterminal)', $resp->get_status(), 409 );
	expect_eq( 'REST conflict body status rejected', $resp->get_data()['status'], 'rejected' );
	expect_eq( 'REST conflict body code reservation_conflict', $resp->get_data()['error']['code'], 'reservation_conflict' );
}

/**
 * #6 — enumeration completeness: renew_subscription has a family AND a handler
 * (the gap was: family_map named it, the adapter called it, but no handler was
 * registered → unknown_type). Also asserts every produced type has a family.
 */
function test_renew_handler_registered() {
	echo "\n[renew_subscription handler + family consistency (#6)]\n";

	// family_map includes renew_subscription.
	expect_eq( 'renew_subscription family is subscription_write', Felix_Command_Handlers::family_for( 'renew_subscription' ), 'subscription_write' );

	// A handler IS registered (execute does NOT return unknown_type).
	$h = new Felix_Command_Handlers();
	$r = $h->execute( 'cmd-x', 'renew_subscription', array( 'subscriptionId' => 1 ) );
	expect( 'renew_subscription has a handler (not unknown_type)', ! ( 'rejected' === $r['status'] && 'unknown_type' === $r['error']['code'] ) );

	// Every connector-produced type resolves to a family (deny/default for unknown).
	$produced = array(
		'ping', 'get_order', 'search_orders', 'sync_orders', 'sync_products',
		'list_products', 'get_subscription', 'list_subscriptions', 'list_subscriptions_for_customer',
		'list_customers', 'update_order_status', 'update_order_shipping_address',
		'create_coupon', 'update_coupon', 'deactivate_coupon',
		'update_subscription_status', 'renew_subscription',
	);
	$missing = array();
	foreach ( $produced as $type ) {
		if ( null === Felix_Command_Handlers::family_for( $type ) ) {
			$missing[] = $type;
		}
	}
	expect( 'every produced command type has a family', empty( $missing ) );

	// Unknown type stays deny/default.
	expect( 'unknown type has no family (deny)', null === Felix_Command_Handlers::family_for( 'totally_made_up' ) );
}

/**
 * #1 — authorization_basis is accepted as an OBJECT (the backend now stores it
 * as ::jsonb, not a JSON string). The handler authorize() must accept the
 * object form and not reject it.
 */
function test_authorization_basis_object_form() {
	echo "\n[authorization_basis object form accepted (#1)]\n";
	// approval object → write allowed.
	$r = Felix_Command_Handlers::authorize( 'subscription_write', array( 'kind' => 'approval', 'evidenceRef' => 'human_approved' ) );
	expect( 'approval basis object accepted for write', $r['ok'] );

	// A JSON STRING (the old backend bug shape) must be rejected — proving the
	// plugin fails closed on the string form so the ::jsonb fix is required.
	$r2 = Felix_Command_Handlers::authorize( 'subscription_write', '{"kind":"approval"}' );
	expect( 'string authorization_basis rejected (proves #1 contract)', ! $r2['ok'] );
}

// =============================================================================
// V0.4.1 COMMAND-SURFACE PARITY TESTS
// =============================================================================
//
// The new handler surface (refund.create, get_coupon, list_coupons, get_product,
// sync_coupons, register_webhooks, verify_webhooks, remove_webhooks, create_order,
// delete_customer) is exercised here end-to-end against the in-memory WC/WP
// shims in bootstrap.php. Each group covers a happy path AND a validation
// failure; additionally: over-refund rejection, admin-refusal on delete_customer,
// and idempotent webhook re-registration.

/**
 * Seed an order into the in-memory store. Returns the order id.
 */
function seed_order( $overrides = array() ) {
	$id = ++$GLOBALS['__felix_next_id']['order'];
	$GLOBALS['__felix_orders_meta'][ $id ] = array_merge(
		array(
			'status'         => 'processing',
			'total'          => 100.0,
			'total_refunded' => 0.0,
			'currency'       => 'USD',
			'number'         => (string) $id,
			'customer_id'    => 0,
			'created'        => time(),
			'items'          => array(),
			'billing'        => array(),
			'shipping'       => array(),
			'payment_method' => 'stripe',
		),
		$overrides
	);
	return $id;
}

/**
 * Seed a product. Returns the product id.
 */
function seed_product( $overrides = array() ) {
	$id = ++$GLOBALS['__felix_next_id']['product'];
	$GLOBALS['__felix_products_meta'][ $id ] = array_merge(
		array(
			'name'            => 'Widget ' . $id,
			'slug'            => 'widget-' . $id,
			'status'          => 'publish',
			'type'            => 'simple',
			'price'           => '10.00',
			'regularPrice'    => '10.00',
			'salePrice'       => '',
			'sku'             => 'SKU-' . $id,
			'manageStock'     => true,
			'stockStatus'     => 'instock',
			'stockQuantity'   => 50,
			'description'     => 'A widget.',
			'shortDescription'=> 'Widget.',
		),
		$overrides
	);
	return $id;
}

/**
 * Seed a coupon AND its shop_coupon CPT post (the CPT powers list/sync via
 * WP_Query). Returns the coupon id.
 */
function seed_coupon( $code, $overrides = array(), $post_overrides = array() ) {
	$id     = ++$GLOBALS['__felix_next_id']['coupon'];
	$modified_ts = $post_overrides['modified'] ?? time();
	$date_ts     = $post_overrides['date'] ?? $modified_ts;
	$GLOBALS['__felix_coupons'][ $id ] = array_merge(
		array(
			'code'         => wc_sanitize_coupon_code( $code ),
			'discountType' => 'percent',
			'amount'       => 10,
			'status'       => 'publish',
			'dateExpires'  => null,
			'usageCount'   => 0,
			'usageLimit'   => 0,
			'freeShipping' => false,
			'productIds'   => array(),
		),
		$overrides
	);
	$GLOBALS['__felix_coupon_code_index'][ wc_sanitize_coupon_code( $code ) ] = $id;

	$post                 = new stdClass();
	$post->ID             = $id;
	$post->post_title     = $code;
	$post->post_modified  = gmdate( 'Y-m-d H:i:s', $modified_ts );
	$post->post_date      = gmdate( 'Y-m-d H:i:s', $date_ts );
	$GLOBALS['__felix_coupon_posts'][ $id ] = $post;
	return $id;
}

/**
 * Seed a webhook. Returns the webhook id.
 */
function seed_webhook( $topic, $delivery_url, $overrides = array() ) {
	$id = ++$GLOBALS['__felix_next_id']['webhook'];
	$GLOBALS['__felix_webhooks'][ $id ] = array_merge(
		array(
			'name'         => 'Felix',
			'status'       => 'active',
			'topic'        => $topic,
			'delivery_url' => $delivery_url,
			'secret'       => 's',
			'api_version'  => 3,
		),
		$overrides
	);
	return $id;
}

/**
 * Seed a WP user. Returns the user id.
 */
function seed_user( $overrides = array() ) {
	$id = ++$GLOBALS['__felix_next_id']['user'];
	$data = array_merge(
		array(
			'ID'           => $id,
			'user_email'   => 'user' . $id . '@example.com',
			'roles'        => array( 'customer' ),
			'display_name' => 'Customer ' . $id,
		),
		$overrides
	);
	$GLOBALS['__felix_users'][ $id ] = new WP_User( $data );
	return $id;
}

/**
 * Execute a handler directly (bypassing the processor) with a write basis.
 */
function exec_write( $type, $args ) {
	$h = new Felix_Command_Handlers();
	return $h->execute( 'cmd-' . $type, $type, $args, write_basis() );
}
function exec_read( $type, $args ) {
	$h = new Felix_Command_Handlers();
	return $h->execute( 'cmd-' . $type, $type, $args, read_basis() );
}

/**
 * Every connector-produced command type has BOTH a family AND a handler, and
 * the new write families are classified as writes (read basis denies them).
 */
function test_command_surface_parity() {
	echo "\n[command-surface parity — family + handler for every type]\n";

	$types = array(
		'ping', 'get_order', 'search_orders', 'sync_orders', 'sync_products', 'sync_coupons',
		'get_product', 'list_products', 'list_customers',
		'get_subscription', 'list_subscriptions', 'list_subscriptions_for_customer',
		'get_coupon', 'list_coupons',
		'register_webhooks', 'verify_webhooks', 'remove_webhooks',
		'update_order_status', 'update_order_shipping_address', 'create_order',
		'create_coupon', 'update_coupon', 'deactivate_coupon',
		'update_subscription_status', 'renew_subscription',
		'refund.create', 'delete_customer',
	);

	$no_family = array();
	foreach ( $types as $type ) {
		if ( null === Felix_Command_Handlers::family_for( $type ) ) {
			$no_family[] = $type;
		}
	}
	expect( 'every parity type has a family', empty( $no_family ) );

	// Every parity type has a handler registered (introspect the registry so
	// we don't depend on execution-time WC stubs for handlers not under test).
	$no_handler = array();
	$h          = new Felix_Command_Handlers();
	$prop       = new ReflectionProperty( 'Felix_Command_Handlers', 'handlers' );
	$prop->setAccessible( true );
	$registered = $prop->getValue( $h );
	foreach ( $types as $type ) {
		if ( ! isset( $registered[ $type ] ) ) {
			$no_handler[] = $type;
		}
	}
	expect( 'every parity type has a handler (none unknown_type)', empty( $no_handler ) );

	// New write families must be classified as WRITE (read basis insufficient).
	expect( 'order_create is a write family', ! Felix_Command_Handlers::is_read_family( 'order_create' ) );
	expect( 'customer_write is a write family', ! Felix_Command_Handlers::is_read_family( 'customer_write' ) );
	expect( 'refund is a write family', ! Felix_Command_Handlers::is_read_family( 'refund' ) );
	expect( 'webhook_management is a write family', ! Felix_Command_Handlers::is_read_family( 'webhook_management' ) );

	// Read families for the new read handlers.
	expect( 'coupon_read is a read family', Felix_Command_Handlers::is_read_family( 'coupon_read' ) );
	expect( 'product_read is a read family', Felix_Command_Handlers::is_read_family( 'product_read' ) );
}

/**
 * refund.create — happy path + over-refund rejection + missing-args failure +
 * a WP_Error from wc_create_refund surfaces the store's message (never reports
 * success without a refund id).
 */
function test_refund_create() {
	echo "\n[refund.create — happy, over-refund reject, validation]\n";
	reset_state();

	// Happy path: full refund on a $100 order.
	$oid = seed_order( array( 'total' => 100.0 ) );
	$r   = exec_write( 'refund.create', array( 'orderId' => $oid, 'amount' => 25, 'reason' => 'customer request' ) );
	expect_eq( 'refund.create happy => done', $r['status'], 'done' );
	expect_eq( 'refund has an id', $r['result']['refund']['id'] > 0, true );
	expect_eq( 'refund amount echoed', $r['result']['refund']['amount'], 25 );
	expect_eq( 'order totalRefunded reflects refund', $r['result']['order']['totalRefunded'], 25 );
	expect( 'refund dateCreated present', ! empty( $r['result']['refund']['dateCreated'] ) );

	// Over-refund: $200 on a $75 remaining ($100 total − $25 already refunded).
	$r2 = exec_write( 'refund.create', array( 'orderId' => $oid, 'amount' => 200, 'reason' => 'too much' ) );
	expect_eq( 'over-refund => failed', $r2['status'], 'failed' );
	expect( 'over-refund message mentions exceeds', false !== strpos( $r2['error']['message'], 'exceeds' ) );

	// Exactly-remaining refund succeeds (boundary).
	$r3 = exec_write( 'refund.create', array( 'orderId' => $oid, 'amount' => 75, 'reason' => 'remainder' ) );
	expect_eq( 'remaining-total refund succeeds', $r3['status'], 'done' );

	// Missing args.
	$r4 = exec_write( 'refund.create', array( 'orderId' => $oid ) );
	expect_eq( 'missing amount => failed', $r4['status'], 'failed' );

	// Unknown order.
	$r5 = exec_write( 'refund.create', array( 'orderId' => 999999, 'amount' => 5 ) );
	expect_eq( 'unknown order => failed', $r5['status'], 'failed' );

	// P2-1: zero/negative amount rejected explicitly BEFORE the over-refund
	// check — a negative amount never satisfies `> remaining`, so without
	// this guard it would bypass the upper bound and reach wc_create_refund.
	$oid2 = seed_order( array( 'total' => 100.0 ) );
	$r6 = exec_write( 'refund.create', array( 'orderId' => $oid2, 'amount' => 0 ) );
	expect_eq( 'zero amount => failed', $r6['status'], 'failed' );
	expect( 'zero amount message names zero', false !== strpos( $r6['error']['message'], 'zero' ) );

	$r7 = exec_write( 'refund.create', array( 'orderId' => $oid2, 'amount' => -25 ) );
	expect_eq( 'negative amount => failed', $r7['status'], 'failed' );
	expect( 'negative amount message names zero', false !== strpos( $r7['error']['message'], 'zero' ) );
}

/**
 * get_coupon — happy path (code + couponId) + not-found + missing-args.
 */
function test_get_coupon() {
	echo "\n[get_coupon — happy, not-found, validation]\n";
	reset_state();

	$cid = seed_coupon( 'SAVE10', array( 'discountType' => 'percent', 'amount' => 10, 'freeShipping' => true, 'productIds' => array( 7, 8 ) ) );

	$r = exec_read( 'get_coupon', array( 'code' => 'SAVE10' ) );
	expect_eq( 'get_coupon by code => done', $r['status'], 'done' );
	expect_eq( 'coupon id matches', $r['result']['coupon']['id'], $cid );
	expect_eq( 'coupon code uppercased on store', $r['result']['coupon']['code'], 'save10' );
	expect_eq( 'discountType projected', $r['result']['coupon']['discountType'], 'percent' );
	expect_eq( 'amount projected', $r['result']['coupon']['amount'], 10 );
	expect_eq( 'freeShipping projected', $r['result']['coupon']['freeShipping'], true );
	expect_eq( 'productIds projected', $r['result']['coupon']['productIds'], array( 7, 8 ) );

	$r2 = exec_read( 'get_coupon', array( 'couponId' => $cid ) );
	expect_eq( 'get_coupon by id => done', $r2['status'], 'done' );

	$r3 = exec_read( 'get_coupon', array( 'code' => 'NOPE' ) );
	expect_eq( 'unknown coupon => failed', $r3['status'], 'failed' );

	$r4 = exec_read( 'get_coupon', array() );
	expect_eq( 'missing code+id => failed', $r4['status'], 'failed' );
}

/**
 * list_coupons — paged list + hasMore pagination + search + perPage cap.
 */
function test_list_coupons() {
	echo "\n[list_coupons — paged, hasMore, search]\n";
	reset_state();

	for ( $i = 0; $i < 5; $i++ ) {
		seed_coupon( 'C' . $i );
	}
	seed_coupon( 'PROMO-X' );

	// page 1 of perPage 2 → 2 items, hasMore true.
	$r = exec_read( 'list_coupons', array( 'page' => 1, 'perPage' => 2 ) );
	expect_eq( 'list_coupons => done', $r['status'], 'done' );
	expect_eq( 'page size respected', count( $r['result']['coupons'] ), 2 );
	expect_eq( 'hasMore true when more remain', $r['result']['hasMore'], true );

	// page 3 of perPage 2 → 1 item (6 total), hasMore false.
	$r2 = exec_read( 'list_coupons', array( 'page' => 3, 'perPage' => 2 ) );
	expect_eq( 'last page hasMore false', $r2['result']['hasMore'], false );

	// search narrows to the PROMO title.
	$r3 = exec_read( 'list_coupons', array( 'search' => 'PROMO', 'perPage' => 50 ) );
	expect_eq( 'search matches 1 coupon', count( $r3['result']['coupons'] ), 1 );
	expect_eq( 'search matched PROMO-X', $r3['result']['coupons'][0]['code'], 'promo-x' );

	// perPage cap at 50 even when over-requested.
	$r4 = exec_read( 'list_coupons', array( 'perPage' => 9999 ) );
	expect_eq( 'perPage capped (no failure)', $r4['status'], 'done' );
}

/**
 * get_product — by id and by sku, categories appended, not-found, missing-args.
 */
function test_get_product() {
	echo "\n[get_product — by id, by sku, categories]\n";
	reset_state();

	$pid = seed_product( array( 'sku' => 'WIDGET-42', 'description' => 'A fine widget.' ) );
	// seed a product_cat term.
	$term       = new stdClass();
	$term->name = 'Gear';
	$GLOBALS['__felix_terms'][ $pid ]['product_cat'] = array( $term );

	$r = exec_read( 'get_product', array( 'productId' => $pid ) );
	expect_eq( 'get_product by id => done', $r['status'], 'done' );
	expect_eq( 'description projected', $r['result']['product']['description'], 'A fine widget.' );
	expect( 'stockQuantity projected', null !== $r['result']['product']['stockQuantity'] );
	expect_eq( 'categories appended', $r['result']['product']['categories'], array( 'Gear' ) );

	$r2 = exec_read( 'get_product', array( 'sku' => 'WIDGET-42' ) );
	expect_eq( 'get_product by sku => done', $r2['status'], 'done' );
	expect_eq( 'sku lookup resolves id', $r2['result']['product']['id'], $pid );

	$r3 = exec_read( 'get_product', array( 'sku' => 'MISSING' ) );
	expect_eq( 'unknown sku => failed', $r3['status'], 'failed' );

	$r4 = exec_read( 'get_product', array() );
	expect_eq( 'missing productId+sku => failed', $r4['status'], 'failed' );
}

/**
 * sync_coupons — mirrors sync_orders: paged, modified_after cursor, ASC.
 */
function test_sync_coupons() {
	echo "\n[sync_coupons — paged, modified_after cursor, ASC]\n";
	reset_state();

	$old = seed_coupon( 'OLD', array(), array( 'modified' => time() - 3600 ) );
	$new = seed_coupon( 'NEW', array(), array( 'modified' => time() - 60 ) );

	// No cursor → both returned, ASC by modified (OLD before NEW).
	$r = exec_read( 'sync_coupons', array() );
	expect_eq( 'sync_coupons no cursor => done', $r['status'], 'done' );
	expect_eq( 'returns all coupons', count( $r['result']['coupons'] ), 2 );
	expect_eq( 'ASC order (OLD first)', $r['result']['coupons'][0]['code'], 'old' );

	// modified_after cursor → only the recently-modified coupon.
	$r2 = exec_read( 'sync_coupons', array( 'modifiedAfter' => gmdate( 'Y-m-d H:i:s', time() - 120 ) ) );
	expect_eq( 'modified_after filters older coupon', count( $r2['result']['coupons'] ), 1 );
	expect_eq( 'only NEW coupon after cursor', $r2['result']['coupons'][0]['code'], 'new' );

	// paged: limit 1 page 1 → 1 item.
	$r3 = exec_read( 'sync_coupons', array( 'limit' => 1, 'page' => 1 ) );
	expect_eq( 'limit respected', count( $r3['result']['coupons'] ), 1 );
}

/**
 * register_webhooks — happy path + IDEMPOTENT re-register (same deliveryUrl +
 * topic skipped, not duplicated).
 */
function test_register_webhooks() {
	echo "\n[register_webhooks — happy + idempotent re-register]\n";
	reset_state();

	$r = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://felix.example.com/hook',
		'secret'      => 'topsecret',
		'topics'      => array( 'order.created', 'order.updated' ),
	) );
	expect_eq( 'register_webhooks => done', $r['status'], 'done' );
	expect_eq( 'both topics registered', count( $r['result']['registered'] ), 2 );
	expect_eq( 'none skipped first time', count( $r['result']['skipped'] ), 0 );
	expect( 'registered entries carry ids', $r['result']['registered'][0]['id'] > 0 );

	// Idempotent re-register: same deliveryUrl + topics → all skipped.
	$r2 = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://felix.example.com/hook',
		'secret'      => 'topsecret',
		'topics'      => array( 'order.created', 'order.updated' ),
	) );
	expect_eq( 're-register => done', $r2['status'], 'done' );
	expect_eq( 're-register none newly registered', count( $r2['result']['registered'] ), 0 );
	expect_eq( 're-register all skipped (idempotent)', count( $r2['result']['skipped'] ), 2 );

	// A new topic alongside an existing one → 1 registered, 1 skipped.
	$r3 = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://felix.example.com/hook',
		'secret'      => 'topsecret',
		'topics'      => array( 'order.created', 'order.deleted' ),
	) );
	expect_eq( 'mixed: 1 newly registered', count( $r3['result']['registered'] ), 1 );
	expect_eq( 'mixed: 1 skipped', count( $r3['result']['skipped'] ), 1 );
	expect_eq( 'newly registered is order.deleted', $r3['result']['registered'][0]['topic'], 'order.deleted' );

	// Validation: missing topics.
	$r4 = exec_write( 'register_webhooks', array( 'deliveryUrl' => 'https://x.example.com/hook' ) );
	expect_eq( 'missing topics => failed', $r4['status'], 'failed' );

	// P2-2: deliveryUrl is validated — scheme MUST be https, and the host
	// MUST NOT be localhost or a private/reserved IP range (SSRF guard for the
	// target the store will POST to).

	// Non-https scheme rejected.
	$http = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'http://felix.example.com/hook',
		'secret'      => 's',
		'topics'      => array( 'order.created' ),
	) );
	expect_eq( 'http deliveryUrl => failed', $http['status'], 'failed' );
	expect( 'http refusal names https', false !== strpos( $http['error']['message'], 'https' ) );

	// Private IPv4 ranges rejected.
	$priv = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://10.0.0.5/hook',
		'secret'      => 's',
		'topics'      => array( 'order.created' ),
	) );
	expect_eq( 'private 10/8 deliveryUrl => failed', $priv['status'], 'failed' );
	expect( 'private refusal names private', false !== strpos( $priv['error']['message'], 'private' ) );

	$cg = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://192.168.1.1/hook',
		'secret'      => 's',
		'topics'      => array( 'order.created' ),
	) );
	expect_eq( 'private 192.168/16 deliveryUrl => failed', $cg['status'], 'failed' );

	// Loopback (127/8 IPv4, ::1 IPv6) rejected.
	$loop = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://127.0.0.1/hook',
		'secret'      => 's',
		'topics'      => array( 'order.created' ),
	) );
	expect_eq( 'loopback IPv4 deliveryUrl => failed', $loop['status'], 'failed' );

	$v6 = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://[::1]/hook',
		'secret'      => 's',
		'topics'      => array( 'order.created' ),
	) );
	expect_eq( 'loopback IPv6 deliveryUrl => failed', $v6['status'], 'failed' );

	// 'localhost' host rejected.
	$lh = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://localhost/hook',
		'secret'      => 's',
		'topics'      => array( 'order.created' ),
	) );
	expect_eq( 'localhost deliveryUrl => failed', $lh['status'], 'failed' );

	// A public https named host is accepted (positive control).
	$ok = exec_write( 'register_webhooks', array(
		'deliveryUrl' => 'https://hooks.felix.app/inbox',
		'secret'      => 's',
		'topics'      => array( 'order.created' ),
	) );
	expect_eq( 'public https deliveryUrl => done', $ok['status'], 'done' );
	expect_eq( 'public https registers the topic', count( $ok['result']['registered'] ), 1 );
}

/**
 * verify_webhooks — active / missing / disabled classification for a deliveryUrl.
 */
function test_verify_webhooks() {
	echo "\n[verify_webhooks — active, missing, disabled]\n";
	reset_state();

	seed_webhook( 'order.created', 'https://felix.example.com/hook', array( 'status' => 'active' ) );
	seed_webhook( 'order.updated', 'https://felix.example.com/hook', array( 'status' => 'paused' ) );
	// A webhook for a DIFFERENT delivery url must be ignored.
	seed_webhook( 'order.created', 'https://other.example.com/hook', array( 'status' => 'active' ) );

	$r = exec_write( 'verify_webhooks', array(
		'deliveryUrl' => 'https://felix.example.com/hook',
		'topics'      => array( 'order.created', 'order.updated', 'order.deleted' ),
	) );
	expect_eq( 'verify_webhooks => done', $r['status'], 'done' );
	expect_eq( 'active topic listed', $r['result']['active'], array( 'order.created' ) );
	expect_eq( 'missing topic listed', $r['result']['missing'], array( 'order.deleted' ) );
	expect_eq( 'disabled topic carried with status', $r['result']['disabled'][0]['topic'], 'order.updated' );
	expect_eq( 'disabled topic status paused', $r['result']['disabled'][0]['status'], 'paused' );

	$r2 = exec_write( 'verify_webhooks', array( 'deliveryUrl' => 'https://felix.example.com/hook' ) );
	expect_eq( 'missing topics => failed', $r2['status'], 'failed' );
}

/**
 * remove_webhooks — deletes only matching delivery_url, counts removed.
 */
function test_remove_webhooks() {
	echo "\n[remove_webhooks — delete matching deliveryUrl]\n";
	reset_state();

	seed_webhook( 'order.created', 'https://felix.example.com/hook' );
	seed_webhook( 'order.updated', 'https://felix.example.com/hook' );
	seed_webhook( 'order.created', 'https://other.example.com/hook' );

	$r = exec_write( 'remove_webhooks', array( 'deliveryUrl' => 'https://felix.example.com/hook' ) );
	expect_eq( 'remove_webhooks => done', $r['status'], 'done' );
	expect_eq( 'removed both matching webhooks', $r['result']['removed'], 2 );

	// Second removal on same url → 0 (already gone).
	$r2 = exec_write( 'remove_webhooks', array( 'deliveryUrl' => 'https://felix.example.com/hook' ) );
	expect_eq( 'idempotent remove returns 0', $r2['result']['removed'], 0 );

	// The unrelated webhook survives.
	$r3 = exec_write( 'verify_webhooks', array(
		'deliveryUrl' => 'https://other.example.com/hook',
		'topics'      => array( 'order.created' ),
	) );
	expect_eq( 'unrelated webhook survives', $r3['result']['active'], array( 'order.created' ) );

	$r4 = exec_write( 'remove_webhooks', array() );
	expect_eq( 'missing deliveryUrl => failed', $r4['status'], 'failed' );
}

/**
 * create_order — happy path + zero-price (comp-order) override semantics +
 * missing lineItems + unknown product.
 */
function test_create_order() {
	echo "\n[create_order — happy, zero-price override, validation]\n";
	reset_state();

	$p1 = seed_product( array( 'price' => '10.00', 'name' => 'Hat' ) );
	$p2 = seed_product( array( 'price' => '25.00', 'name' => 'Bag' ) );

	$r = exec_write( 'create_order', array(
		'lineItems' => array(
			array( 'productId' => $p1, 'quantity' => 2 ),
			array( 'productId' => $p2, 'quantity' => 1 ),
		),
		'shippingAddress' => array( 'firstName' => 'Ada', 'lastName' => 'Lovelace', 'address1' => '1 Main', 'city' => 'London', 'postcode' => 'W1', 'country' => 'GB' ),
		'status'          => 'processing',
		'note'            => 'comp order',
	) );
	expect_eq( 'create_order => done', $r['status'], 'done' );
	expect( 'order id assigned', $r['result']['order']['id'] > 0 );
	expect_eq( 'total = 2*10 + 1*25', $r['result']['order']['total'], 45.0 );
	expect_eq( 'default status processing', $r['result']['order']['status'], 'processing' );
	expect_eq( 'lineItems projected', count( $r['result']['order']['lineItems'] ), 2 );

	// Zero-price override AFTER calculate_totals → total reflects overrides.
	$r2 = exec_write( 'create_order', array(
		'lineItems' => array(
			array( 'productId' => $p1, 'quantity' => 2, 'priceOverride' => 0 ),
			array( 'productId' => $p2, 'quantity' => 1 ),
		),
	) );
	expect_eq( 'override total = 2*0 + 1*25', $r2['result']['order']['total'], 25.0 );
	expect_eq( 'overridden line total zero', $r2['result']['order']['lineItems'][0]['total'], 0.0 );

	// Missing lineItems.
	$r3 = exec_write( 'create_order', array( 'status' => 'completed' ) );
	expect_eq( 'missing lineItems => failed', $r3['status'], 'failed' );

	// Unknown product id.
	$r4 = exec_write( 'create_order', array( 'lineItems' => array( array( 'productId' => 999999, 'quantity' => 1 ) ) ) );
	expect_eq( 'unknown product => failed', $r4['status'], 'failed' );

	// P1-2: a negative priceOverride is rejected at arg-validation time (no
	// order is created), so it can never invert a line total.
	$r5 = exec_write( 'create_order', array(
		'lineItems' => array(
			array( 'productId' => $p1, 'quantity' => 1, 'priceOverride' => -5 ),
		),
	) );
	expect_eq( 'negative priceOverride => failed', $r5['status'], 'failed' );
	expect( 'negative override message names priceOverride', false !== strpos( $r5['error']['message'], 'priceOverride' ) );

	// P2-3: overrides correlate to order lines by productId, NOT by line
	// position. Three products; override only the MIDDLE one and confirm that
	// the middle line is re-priced while the outer lines keep their catalog
	// totals (positional matching on a reordered order would mis-apply).
	$pa = seed_product( array( 'price' => '3.00', 'name' => 'Alpha' ) );
	$pb = seed_product( array( 'price' => '7.00', 'name' => 'Bravo' ) );
	$pc = seed_product( array( 'price' => '11.00', 'name' => 'Charlie' ) );
	$r6 = exec_write( 'create_order', array(
		'lineItems' => array(
			array( 'productId' => $pa, 'quantity' => 1 ),
			array( 'productId' => $pb, 'quantity' => 2, 'priceOverride' => 4 ),
			array( 'productId' => $pc, 'quantity' => 1 ),
		),
	) );
	expect_eq( 'productId-keyed override => done', $r6['status'], 'done' );
	$by_pid = array();
	foreach ( $r6['result']['order']['lineItems'] as $ln ) {
		$by_pid[ $ln['productId'] ] = (float) $ln['total'];
	}
	expect_eq( 'middle (pb) line overridden to 2*4', $by_pid[ $pb ], 8.0 );
	expect_eq( 'first (pa) line untouched at catalog', $by_pid[ $pa ], 3.0 );
	expect_eq( 'last (pc) line untouched at catalog', $by_pid[ $pc ], 11.0 );
	expect_eq( 'order total reflects single targeted override', $r6['result']['order']['total'], 3.0 + 8.0 + 11.0 );

	// P2-3: an ambiguous override (two input lines sharing the same productId
	// produce two order lines with that productId) is rejected — it is never
	// silently applied to just one of the colliding lines.
	$r7 = exec_write( 'create_order', array(
		'lineItems' => array(
			array( 'productId' => $p1, 'quantity' => 1, 'priceOverride' => 2 ),
			array( 'productId' => $p1, 'quantity' => 2 ),
		),
	) );
	expect_eq( 'ambiguous productId override => failed', $r7['status'], 'failed' );
	expect( 'ambiguous override message names ambiguous', false !== strpos( $r7['error']['message'], 'ambiguous' ) );
}

/**
 * delete_customer — happy path + ADMIN-REFUSAL + shop-manager refusal +
 * not-found. Customer orders are retained.
 */
function test_delete_customer() {
	echo "\n[delete_customer — happy, admin-refusal, not-found]\n";
	reset_state();

	$cust = seed_user( array( 'user_email' => 'cust@example.com', 'roles' => array( 'customer' ) ) );
	$admin = seed_user( array( 'user_email' => 'admin@example.com', 'roles' => array( 'administrator' ) ) );
	$mgr   = seed_user( array( 'user_email' => 'mgr@example.com', 'roles' => array( 'shop_manager' ) ) );

	// Happy path by id.
	$r = exec_write( 'delete_customer', array( 'customerId' => $cust ) );
	expect_eq( 'delete customer => done', $r['status'], 'done' );
	expect_eq( 'deleted true', $r['result']['deleted'], true );
	expect_eq( 'customerId echoed', $r['result']['customerId'], $cust );
	expect_eq( 'ordersRetained true', $r['result']['ordersRetained'], true );
	expect( 'user removed from store', ! isset( $GLOBALS['__felix_users'][ $cust ] ) );

	// Refuse admin (explicit error).
	$r2 = exec_write( 'delete_customer', array( 'customerId' => $admin ) );
	expect_eq( 'admin deletion refused => failed', $r2['status'], 'failed' );
	expect( 'refusal message mentions non-customer', false !== strpos( $r2['error']['message'], 'non-customer' ) );
	expect( 'admin still present (not deleted)', isset( $GLOBALS['__felix_users'][ $admin ] ) );

	// Refuse shop-manager by email lookup.
	$r3 = exec_write( 'delete_customer', array( 'email' => 'mgr@example.com' ) );
	expect_eq( 'shop_manager deletion refused => failed', $r3['status'], 'failed' );
	expect( 'shop_manager still present', isset( $GLOBALS['__felix_users'][ $mgr ] ) );

	// P1-1: a multi-role user holding BOTH customer AND administrator must be
	// refused. WooCommerce adds the customer role to admins who place orders,
	// so a mere membership check (in_array) would let them through. Customer
	// must be the ONLY role, and the refusal must name the actual roles.
	$multi = seed_user( array( 'user_email' => 'multi@example.com', 'roles' => array( 'administrator', 'customer' ) ) );
	$r7 = exec_write( 'delete_customer', array( 'customerId' => $multi ) );
	expect_eq( 'multi-role admin refused => failed', $r7['status'], 'failed' );
	expect( 'refusal names administrator role', false !== strpos( $r7['error']['message'], 'administrator' ) );
	expect( 'refusal names customer role', false !== strpos( $r7['error']['message'], 'customer' ) );
	expect( 'multi-role user still present (not deleted)', isset( $GLOBALS['__felix_users'][ $multi ] ) );

	// Resolve-by-email happy path.
	$cust2 = seed_user( array( 'user_email' => 'cust2@example.com', 'roles' => array( 'customer' ) ) );
	$r4 = exec_write( 'delete_customer', array( 'email' => 'cust2@example.com' ) );
	expect_eq( 'delete customer by email => done', $r4['status'], 'done' );

	// Not found.
	$r5 = exec_write( 'delete_customer', array( 'customerId' => 999999 ) );
	expect_eq( 'unknown customer => failed', $r5['status'], 'failed' );

	// Missing args.
	$r6 = exec_write( 'delete_customer', array() );
	expect_eq( 'missing customerId+email => failed', $r6['status'], 'failed' );
}

/**
 * A read basis (connector-read) is DENIED for the new write families but
 * allowed for the new read families — proven through the shared processor.
 */
function test_new_family_authorization_classification() {
	echo "\n[new family read/write authorization classification]\n";

	// refund.create (refund) — write family: connector-read denied.
	expect( 'refund denied for connector-read', ! Felix_Command_Handlers::authorize( 'refund', read_basis() )['ok'] );
	// create_order (order_create) — write family.
	expect( 'order_create denied for connector-read', ! Felix_Command_Handlers::authorize( 'order_create', read_basis() )['ok'] );
	// delete_customer (customer_write) — write family.
	expect( 'customer_write denied for connector-read', ! Felix_Command_Handlers::authorize( 'customer_write', read_basis() )['ok'] );
	// register_webhooks (webhook_management) — write family.
	expect( 'webhook_management denied for connector-read', ! Felix_Command_Handlers::authorize( 'webhook_management', read_basis() )['ok'] );

	// get_coupon / list_coupons (coupon_read) — read family: connector-read allowed.
	expect( 'coupon_read allowed for connector-read', Felix_Command_Handlers::authorize( 'coupon_read', read_basis() )['ok'] );
	// get_product (product_read) — read family.
	expect( 'product_read allowed for connector-read', Felix_Command_Handlers::authorize( 'product_read', read_basis() )['ok'] );
	// sync_coupons (sync) — read family.
	expect( 'sync allowed for connector-read', Felix_Command_Handlers::authorize( 'sync', read_basis() )['ok'] );
}

// The runner class is only loaded via felix-connector.php (not in the test
// bootstrap), but capability_list is referenced statically. Load it safely.
if ( ! class_exists( 'Felix_Runner' ) ) {
	require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-runner.php';
}

/**
 * Pairing-code input normalization + validation.
 *
 * The backend now mints 8-char codes (grouped XXXX-XXXX) from an unambiguous
 * alphabet. The plugin must collapse whatever the operator types — hyphen,
 * spaces, lowercase, stray punctuation, even ambiguous glyphs — back to the
 * canonical 8-char string the backend compares against, and reject anything
 * that does not normalize to exactly FELIX_PAIRING_CODE_LENGTH characters.
 */
function test_pairing_code_normalization() {
	echo "\n[pairing-code normalization + validation]\n";

	// Canonical grouped display → ungrouped canonical.
	expect_eq( 'strips the cosmetic hyphen', Felix_Settings::normalize_pairing_code( 'ABCD-EFGH' ), 'ABCDEFGH' );
	// Lowercase is uppercased.
	expect_eq( 'uppercases lowercase input', Felix_Settings::normalize_pairing_code( 'abcd-efgh' ), 'ABCDEFGH' );
	// Spaces and stray punctuation collapse too.
	expect_eq( 'strips spaces + punctuation', Felix_Settings::normalize_pairing_code( 'AB CD-EF GH!' ), 'ABCDEFGH' );
	// Already-canonical input is idempotent.
	expect_eq( 'idempotent on canonical input', Felix_Settings::normalize_pairing_code( 'K7QM9HR2' ), 'K7QM9HR2' );

	// Validity gate: a correctly typed code normalizes to exactly 8 chars.
	expect( 'grouped 8-char code is valid', strlen( Felix_Settings::normalize_pairing_code( 'K7QM-9HR2' ) ) === FELIX_PAIRING_CODE_LENGTH );

	// Ambiguous glyphs (0/O/1/I/L never appear in a minted code) are dropped,
	// so a mistyped code under-shoots the length and is rejected — never mapped
	// to a plausible-but-wrong code.
	expect( 'ambiguous 0 rejected (length drops)', strlen( Felix_Settings::normalize_pairing_code( 'ABCD0EFG' ) ) < FELIX_PAIRING_CODE_LENGTH );
	expect( 'legacy 6-char code rejected', strlen( Felix_Settings::normalize_pairing_code( 'ABC123' ) ) < FELIX_PAIRING_CODE_LENGTH );
	expect( 'empty input rejected', '' === Felix_Settings::normalize_pairing_code( '' ) );

	// Entropy sanity: the normalized alphabet never contains 0, 1, O, or I.
	$sample = Felix_Settings::normalize_pairing_code( 'K7QM9HR2' );
	expect( 'canonical alphabet excludes 0', false === strpos( $sample, '0' ) );
	expect( 'canonical alphabet excludes 1', false === strpos( $sample, '1' ) );
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
test_canonical_json_contract();
test_canonical_json_contract_v2_signed_fixtures();
test_signature_with_url_and_unicode();
test_stale_reservation_reconciled();
test_fresh_reservation_not_reconciled();
test_fresh_conflict_then_later_terminal_retrieval();
test_renew_handler_registered();
test_authorization_basis_object_form();
test_pairing_code_normalization();

// v0.4.1 command-surface parity.
test_command_surface_parity();
test_refund_create();
test_get_coupon();
test_list_coupons();
test_get_product();
test_sync_coupons();
test_register_webhooks();
test_verify_webhooks();
test_remove_webhooks();
test_create_order();
test_delete_customer();
test_new_family_authorization_classification();

echo str_repeat( '=', 60 ) . "\n";
$total = $GLOBALS['__pass'] + $GLOBALS['__fail'];
echo sprintf( "%d tests, %d passed, %d failed\n", $total, $GLOBALS['__pass'], $GLOBALS['__fail'] );

if ( $GLOBALS['__fail'] > 0 ) {
	exit( 1 );
}
exit( 0 );

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
test_canonical_json_contract();
test_canonical_json_contract_v2_signed_fixtures();
test_signature_with_url_and_unicode();
test_stale_reservation_reconciled();
test_fresh_reservation_not_reconciled();
test_fresh_conflict_then_later_terminal_retrieval();
test_renew_handler_registered();
test_authorization_basis_object_form();

echo str_repeat( '=', 60 ) . "\n";
$total = $GLOBALS['__pass'] + $GLOBALS['__fail'];
echo sprintf( "%d tests, %d passed, %d failed\n", $total, $GLOBALS['__pass'], $GLOBALS['__fail'] );

if ( $GLOBALS['__fail'] > 0 ) {
	exit( 1 );
}
exit( 0 );

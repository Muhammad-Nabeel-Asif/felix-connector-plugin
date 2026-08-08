<?php
/**
 * Felix Command Processor — single shared command pipeline.
 *
 * Both transports (the outbound long-poll runner and the inbound direct
 * REST endpoint) call this class to turn a signed command envelope into a
 * terminal result. The pipeline:
 *
 *   1. Verify the Ed25519 signature over the canonical body.
 *   2. Validate the envelope (keyId known, storeId/generation match, TTL).
 *   3. Validate the authorization basis against the command family.
 *   4. ATOMICALLY reserve the command ID via a single PRIMARY KEY INSERT.
 *      This is the exactly-once gate — concurrent poll vs. direct calls for
 *      the same command ID cannot both win.
 *   5. If reservation is a duplicate of a terminal row, return the stored
 *      terminal result WITHOUT re-executing (idempotent redelivery).
 *   6. If we won the reservation, check the nonce, execute the handler,
 *      and mark the row terminal.
 *
 * The processor itself NEVER posts to /connector/result. Each transport
 * decides what to do with the returned terminal envelope:
 *   - poll path: POSTs the result back to Felix (kept for back-compat).
 *   - direct path: returns it as the HTTP response body.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_Command_Processor {

	/** @var Felix_Command_Handlers */
	private $handlers;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->handlers = new Felix_Command_Handlers();
	}

	/**
	 * Process a signed command envelope end-to-end.
	 *
	 * @param string $raw_body Raw request/response body bytes (used for signature).
	 * @param array  $command  Decoded command envelope.
	 * @return array Terminal result envelope:
	 *   {
	 *     commandId:      string,
	 *     status:         'done'|'failed'|'unconfirmed'|'rejected',
	 *     result:         mixed|null,
	 *     error:          array|null,
	 *     processorTxnIds:array,
	 *     executedAt:     string ISO-8601,
	 *     alreadyExecuted:bool     // true when returned from ledger (redelivery)
	 *   }
	 *
	 * 'unconfirmed' is returned only when the handler ran but the terminal
	 * result could not be durably persisted.
	 */
	public function process( $raw_body, $command ) {
		$command_id = isset( $command['commandId'] ) ? (string) $command['commandId'] : '';

		// -------------------------------------------------------------------------
		// 1. Signature verification (deny unsigned / bad signature).
		// -------------------------------------------------------------------------
		$key_manifest = get_option( FELIX_OPT_KEY_MANIFEST, array() );
		$key_id       = isset( $command['keyId'] ) ? (string) $command['keyId'] : '';
		$public_key   = Felix_Crypto::lookup_key( $key_manifest, $key_id );

		if ( ! $public_key ) {
			return $this->reject( $command_id, 'unknown_key', 'Signing key not found', null );
		}

		$signature = isset( $command['signature'] ) ? (string) $command['signature'] : '';
		if ( '' === $signature ) {
			return $this->reject( $command_id, 'signature_missing', 'Command signature is missing', null );
		}

		$sig_valid = Felix_Crypto::verify_command_signature( $raw_body, $signature, $public_key );
		if ( ! $sig_valid ) {
			return $this->reject( $command_id, 'signature_invalid', 'Signature verification failed', null );
		}

		// -------------------------------------------------------------------------
		// 2. Envelope validation.
		// -------------------------------------------------------------------------
		$envelope_error = $this->validate_envelope( $command );
		if ( null !== $envelope_error ) {
			return $this->reject( $command_id, $envelope_error['code'], $envelope_error['message'], null );
		}

		// -------------------------------------------------------------------------
		// 3. Authorization-basis precheck (deny before reservation + handler).
		//    The handler runs an identical check internally; doing it here too
		//    means a bad-basis command never even reserves a ledger row.
		// -------------------------------------------------------------------------
		$type   = isset( $command['type'] ) ? (string) $command['type'] : '';
		$family = Felix_Command_Handlers::family_for( $type );
		if ( null === $family ) {
			return $this->reject( $command_id, 'unknown_type', sprintf( 'Unknown command type: %s', $type ), null );
		}

		$auth_basis = isset( $command['authorizationBasis'] ) ? $command['authorizationBasis'] : null;
		$auth       = Felix_Command_Handlers::authorize( $family, $auth_basis );
		if ( ! $auth['ok'] ) {
			return $this->reject( $command_id, $auth['code'], $auth['message'], $auth_basis );
		}

		// -------------------------------------------------------------------------
		// 4. Atomic reservation — the exactly-once gate.
		// -------------------------------------------------------------------------
		$reservation = Felix_Command_Ledger::reserve( $command_id, $type, $auth_basis );

		if ( 'error' === $reservation['status'] ) {
			return $this->reject( $command_id, 'ledger_error', $reservation['error'] ?: 'Ledger reservation failed', $auth_basis );
		}

		if ( 'duplicate' === $reservation['status'] ) {
			$row = $reservation['record'];
			if ( $row && in_array( $row->status, Felix_Command_Ledger::terminal_statuses(), true ) ) {
				// Idempotent redelivery — return the stored terminal result.
				$terminal = Felix_Command_Ledger::row_to_terminal_result( $row );
				$terminal['alreadyExecuted'] = true;
				return $terminal;
			}

			// A prior process reserved this ID but never reached a terminal
			// state (crashed mid-flight). Treat as a soft conflict and reject
			// without executing — the backend will retry on the next tick.
			return $this->reject(
				$command_id,
				'reservation_conflict',
				'Command ID is currently reserved by another execution',
				$auth_basis
			);
		}

		// -------------------------------------------------------------------------
		// 5. We won the reservation. Nonce check, execute, mark terminal.
		//
		//    NOTE on ordering: the nonce is checked AFTER the reservation, so a
		//    replayed nonce for a *new* command ID still consumes a reserved
		//    row. That is intentional — it prevents a replayed nonce from
		//    silently slipping past the dedup gate on a later retry.
		// -------------------------------------------------------------------------
		$nonce = isset( $command['nonce'] ) ? (string) $command['nonce'] : '';
		if ( '' !== $nonce && ! Felix_Command_Ledger::check_nonce( $nonce ) ) {
			return $this->finalize(
				$command_id,
				array(
					'status' => 'rejected',
					'error'  => array( 'code' => 'nonce_seen', 'message' => 'Nonce already consumed' ),
				),
				$auth_basis
			);
		}

		$result = $this->handlers->execute(
			$command_id,
			$type,
			isset( $command['args'] ) && is_array( $command['args'] ) ? $command['args'] : array(),
			$auth_basis
		);

		return $this->finalize( $command_id, $result, $auth_basis );
	}

	/**
	 * Persist the handler's terminal result against the reserved row and
	 * return the terminal envelope. If persistence fails for any reason (DB
	 * error, or the reserved→terminal guard rejected the transition because we
	 * no longer hold the row), the side-effecting handler already ran but the
	 * ledger does not reflect it — so we MUST surface 'unconfirmed' to the
	 * caller rather than a possibly-false 'done'.
	 *
	 * @param string $command_id
	 * @param array  $result Handler result envelope {status, result?, error?, processorTxnIds?}.
	 * @param array  $auth_basis Optional audit trail.
	 * @return array Terminal envelope.
	 */
	private function finalize( $command_id, $result, $auth_basis = null ) {
		$status           = isset( $result['status'] ) ? $result['status'] : 'failed';
		$result_payload   = isset( $result['result'] ) ? $result['result'] : null;
		$error            = isset( $result['error'] ) ? $result['error'] : null;
		$processor_txn_ids = isset( $result['processorTxnIds'] ) ? $result['processorTxnIds'] : array();

		$persisted = Felix_Command_Ledger::mark_terminal(
			$command_id,
			$status,
			$result_payload,
			$error,
			$processor_txn_ids
		);

		if ( ! $persisted ) {
			// The handler executed (or a rejection was decided) but we could
			// not durably record the outcome. The caller must NOT trust a
			// 'done'/'rejected' here — surface unconfirmed so the backend can
			// reconcile/retry instead of double-counting.
			return array(
				'commandId'       => $command_id,
				'status'          => 'unconfirmed',
				'result'          => null,
				'error'           => array(
					'code'    => 'persistence_failed',
					'message' => 'Command executed but the terminal result could not be persisted',
				),
				'processorTxnIds' => array(),
				'executedAt'      => current_time( 'c' ),
				'alreadyExecuted' => false,
			);
		}

		return array(
			'commandId'       => $command_id,
			'status'          => $status,
			'result'          => $result_payload,
			'error'           => $error,
			'processorTxnIds' => $processor_txn_ids,
			'executedAt'      => current_time( 'c' ),
			'alreadyExecuted' => false,
		);
	}

	/**
	 * Validate the command envelope (store / generation / TTL).
	 *
	 * @param array $command
	 * @return array|null Error array or null if valid.
	 */
	private function validate_envelope( $command ) {
		$store_id = isset( $command['storeId'] ) ? (string) $command['storeId'] : '';
		if ( $store_id !== (string) Felix_Pairing::get_store_id() ) {
			return array(
				'code'    => 'store_mismatch',
				'message' => 'Store ID mismatch',
			);
		}

		$generation = isset( $command['generation'] ) ? (int) $command['generation'] : 0;
		if ( $generation !== (int) Felix_Pairing::get_generation() ) {
			return array(
				'code'    => 'generation_mismatch',
				'message' => 'Generation mismatch',
			);
		}

		$issued_at_raw = isset( $command['issuedAt'] ) ? (string) $command['issuedAt'] : '';
		$issued_at     = strtotime( $issued_at_raw );
		$ttl           = isset( $command['ttlSeconds'] ) ? (int) $command['ttlSeconds'] : 120;
		if ( false === $issued_at || ( time() - $issued_at ) > $ttl ) {
			return array(
				'code'    => 'ttl_expired',
				'message' => 'Command TTL expired or issuedAt missing',
			);
		}

		return null;
	}

	/**
	 * Build a rejection envelope. Rejections are NOT recorded against the
	 * command ID before reservation (no row exists yet), so we just return
	 * the terminal shape. The transport decides whether to persist/post.
	 *
	 * @param string $command_id
	 * @param string $code
	 * @param string $message
	 * @param array  $auth_basis Optional, for audit only.
	 * @return array
	 */
	private function reject( $command_id, $code, $message, $auth_basis = null ) {
		return array(
			'commandId'       => $command_id,
			'status'          => 'rejected',
			'result'          => null,
			'error'           => array(
				'code'    => $code,
				'message' => $message,
			),
			'processorTxnIds' => array(),
			'executedAt'      => current_time( 'c' ),
			'alreadyExecuted' => false,
		);
	}
}

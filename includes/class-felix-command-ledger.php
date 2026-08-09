<?php
/**
 * Felix Command Ledger — dedup table for at-least-once delivery.
 *
 * Records every executed command ID so redelivery returns the stored result
 * without re-executing. Pruned after 30 days.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_Command_Ledger {

	private static $table_name = 'felix_connector_commands';

	/**
	 * Reservation lease (seconds). A `reserved` row older than this is
	 * considered CRASHED (the process that reserved it never reached a terminal
	 * state). On the next redelivery, a stale reservation is reconciled to an
	 * honest `unconfirmed` outcome so the same command id stops blocking
	 * redelivery (the backend requeues/retries, and the next redelivery returns
	 * the stored unconfirmed terminal). Sized relative to the backend's
	 * ~120s command TTL: a reservation older than 120s has almost certainly
	 * been abandoned (plugin executions are seconds), and the backend will have
	 * begun requeuing redeliveries by then.
	 */
	const RESERVATION_LEASE_SECONDS = 120;

	/**
	 * Create the ledger table on activation.
	 */
	public static function create_table() {
		global $wpdb;
		$table_name = $wpdb->prefix . self::$table_name;

		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			id varchar(64) NOT NULL,
			type varchar(100) NOT NULL,
			status varchar(20) NOT NULL,
			result longtext,
			error longtext,
			processor_txn_ids text,
			authorization_basis longtext,
			executed_at datetime NOT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Check if a command has already been executed.
	 *
	 * @param string $command_id
	 * @return object|null The stored row or null.
	 */
	public static function get( $command_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::$table_name;

		// phpcs:ignore WordPress.DB.PreparedSQL
		$row = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table_name} WHERE id = %s", $command_id )
		);

		return $row;
	}

	/**
	 * Record a command execution (legacy single-shot insert).
	 *
	 * Kept for back-compat. New code uses reserve() + mark_terminal() so the
	 * reservation is atomic and shared by both poll and direct transports.
	 *
	 * @param string $command_id
	 * @param string $type
	 * @param string $status       done|failed|unconfirmed|rejected.
	 * @param mixed  $result       JSON-serializable result payload.
	 * @param array  $error        Optional error {code, message}.
	 * @param array  $processor_txn_ids Optional processor transaction IDs.
	 * @param array  $authorization_basis Optional audit trail.
	 * @return bool True on success.
	 */
	public static function record( $command_id, $type, $status, $result = null, $error = null, $processor_txn_ids = array(), $authorization_basis = null ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::$table_name;

		$inserted = $wpdb->insert(
			$table_name,
			array(
				'id'                 => $command_id,
				'type'               => $type,
				'status'             => $status,
				'result'             => $result ? wp_json_encode( $result ) : null,
				'error'              => $error ? wp_json_encode( $error ) : null,
				'processor_txn_ids'  => ! empty( $processor_txn_ids ) ? wp_json_encode( $processor_txn_ids ) : null,
				'authorization_basis' => $authorization_basis ? wp_json_encode( $authorization_basis ) : null,
				'executed_at'        => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		// If insert failed due to duplicate key, the command was already recorded.
		return false !== $inserted;
	}

	/**
	 * Atomically reserve a command ID BEFORE any handler runs.
	 *
	 * This is the exactly-once gate shared by both the outbound poll runner
	 * and the inbound direct REST endpoint. The reservation is a single
	 * PRIMARY KEY INSERT — MySQL/MariaDB enforces atomicity, so two
	 * concurrent reservations for the same command ID cannot both succeed.
	 *
	 * Possible outcomes:
	 *   - 'reserved' : we won the race; caller MUST execute + mark_terminal().
	 *   - 'duplicate': the command ID is already in the ledger; caller MUST
	 *                  return the stored terminal result without re-executing.
	 *                  record may be a non-terminal 'reserved' row if a prior
	 *                  process crashed mid-flight — caller treats that as a
	 *                  soft conflict and rejects.
	 *   - 'error'    : database failure; caller rejects.
	 *
	 * @param string $command_id
	 * @param string $type
	 * @param array  $authorization_basis Optional audit trail.
	 * @return array {status: string, record: object|null, error: string|null}
	 */
	public static function reserve( $command_id, $type, $authorization_basis = null ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::$table_name;

		$auth_json = $authorization_basis ? wp_json_encode( $authorization_basis ) : null;

		$inserted = $wpdb->insert(
			$table_name,
			array(
				'id'                  => $command_id,
				'type'                => $type,
				'status'              => 'reserved',
				'authorization_basis' => $auth_json,
				'executed_at'         => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s' )
		);

		if ( false !== $inserted ) {
			return array(
				'status' => 'reserved',
				'record' => null,
				'error'  => null,
			);
		}

		// Inspect the driver error to distinguish duplicate key from real failure.
		$last_error = isset( $wpdb->last_error ) ? (string) $wpdb->last_error : '';
		if ( $last_error !== '' && stripos( $last_error, 'Duplicate' ) !== false ) {
			$row = self::get( $command_id );

			// STALE-RESERVATION RECONCILIATION (#3): a `reserved` row whose lease
			// has elapsed was abandoned by a crashed process. Reconcile it to an
			// honest `unconfirmed` outcome so the next redelivery returns a
			// truthful terminal instead of looping reservation_conflict until
			// the 30-day prune (the backend TTL is ~120s; a reservation older
			// than the lease has almost certainly been abandoned). A FRESH
			// reservation stays a soft conflict (returned as-is; the processor
			// rejects with reservation_conflict so the backend retries).
			if ( $row && 'reserved' === $row->status && self::is_reservation_stale( $row ) ) {
				self::reconcile_stale_reservation( $row );
				$row = self::get( $command_id );
			}

			return array(
				'status' => 'duplicate',
				'record' => $row,
				'error'  => null,
			);
		}

		return array(
			'status' => 'error',
			'record' => null,
			'error'  => $last_error ?: 'unknown ledger insert failure',
		);
	}

	/**
	 * True when a `reserved` ledger row is older than the reservation lease
	 * (the reserving process crashed before reaching a terminal state).
	 *
	 * @param object $row
	 * @return bool
	 */
	public static function is_reservation_stale( $row ) {
		if ( ! isset( $row->created_at ) ) {
			return false;
		}
		$created = strtotime( $row->created_at );
		if ( false === $created ) {
			return false;
		}
		return ( time() - $created ) > self::RESERVATION_LEASE_SECONDS;
	}

	/**
	 * Reconcile a stale `reserved` row to an honest `unconfirmed` terminal.
	 * The side-effecting handler already ran (or not) but the ledger never
	 * recorded the outcome — surfacing `unconfirmed` lets the backend
	 * reconcile/retry instead of trusting an unknown state. Pinned to
	 * status='reserved' so a row that already reached terminal is untouched.
	 *
	 * @param object $row
	 * @return void
	 */
	public static function reconcile_stale_reservation( $row ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::$table_name;

		$wpdb->update(
			$table_name,
			array(
				'status'      => 'unconfirmed',
				'error'       => wp_json_encode(
					array(
						'code'    => 'reservation_abandoned',
						'message' => 'Reservation lease elapsed without a terminal result (process crash); reconciled to unconfirmed',
					)
				),
				'executed_at' => current_time( 'mysql' ),
			),
			array(
				'id'     => $row->id,
				'status' => 'reserved',
			),
			array( '%s', '%s', '%s' ),
			array( '%s', '%s' )
		);
	}

	/**
	 * Update a previously-reserved row to its terminal status. Called only by
	 * the holder that won the reservation.
	 *
	 * The WHERE clause pins `status = 'reserved'`, so a terminal transition is
	 * ONLY possible from the reserved state. This makes the contract explicit
	 * and acts as defense-in-depth: a stale mark_terminal() issued by a process
	 * that lost the reservation race (or a row that already reached terminal)
	 * affects zero rows and reports failure. We never overwrite a terminal row
	 * and never steal a row we do not hold.
	 *
	 * @param string $command_id
	 * @param string $status       done|failed|unconfirmed|rejected.
	 * @param mixed  $result
	 * @param array  $error
	 * @param array  $processor_txn_ids
	 * @return bool True only when the reserved→terminal transition happened.
	 */
	public static function mark_terminal( $command_id, $status, $result = null, $error = null, $processor_txn_ids = array() ) {
		global $wpdb;
		$table_name = $wpdb->prefix . self::$table_name;

		$updated = $wpdb->update(
			$table_name,
			array(
				'status'            => $status,
				'result'            => $result ? wp_json_encode( $result ) : null,
				'error'             => $error ? wp_json_encode( $error ) : null,
				'processor_txn_ids' => ! empty( $processor_txn_ids ) ? wp_json_encode( $processor_txn_ids ) : null,
				'executed_at'       => current_time( 'mysql' ),
			),
			array(
				'id'     => $command_id,
				'status' => 'reserved',
			),
			array( '%s', '%s', '%s', '%s', '%s' ),
			array( '%s', '%s' )
		);

		// $wpdb->update() returns int|false: the number of rows affected, or
		// false on error. The transition succeeded only when exactly the one
		// reserved row was updated.
		return ( false !== $updated && $updated > 0 );
	}

	/**
	 * Convert a stored ledger row into the terminal result envelope that both
	 * transports return to the caller. Never re-executes.
	 *
	 * @param object $row
	 * @return array
	 */
	public static function row_to_terminal_result( $row ) {
		// Defensive against sparse rows (e.g. a freshly-reconciled unconfirmed
		// row that has no result/processor_txn_ids yet).
		$result_raw          = isset( $row->result ) ? $row->result : null;
		$error_raw           = isset( $row->error ) ? $row->error : null;
		$processor_txn_raw   = isset( $row->processor_txn_ids ) ? $row->processor_txn_ids : null;
		return array(
			'commandId'      => isset( $row->id ) ? $row->id : null,
			'status'         => isset( $row->status ) ? $row->status : 'unconfirmed',
			'result'         => $result_raw ? json_decode( $result_raw, true ) : null,
			'error'          => $error_raw ? json_decode( $error_raw, true ) : null,
			'processorTxnIds' => $processor_txn_raw ? json_decode( $processor_txn_raw, true ) : array(),
			'executedAt'     => isset( $row->executed_at ) ? $row->executed_at : current_time( 'mysql' ),
		);
	}

	/**
	 * Terminal (handler-executed) statuses. 'reserved' is intentionally
	 * excluded — it means a prior process crashed mid-flight.
	 *
	 * @return string[]
	 */
	public static function terminal_statuses() {
		return array( 'done', 'failed', 'unconfirmed', 'rejected' );
	}

	/**
	 * Prune entries older than 30 days.
	 */
	public static function prune() {
		global $wpdb;
		$table_name = $wpdb->prefix . self::$table_name;

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table_name} WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)"
			)
		);
	}

	/**
	 * Check and record a nonce for replay protection.
	 *
	 * @param string $nonce The nonce value from the command envelope.
	 * @return bool True if nonce is fresh (not seen before).
	 */
	public static function check_nonce( $nonce ) {
		$seen = get_option( FELIX_OPT_SEEN_NONCES, array() );

		// Prune old nonces (older than 24h).
		$cutoff      = time() - 86400;
		$pruned_seen = array_filter(
			$seen,
			function ( $ts ) use ( $cutoff ) {
				return $ts > $cutoff;
			}
		);

		if ( isset( $pruned_seen[ $nonce ] ) ) {
			// Already seen — replay attempt or legitimate redelivery.
			// Update the pruned option and return false.
			update_option( FELIX_OPT_SEEN_NONCES, $pruned_seen, false );
			return false;
		}

		// Fresh nonce — record it.
		$pruned_seen[ $nonce ] = time();
		update_option( FELIX_OPT_SEEN_NONCES, $pruned_seen, false );

		return true;
	}
}

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
	 * Record a command execution.
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

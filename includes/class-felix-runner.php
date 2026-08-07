<?php
/**
 * Felix Runner — the core poll/execute loop for the connector.
 *
 * Supports two invocation contexts:
 *  1. FELIX_RUNNER_MODE (external server cron via runner.php) — long window loop.
 *  2. WP-Cron hook (inside WordPress) — short bounded cycle.
 *
 * Both paths share the same flock + DB-lease mutex so they cannot
 * double-execute commands.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_Runner {

	/** @var int Default runner window in seconds (CLI mode). */
	private $window_seconds = 1790;

	/** @var int Default long-poll hold time. */
	private $poll_hold_seconds = 25;

	/** @var int Minimum re-poll delay after receiving a command. */
	private $min_repoll_delay_ms = 100;

	/** @var int Degraded-mode poll interval. */
	private $degraded_poll_interval_ms = 4000;

	/** @var int Lease duration in seconds. */
	private $lease_seconds = 60;

	/** @var int Max backoff for error retries. */
	private $max_backoff_seconds = 30;

	/** @var string Holder ID for this runner instance. */
	private $holder_id;

	/** @var bool Whether we're in degraded mode. */
	private $degraded = false;

	/** @var int Consecutive error count. */
	private $error_count = 0;

	/** @var Felix_Command_Handlers */
	private $handlers;

	/** @var string Lock file path. */
	private $lock_file;

	/** @var resource|null Lock file handle. */
	private $lock_handle;

	/** @var string Log file path. */
	private $log_file;

	/** @var bool Whether we're running as CLI (affects logging). */
	private $is_cli;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->holder_id = wp_generate_uuid4();
		$this->handlers  = new Felix_Command_Handlers();
		$this->is_cli    = ( defined( 'FELIX_RUNNER_MODE' ) && FELIX_RUNNER_MODE ) || ( php_sapi_name() === 'cli' );

		// Apply host profile overrides.
		$profile = get_option( FELIX_OPT_HOST_PROFILE, array() );
		if ( isset( $profile['windowSeconds'] ) ) {
			$this->window_seconds = intval( $profile['windowSeconds'] );
		}
		if ( isset( $profile['pollHoldSeconds'] ) ) {
			$this->poll_hold_seconds = intval( $profile['pollHoldSeconds'] );
		}
		if ( isset( $profile['minRepollDelayMs'] ) ) {
			$this->min_repoll_delay_ms = intval( $profile['minRepollDelayMs'] );
		}
		if ( isset( $profile['degradedPollIntervalMs'] ) ) {
			$this->degraded_poll_interval_ms = intval( $profile['degradedPollIntervalMs'] );
		}

		$this->lock_file = sys_get_temp_dir() . '/felix-runner.lock';
		$this->log_file  = WP_CONTENT_DIR . '/uploads/felix-connector.log';
	}

	/**
	 * Main run loop — CLI / external cron mode.
	 * Runs the full window_seconds poll loop.
	 */
	public function run() {
		if ( ! Felix_Pairing::is_paired() ) {
			$this->log( 'Store not paired, exiting.' );
			$this->record_run( 'skipped' );
			return;
		}

		// Acquire flock (cheap first gate).
		$this->lock_handle = @fopen( $this->lock_file, 'c' );
		if ( ! $this->lock_handle ) {
			$this->log( 'Could not open lock file.' );
			$this->record_run( 'error' );
			return;
		}

		if ( ! flock( $this->lock_handle, LOCK_EX | LOCK_NB ) ) {
			// Another runner has the lock. Wait up to 120s to take over.
			$this->log( 'Waiting for lock (up to 120s)...' );
			$waited = 0;
			while ( $waited < 120 ) {
				if ( flock( $this->lock_handle, LOCK_EX | LOCK_NB ) ) {
					break;
				}
				if ( $this->acquire_lease() ) {
					break; // Lease expired — take over.
				}
				usleep( 500000 );
				$waited += 0.5;
			}
			if ( $waited >= 120 ) {
				$this->log( 'Could not acquire lock after 120s, exiting.' );
				fclose( $this->lock_handle );
				$this->record_run( 'skipped' );
				return;
			}
		}

		// Acquire DB lease.
		if ( ! $this->acquire_lease() ) {
			$this->log( 'Valid lease held by another runner, exiting.' );
			flock( $this->lock_handle, LOCK_UN );
			fclose( $this->lock_handle );
			$this->record_run( 'skipped' );
			return;
		}

		$this->log( sprintf( 'Started (holder=%s, window=%ds)', $this->holder_id, $this->window_seconds ) );

		$start_time = time();
		$deadline   = $start_time + $this->window_seconds;

		while ( time() < $deadline ) {
			$this->renew_lease();
			update_option( FELIX_OPT_RUNNER_HEARTBEAT, time() );

			$result = $this->poll_once();

			if ( $result === false ) {
				$this->error_count++;
				$backoff = min( $this->max_backoff_seconds, pow( 2, $this->error_count ) + mt_rand( 0, 1000 ) / 1000 );
				$this->log( sprintf( 'Poll error #%d, backing off %.1fs', $this->error_count, $backoff ) );
				usleep( (int) ( $backoff * 1000000 ) );
				continue;
			}

			$this->error_count = 0;

			if ( $this->degraded ) {
				usleep( $this->degraded_poll_interval_ms * 1000 );
			} else {
				usleep( $this->min_repoll_delay_ms * 1000 );
			}
		}

		$this->release_lease();
		$this->log( sprintf( 'Window complete, exiting (ran %ds)', time() - $start_time ) );

		flock( $this->lock_handle, LOCK_UN );
		fclose( $this->lock_handle );

		$this->record_run( 'success' );
	}

	/**
	 * WP-Cron entry point — short bounded cycle.
	 *
	 * Does a best-effort acquisition of flock + DB lease, then runs
	 * a small number of poll cycles within a time budget (~60s).
	 * If locks cannot be acquired, exits silently (external cron has it).
	 */
	public function run_wp_cron() {
		if ( ! Felix_Pairing::is_paired() ) {
			$this->record_run( 'skipped' );
			return;
		}

		// Time budget for WP-Cron — keep it short to avoid PHP timeouts.
		$budget_seconds = 50;
		$max_polls      = 3;
		$start_time     = time();
		$deadline       = $start_time + $budget_seconds;

		// Attempt flock acquisition (non-blocking — don't wait).
		$this->lock_handle = @fopen( $this->lock_file, 'c' );
		if ( ! $this->lock_handle ) {
			$this->record_run( 'error' );
			return;
		}

		if ( ! flock( $this->lock_handle, LOCK_EX | LOCK_NB ) ) {
			// External cron (or another WP-Cron process) has the lock.
			$this->record_run( 'skipped' );
			fclose( $this->lock_handle );
			$this->lock_handle = null;
			return;
		}

		// Attempt DB lease.
		if ( ! $this->acquire_lease() ) {
			$this->record_run( 'skipped' );
			flock( $this->lock_handle, LOCK_UN );
			fclose( $this->lock_handle );
			$this->lock_handle = null;
			return;
		}

		$this->log( sprintf( 'WP-Cron cycle started (holder=%s, budget=%ds)', $this->holder_id, $budget_seconds ) );

		$polls = 0;
		$had_error = false;

		while ( time() < $deadline && $polls < $max_polls ) {
			$this->renew_lease();
			update_option( FELIX_OPT_RUNNER_HEARTBEAT, time() );

			$result = $this->poll_once();

			if ( $result === false ) {
				$this->error_count++;
				$had_error = true;

				// In WP-Cron, don't do long backoffs — just break after one error.
				$this->log( sprintf( 'WP-Cron poll error #%d, ending cycle', $this->error_count ) );
				break;
			}

			$this->error_count = 0;
			$polls++;

			$remaining = max( 0, ( $deadline - time() ) * 1000000 );
			if ( $this->degraded ) {
				usleep( min( $this->degraded_poll_interval_ms * 1000, $remaining ) );
			} else {
				usleep( min( $this->min_repoll_delay_ms * 1000, $remaining ) );
			}
		}

		$this->release_lease();
		$this->log( sprintf( 'WP-Cron cycle complete (%d polls, %ds)', $polls, time() - $start_time ) );

		flock( $this->lock_handle, LOCK_UN );
		fclose( $this->lock_handle );
		$this->lock_handle = null;

		$this->record_run( $had_error ? 'error' : 'success' );
	}

	/**
	 * Record run outcome for UI freshness tracking.
	 *
	 * @param string $status success|error|skipped
	 */
	private function record_run( $status ) {
		update_option( 'felix_last_run_at', time() );
		update_option( 'felix_last_run_status', $status );

		// Update local liveness state so the settings page reflects reality.
		if ( 'success' === $status ) {
			update_option( FELIX_OPT_LIVENESS_STATE, 'connected' );
		} elseif ( 'error' === $status && get_option( FELIX_OPT_LIVENESS_STATE ) === 'connected' ) {
			update_option( FELIX_OPT_LIVENESS_STATE, 'reconnecting' );
		}
	}

	/**
	 * Perform one long-poll cycle.
	 *
	 * @return bool True on success, false on error.
	 */
	private function poll_once() {
		$store_id   = Felix_Pairing::get_store_id();
		$generation = Felix_Pairing::get_generation();
		$endpoint   = get_option( FELIX_OPT_POLL_ENDPOINT, FELIX_API_BASE . '/connector/poll' );

		$timestamp = (string) ( time() * 1000 );
		$sign_data = "{$store_id}\n{$generation}\n{$timestamp}";

		$keypair = Felix_Pairing::get_keypair();
		$secret  = Felix_Crypto::get_secret_key( $keypair['encryptedSecret'] );
		if ( ! $secret ) {
			$this->log( 'Could not decrypt secret key.' );
			return false;
		}

		$signature = Felix_Crypto::sign( $sign_data, $secret );
		sodium_memzero( $secret );

		$url = add_query_arg(
			array(
				'storeId'    => $store_id,
				'generation' => $generation,
			),
			$endpoint
		);

		$response = wp_remote_get(
			$url,
			array(
				'timeout' => $this->poll_hold_seconds + 10,
				'headers' => array(
					'X-Felix-Plugin-Sig'   => $signature,
					'X-Felix-Plugin-KeyId' => $keypair['publicKey'],
					'X-Felix-Timestamp'    => $timestamp,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->log( 'WP Error: ' . $response->get_error_message() );
			$this->degraded = true;
			return false;
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$raw_body    = wp_remote_retrieve_body( $response );

		if ( 204 === $status_code ) {
			return true; // No command.
		}

		if ( 200 !== $status_code ) {
			if ( 401 === $status_code ) {
				$this->log( 'Auth rejected (401). Pairing may be invalid.' );
			} else {
				$this->log( "Unexpected status {$status_code}" );
			}
			$this->degraded = true;
			return false;
		}

		$command = json_decode( $raw_body, true );
		if ( ! $command || ! isset( $command['commandId'] ) ) {
			// Empty body or no command = "no command" response.
			if ( empty( $raw_body ) || $raw_body === '{"command":null}' ) {
				return true;
			}
			$this->log( 'Invalid command body.' );
			return false;
		}

		// Verify command signature.
		$key_manifest = get_option( FELIX_OPT_KEY_MANIFEST, array() );
		$public_key   = Felix_Crypto::lookup_key( $key_manifest, $command['keyId'] ?? '' );

		if ( ! $public_key ) {
			$this->log( 'Unknown keyId: ' . ( $command['keyId'] ?? '' ) );
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'unknown_key', 'message' => 'Signing key not found' ) );
			return false;
		}

		$sig_valid = Felix_Crypto::verify_command_signature(
			$raw_body,
			$command['signature'] ?? '',
			$public_key
		);

		if ( ! $sig_valid ) {
			$this->log( 'Invalid command signature.' );
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'signature_invalid', 'message' => 'Signature verification failed' ) );
			return false;
		}

		// Validate envelope.
		if ( ! $this->validate_command( $command ) ) {
			return false;
		}

		// Check dedup ledger.
		$existing = Felix_Command_Ledger::get( $command['commandId'] );
		if ( $existing && in_array( $existing->status, array( 'done', 'failed', 'unconfirmed', 'rejected' ), true ) ) {
			$this->post_result(
				$command['commandId'],
				$existing->status,
				$existing->result ? json_decode( $existing->result, true ) : null,
				$existing->error ? json_decode( $existing->error, true ) : null
			);
			return true;
		}

		// Nonce check.
		if ( ! Felix_Command_Ledger::check_nonce( $command['nonce'] ?? '' ) ) {
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'nonce_seen', 'message' => 'Nonce already consumed' ) );
			return false;
		}

		// Execute.
		$this->log( sprintf( 'Executing %s (%s)', $command['type'], $command['commandId'] ) );

		$result = $this->handlers->execute(
			$command['commandId'],
			$command['type'],
			$command['args'] ?? array(),
			$command['authorizationBasis'] ?? null
		);

		Felix_Command_Ledger::record(
			$command['commandId'],
			$command['type'],
			$result['status'],
			$result['result'] ?? null,
			$result['error'] ?? null,
			$result['processorTxnIds'] ?? array(),
			$command['authorizationBasis'] ?? null
		);

		$this->post_result(
			$command['commandId'],
			$result['status'],
			$result['result'] ?? null,
			$result['error'] ?? null,
			$result['processorTxnIds'] ?? array()
		);

		$this->log( sprintf( 'Command %s → %s', $command['commandId'], $result['status'] ) );
		return true;
	}

	/**
	 * Validate a command envelope.
	 *
	 * @param array $command
	 * @return bool
	 */
	private function validate_command( $command ) {
		if ( ( $command['storeId'] ?? '' ) !== Felix_Pairing::get_store_id() ) {
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'store_mismatch', 'message' => 'Store ID mismatch' ) );
			return false;
		}

		if ( (int) ( $command['generation'] ?? 0 ) !== Felix_Pairing::get_generation() ) {
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'generation_mismatch', 'message' => 'Generation mismatch' ) );
			return false;
		}

		$issued_at = strtotime( $command['issuedAt'] ?? '' );
		$ttl       = $command['ttlSeconds'] ?? 120;
		if ( $issued_at === false || ( time() - $issued_at ) > $ttl ) {
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'ttl_expired', 'message' => 'TTL expired' ) );
			return false;
		}

		return true;
	}

	/**
	 * Post a command result to Felix.
	 *
	 * @param string $command_id
	 * @param string $status
	 * @param mixed  $result
	 * @param array  $error
	 * @param array  $processor_txn_ids
	 */
	private function post_result( $command_id, $status, $result = null, $error = null, $processor_txn_ids = array() ) {
		$store_id   = Felix_Pairing::get_store_id();
		$generation = Felix_Pairing::get_generation();
		$endpoint   = get_option( FELIX_OPT_RESULT_ENDPOINT, FELIX_API_BASE . '/connector/result' );

		$body = array(
			'protocolVersion' => FELIX_PROTOCOL_VERSION,
			'commandId'       => $command_id,
			'storeId'         => $store_id,
			'generation'      => $generation,
			'status'          => $status,
			'result'          => $result,
			'error'           => $error,
			'executedAt'      => current_time( 'c' ),
			'processorTxnIds' => $processor_txn_ids,
		);

		$body_json = wp_json_encode( $body );

		$keypair = Felix_Pairing::get_keypair();
		$secret  = Felix_Crypto::get_secret_key( $keypair['encryptedSecret'] );

		$headers = array( 'Content-Type' => 'application/json' );

		if ( $secret ) {
			$sig                              = Felix_Crypto::sign( $body_json, $secret );
			$headers['X-Felix-Plugin-Sig']    = $sig;
			$headers['X-Felix-Plugin-KeyId']  = $keypair['publicKey'];
			$headers['X-Felix-Timestamp']     = (string) ( time() * 1000 );
			sodium_memzero( $secret );
		}

		wp_remote_post(
			$endpoint,
			array(
				'timeout' => 15,
				'headers' => $headers,
				'body'    => $body_json,
			)
		);
	}

	/**
	 * Acquire the DB lease.
	 *
	 * @return bool
	 */
	private function acquire_lease() {
		$lease = get_option( FELIX_OPT_RUNNER_LEASE, array() );
		$now   = time();

		if ( ! empty( $lease ) && isset( $lease['holder'] ) && isset( $lease['expiresAt'] ) ) {
			if ( $lease['holder'] !== $this->holder_id && $lease['expiresAt'] > $now ) {
				return false;
			}
		}

		update_option(
			FELIX_OPT_RUNNER_LEASE,
			array(
				'holder'    => $this->holder_id,
				'expiresAt' => $now + $this->lease_seconds,
			),
			false
		);
		return true;
	}

	/**
	 * Renew the DB lease.
	 */
	private function renew_lease() {
		$lease = get_option( FELIX_OPT_RUNNER_LEASE, array() );
		if ( isset( $lease['holder'] ) && $lease['holder'] === $this->holder_id ) {
			update_option(
				FELIX_OPT_RUNNER_LEASE,
				array(
					'holder'    => $this->holder_id,
					'expiresAt' => time() + $this->lease_seconds,
				),
				false
			);
		}
	}

	/**
	 * Release the DB lease.
	 */
	private function release_lease() {
		$lease = get_option( FELIX_OPT_RUNNER_LEASE, array() );
		if ( isset( $lease['holder'] ) && $lease['holder'] === $this->holder_id ) {
			delete_option( FELIX_OPT_RUNNER_LEASE );
		}
	}

	/**
	 * Log a message to the log file and STDOUT (CLI only).
	 *
	 * @param string $message
	 */
	private function log( $message ) {
		$line = sprintf( '[%s] %s', current_time( 'Y-m-d H:i:s' ), $message ) . "\n";

		// Only write to STDOUT in CLI mode.
		if ( $this->is_cli ) {
			fwrite( STDOUT, $line );
		}

		// Also write to log file (best-effort).
		@file_put_contents( $this->log_file, $line, FILE_APPEND | LOCK_EX );
	}
}

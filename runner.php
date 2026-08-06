<?php
/**
 * Felix Runner — the CLI poll loop (the core of the connector).
 *
 * Launched by system cron. Holds a DB lease + flock, loops back-to-back
 * long-polls within the window budget, executes commands, posts results.
 *
 * CLI entry point: php runner.php
 * Not loaded via WP admin — bootstraps WordPress manually.
 *
 * @package FelixConnector
 */

// Prevent web access.
if ( php_sapi_name() !== 'cli' ) {
	http_response_code( 403 );
	exit( 'CLI only' );
}

// Bootstrap WordPress (minimal — we need WP + Woo functions).
// Find wp-load.php by searching upward from the plugin directory.
$wp_load_path = false;
$search_dir   = dirname( __DIR__ ); // Start in the plugin's parent (wp-content/plugins/).

for ( $i = 0; $i < 6; $i++ ) {
	$candidate = $search_dir . '/wp-load.php';
	if ( file_exists( $candidate ) ) {
		$wp_load_path = $candidate;
		break;
	}
	$search_dir = dirname( $search_dir );
}

// Also try common paths.
if ( ! $wp_load_path ) {
	// Allow override via environment variable.
	if ( getenv( 'WP_LOAD_PATH' ) && file_exists( getenv( 'WP_LOAD_PATH' ) . '/wp-load.php' ) ) {
		$wp_load_path = getenv( 'WP_LOAD_PATH' ) . '/wp-load.php';
	}
}

if ( ! $wp_load_path ) {
	fwrite( STDERR, "Felix Runner: Could not find wp-load.php. Set WP_LOAD_PATH env var.\n" );
	exit( 1 );
}

// Suppress WP's default output during bootstrap.
$_SERVER['HTTP_HOST']     = parse_url( home_url( '/' ), PHP_URL_HOST ) ?? 'localhost';
$_SERVER['REQUEST_URI']   = '/';

// Define runner mode so the main plugin file loads us instead of the normal flow.
define( 'FELIX_RUNNER_MODE', false ); // We loaded runner.php directly; the main plugin file is loaded by wp-load.

require_once $wp_load_path;

// Now WP + Woo are loaded. The main plugin file has already been loaded by WP's plugin system.

class Felix_Runner {

	/** @var int Default runner window in seconds (just under 30 min cron interval). */
	private $window_seconds = 1790;

	/** @var int Default long-poll hold time. */
	private $poll_hold_seconds = 25;

	/** @var int Minimum re-poll delay after receiving a command. */
	private $min_repoll_delay_ms = 100;

	/** @var int Degraded-mode poll interval (when long-poll is severed). */
	private $degraded_poll_interval_ms = 4000;

	/** @var int Lease duration in seconds (renewed each loop). */
	private $lease_seconds = 60;

	/** @var int Max backoff for error retries. */
	private $max_backoff_seconds = 30;

	/** @var int Holder ID for this runner instance. */
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

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->holder_id = function_exists( 'wp_generate_uuid4' )
			? wp_generate_uuid4()
			: bin2hex( random_bytes( 16 ) );

		$this->handlers = new Felix_Command_Handlers();

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
	}

	/**
	 * Main run loop.
	 */
	public function run() {
		// Check pairing.
		if ( ! Felix_Pairing::is_paired() ) {
			fwrite( STDERR, "Felix Runner: Store not paired.\n" );
			return;
		}

		// Acquire flock (cheap first gate).
		$this->lock_handle = fopen( $this->lock_file, 'c' );
		if ( ! flock( $this->lock_handle, LOCK_EX | LOCK_NB ) ) {
			// Another runner has the lock. Wait up to 120s to take over.
			fwrite( STDOUT, "Felix Runner: Waiting for lock (up to 120s)...\n" );
			$waited = 0;
			while ( $waited < 120 ) {
				if ( flock( $this->lock_handle, LOCK_EX | LOCK_NB ) ) {
					break;
				}
				// Check if the DB lease has expired.
				if ( $this->acquire_lease() ) {
					// Lease expired — take over even if flock is still held
					// (the old process may be hung).
					break;
				}
				usleep( 500000 ); // 0.5s poll.
				$waited += 0.5;
			}
			if ( $waited >= 120 ) {
				fwrite( STDERR, "Felix Runner: Could not acquire lock after 120s. Exiting.\n" );
				fclose( $this->lock_handle );
				return;
			}
		}

		// Acquire DB lease.
		if ( ! $this->acquire_lease() ) {
			// Another runner holds a valid lease.
			fwrite( STDOUT, "Felix Runner: Valid lease held by another runner. Exiting.\n" );
			flock( $this->lock_handle, LOCK_UN );
			fclose( $this->lock_handle );
			return;
		}

		fwrite( STDOUT, sprintf( "Felix Runner: Started (holder=%s, window=%ds)\n", $this->holder_id, $this->window_seconds ) );

		$start_time  = time();
		$deadline    = $start_time + $this->window_seconds;

		while ( time() < $deadline ) {
			// Renew lease.
			$this->renew_lease();

			// Stamp heartbeat.
			update_option( FELIX_OPT_RUNNER_HEARTBEAT, time() );

			// Long-poll for commands.
			$result = $this->poll_once();

			if ( $result === false ) {
				// Network error — back off.
				$this->error_count++;
				$backoff = min( $this->max_backoff_seconds, pow( 2, $this->error_count ) + mt_rand( 0, 1000 ) / 1000 );
				fwrite( STDERR, sprintf( "Felix Runner: Poll error #%d, backing off %.1fs\n", $this->error_count, $backoff ) );
				usleep( (int) ( $backoff * 1000000 ) );
				continue;
			}

			// Reset error count on successful poll.
			$this->error_count = 0;

			// Small delay before next poll.
			if ( $this->degraded ) {
				usleep( $this->degraded_poll_interval_ms * 1000 );
			} else {
				usleep( $this->min_repoll_delay_ms * 1000 );
			}
		}

		// Release lease.
		$this->release_lease();

		fwrite( STDOUT, sprintf( "Felix Runner: Window complete, exiting (ran %ds)\n", time() - $start_time ) );

		flock( $this->lock_handle, LOCK_UN );
		fclose( $this->lock_handle );
	}

	/**
	 * Perform one long-poll cycle.
	 *
	 * @return bool True on success (even if no command), false on error.
	 */
	private function poll_once() {
		$store_id   = Felix_Pairing::get_store_id();
		$generation = Felix_Pairing::get_generation();
		$endpoint   = get_option( FELIX_OPT_POLL_ENDPOINT, FELIX_API_BASE . '/connector/poll' );

		$timestamp = (string) ( time() * 1000 );
		$sign_data = "{$store_id}\n{$generation}\n{$timestamp}";

		// Get secret key.
		$keypair   = Felix_Pairing::get_keypair();
		$secret    = Felix_Crypto::get_secret_key( $keypair['encryptedSecret'] );
		if ( ! $secret ) {
			fwrite( STDERR, "Felix Runner: Could not decrypt secret key.\n" );
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
				'timeout'  => $this->poll_hold_seconds + 10, // Hold for the long-poll + buffer.
				'headers'  => array(
					'X-Felix-Plugin-Sig'  => $signature,
					'X-Felix-Plugin-KeyId' => $keypair['publicKey'],
					'X-Felix-Timestamp'    => $timestamp,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			fwrite( STDERR, "Felix Runner: WP Error: " . $response->get_error_message() . "\n" );
			return false;
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$raw_body    = wp_remote_retrieve_body( $response );

		// 204 = no command (long-poll timeout).
		if ( $status_code === 204 ) {
			return true;
		}

		// 200 = command available.
		if ( $status_code !== 200 ) {
			if ( $status_code === 401 ) {
				fwrite( STDERR, "Felix Runner: Auth rejected (401). Check pairing.\n" );
			} else {
				fwrite( STDERR, "Felix Runner: Unexpected status {$status_code}\n" );
			}
			$this->degraded = true;
			return false;
		}

		// Parse command.
		$command = json_decode( $raw_body, true );
		if ( ! $command || ! isset( $command['commandId'] ) ) {
			fwrite( STDERR, "Felix Runner: Invalid command body.\n" );
			return false;
		}

		// Verify command signature.
		$key_manifest = get_option( FELIX_OPT_KEY_MANIFEST, array() );
		$public_key   = Felix_Crypto::lookup_key( $key_manifest, $command['keyId'] ?? '' );

		if ( ! $public_key ) {
			fwrite( STDERR, sprintf( "Felix Runner: Unknown keyId %s\n", $command['keyId'] ?? '' ) );
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'unknown_key', 'message' => 'Signing key not found in manifest' ) );
			return false;
		}

		$sig_valid = Felix_Crypto::verify_command_signature(
			$raw_body,
			$command['signature'] ?? '',
			$public_key
		);

		if ( ! $sig_valid ) {
			fwrite( STDERR, "Felix Runner: Invalid command signature.\n" );
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'signature_invalid', 'message' => 'Command signature verification failed' ) );
			return false;
		}

		// Validate envelope.
		if ( ! $this->validate_command( $command ) ) {
			return false; // validate_command posts the rejection.
		}

		// Check dedup ledger.
		$existing = Felix_Command_Ledger::get( $command['commandId'] );
		if ( $existing && in_array( $existing->status, array( 'done', 'failed', 'unconfirmed', 'rejected' ), true ) ) {
			// Already executed — return the stored result.
			$this->post_result(
				$command['commandId'],
				$existing->status,
				$existing->result ? json_decode( $existing->result, true ) : null,
				$existing->error ? json_decode( $existing->error, true ) : null
			);
			return true;
		}

		// Record nonce (replay protection).
		if ( ! Felix_Command_Ledger::check_nonce( $command['nonce'] ?? '' ) ) {
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'nonce_seen', 'message' => 'Nonce already consumed' ) );
			return false;
		}

		// Execute the command.
		fwrite( STDOUT, sprintf( "Felix Runner: Executing %s (%s)\n", $command['type'], $command['commandId'] ) );

		$result = $this->handlers->execute(
			$command['commandId'],
			$command['type'],
			$command['args'] ?? array(),
			$command['authorizationBasis'] ?? null
		);

		// Record in ledger.
		Felix_Command_Ledger::record(
			$command['commandId'],
			$command['type'],
			$result['status'],
			$result['result'] ?? null,
			$result['error'] ?? null,
			$result['processorTxnIds'] ?? array(),
			$command['authorizationBasis'] ?? null
		);

		// Post result to Felix.
		$this->post_result(
			$command['commandId'],
			$result['status'],
			$result['result'] ?? null,
			$result['error'] ?? null,
			$result['processorTxnIds'] ?? array()
		);

		fwrite( STDOUT, sprintf( "Felix Runner: Command %s → %s\n", $command['commandId'], $result['status'] ) );

		return true;
	}

	/**
	 * Validate a command envelope (storeId, generation, TTL, type).
	 *
	 * @param array $command
	 * @return bool
	 */
	private function validate_command( $command ) {
		// Store ID match.
		if ( ( $command['storeId'] ?? '' ) !== Felix_Pairing::get_store_id() ) {
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'store_mismatch', 'message' => 'Store ID does not match' ) );
			return false;
		}

		// Generation match.
		if ( (int) ( $command['generation'] ?? 0 ) !== Felix_Pairing::get_generation() ) {
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'generation_mismatch', 'message' => 'Pairing generation mismatch' ) );
			return false;
		}

		// TTL check.
		$issued_at  = strtotime( $command['issuedAt'] ?? '' );
		$ttl        = $command['ttlSeconds'] ?? 120;
		if ( $issued_at === false || ( time() - $issued_at ) > $ttl ) {
			$this->post_result( $command['commandId'], 'rejected', null, array( 'code' => 'ttl_expired', 'message' => 'Command TTL expired' ) );
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
			'protocolVersion'  => FELIX_PROTOCOL_VERSION,
			'commandId'        => $command_id,
			'storeId'          => $store_id,
			'generation'       => $generation,
			'status'           => $status,
			'result'           => $result,
			'error'            => $error,
			'executedAt'       => current_time( 'c' ),
			'processorTxnIds'  => $processor_txn_ids,
		);

		// Sign the result body.
		$body_json = wp_json_encode( $body );

		$keypair = Felix_Pairing::get_keypair();
		$secret  = Felix_Crypto::get_secret_key( $keypair['encryptedSecret'] );
		if ( $secret ) {
			$body['signature'] = Felix_Crypto::sign( $body_json, $secret );
			sodium_memzero( $secret );
		}

		wp_remote_post(
			$endpoint,
			array(
				'timeout' => 15,
				'headers' => array(
					'Content-Type'        => 'application/json',
					'X-Felix-Plugin-Sig'  => $body['signature'] ?? '',
					'X-Felix-Plugin-KeyId' => $keypair['publicKey'],
					'X-Felix-Timestamp'    => (string) ( time() * 1000 ),
				),
				'body'    => wp_json_encode( $body ),
			)
		);
	}

	/**
	 * Acquire the DB lease.
	 *
	 * @return bool True if acquired.
	 */
	private function acquire_lease() {
		$lease = get_option( FELIX_OPT_RUNNER_LEASE, array() );
		$now   = time();

		if ( ! empty( $lease ) && isset( $lease['holder'] ) && isset( $lease['expiresAt'] ) ) {
			if ( $lease['holder'] !== $this->holder_id && $lease['expiresAt'] > $now ) {
				// Another valid lease.
				return false;
			}
		}

		// Claim the lease.
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

		// Only renew if we still hold it.
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
}

// Instantiate and run.
( new Felix_Runner() )->run();

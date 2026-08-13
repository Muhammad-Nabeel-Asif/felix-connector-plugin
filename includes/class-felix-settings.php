<?php
/**
 * Felix Settings — wp-admin settings page for the connector.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_Settings {

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'handle_form' ) );
	}

	public function add_menu() {
		add_submenu_page(
			'woocommerce',
			__( 'Felix Connector', 'felix-connector' ),
			__( 'Felix Connector', 'felix-connector' ),
			'manage_woocommerce',
			'felix-connector',
			array( $this, 'render_page' )
		);
	}

	public function handle_form() {
		if ( ! isset( $_POST['felix_action'] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			return;
		}
		check_admin_referer( 'felix_connector_settings' );

		$action = sanitize_text_field( wp_unslash( $_POST['felix_action'] ) );

		switch ( $action ) {
			case 'pair':
				$this->handle_pair();
				break;
			case 'unpair':
				$this->handle_unpair();
				break;
			case 'save_switches':
				$this->handle_save_switches();
				break;
			case 'checkin':
				$this->handle_checkin();
				break;
			case 'download_log':
				$this->handle_download_log();
				break;
		}
	}

	private function handle_pair() {
		$raw_pairing_code = sanitize_text_field( wp_unslash( $_POST['pairing_code'] ?? '' ) );

		if ( '' === $raw_pairing_code ) {
			add_settings_error( 'felix_connector', 'no_code', __( 'Please enter a pairing code from your Felix dashboard.', 'felix-connector' ), 'error' );
			return;
		}

		// Normalize to the canonical form the backend compares against: drop the
		// cosmetic hyphen/space separator and any stray punctuation, uppercase,
		// and keep ONLY unambiguous-alphabet characters. The displayed code is
		// XXXX-XXXX; this collapses it back to the stored 8-char canonical string.
		$pairing_code = self::normalize_pairing_code( $raw_pairing_code );
		if ( strlen( $pairing_code ) !== FELIX_PAIRING_CODE_LENGTH ) {
			add_settings_error(
				'felix_connector',
				'bad_code',
				sprintf(
					/* translators: %d: required pairing-code length. */
					__( 'That pairing code does not look right — it should be %d characters (letters and digits, exactly as shown in Felix, e.g. ABCD-EFGH).', 'felix-connector' ),
					FELIX_PAIRING_CODE_LENGTH
				),
				'error'
			);
			return;
		}

		$keypair = get_option( FELIX_OPT_PLUGIN_KEYPAIR, array() );
		if ( empty( $keypair ) ) {
			$keypair = Felix_Crypto::generate_identity();
			update_option( FELIX_OPT_PLUGIN_KEYPAIR, $keypair, false );
		}

		$environment = $this->gather_environment();

		$post_body = array(
			'protocolVersion' => FELIX_PROTOCOL_VERSION,
			'pairingCode'     => $pairing_code,
			'storeUrl'        => home_url(),
			'pluginPublicKey' => $keypair['publicKey'],
			'environment'     => $environment,
		);

		$response = wp_remote_post(
			FELIX_API_BASE . '/connector/pair',
			array(
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $post_body ),
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			add_settings_error(
				'felix_connector',
				'pair_failed',
				sprintf(
					/* translators: 1: error message, 2: API base URL */
					__( 'Could not reach Felix (%1$s). Check that this server can make outbound HTTPS requests to %2$s.', 'felix-connector' ),
					$response->get_error_message(),
					FELIX_API_BASE
				),
				'error'
			);
			return;
		}

		$code          = wp_remote_retrieve_response_code( $response );
		$response_body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $code !== 200 ) {
			add_settings_error( 'felix_connector', 'pair_error', self::format_pair_error( $code, $response_body ), 'error' );
			return;
		}

		update_option( FELIX_OPT_STORE_ID, sanitize_text_field( $response_body['storeId'] ), false );
		update_option( FELIX_OPT_GENERATION, intval( $response_body['generation'] ), false );
		update_option( FELIX_OPT_POLL_ENDPOINT, esc_url_raw( $response_body['pollEndpoint'] ?? FELIX_API_BASE . '/connector/poll' ), false );
		update_option( FELIX_OPT_RESULT_ENDPOINT, esc_url_raw( $response_body['resultEndpoint'] ?? FELIX_API_BASE . '/connector/result' ), false );
		update_option( FELIX_OPT_PUSH_ENDPOINT, esc_url_raw( $response_body['pushEndpoint'] ?? FELIX_API_BASE . '/connector/push' ), false );
		update_option( FELIX_OPT_HOST_PROFILE, $response_body['hostProfile'] ?? array(), false );
		update_option( FELIX_OPT_KEY_MANIFEST, $response_body['keyManifest'] ?? array(), false );
		update_option( FELIX_OPT_PAIRED, true, false );
		update_option( FELIX_OPT_LIVENESS_STATE, 'pairing', false );

		// Immediate short check-in so Felix sees lastSeenAt without waiting for cron.
		$checkin_status = function_exists( 'felix_connector_checkin_now' )
			? felix_connector_checkin_now()
			: 'skipped';
		if ( 'success' === $checkin_status ) {
			add_settings_error( 'felix_connector', 'pair_success', __( 'Store connected to Felix. Check-in succeeded.', 'felix-connector' ), 'updated' );
		} else {
			add_settings_error( 'felix_connector', 'pair_success', __( 'Store paired with Felix. Click Check in now if status stays on Connecting… — a page view will not connect the store when the WordPress scheduler is disabled.', 'felix-connector' ), 'updated' );
		}
	}

	/**
	 * Normalize an operator-entered pairing code to the canonical form the
	 * backend stores and compares against: uppercase, then keep ONLY the
	 * unambiguous-alphabet characters (drops the cosmetic hyphen/space separator
	 * and any stray punctuation, and silently rejects ambiguous glyphs like 0/O
	 * and 1/I/L which never appear in a minted code). Static so it is unit-
	 * testable without the WP admin lifecycle.
	 *
	 * @param string $raw Raw input from the settings form.
	 * @return string Canonical code (length is checked by the caller).
	 */
	public static function normalize_pairing_code( $raw ) {
		$upper     = strtoupper( (string) $raw );
		$canonical = '';
		$len       = strlen( $upper );
		for ( $i = 0; $i < $len; $i++ ) {
			$ch = $upper[ $i ];
			if ( false !== strpos( FELIX_PAIRING_CODE_ALPHABET, $ch ) ) {
				$canonical .= $ch;
			}
		}
		return $canonical;
	}

	/**
	 * Option keys cleared on unpair. Includes the runner lease so a re-pair
	 * within ~60s is not skipped by a leftover holder from the previous session.
	 *
	 * @return string[]
	 */
	public static function pairing_state_option_keys() {
		return array(
			FELIX_OPT_STORE_ID,
			FELIX_OPT_GENERATION,
			FELIX_OPT_PAIRED,
			FELIX_OPT_POLL_ENDPOINT,
			FELIX_OPT_RESULT_ENDPOINT,
			FELIX_OPT_PUSH_ENDPOINT,
			FELIX_OPT_HOST_PROFILE,
			FELIX_OPT_KEY_MANIFEST,
			FELIX_OPT_LIVENESS_STATE,
			FELIX_OPT_RUNNER_HEARTBEAT,
			FELIX_OPT_RUNNER_LEASE,
			FELIX_OPT_SEEN_NONCES,
			FELIX_OPT_LAST_POLL_ERROR,
			'felix_last_run_at',
			'felix_last_run_status',
		);
	}

	private function handle_unpair() {
		foreach ( self::pairing_state_option_keys() as $key ) {
			delete_option( $key );
		}

		add_settings_error( 'felix_connector', 'unpaired', __( 'Store disconnected from Felix.', 'felix-connector' ), 'updated' );
	}

	private function handle_save_switches() {
		$killed = isset( $_POST['kill_switches'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['kill_switches'] ) ) : array();
		update_option( FELIX_OPT_KILL_SWITCHES, $killed, false );
		add_settings_error( 'felix_connector', 'switches_saved', __( 'Command permissions updated.', 'felix-connector' ), 'updated' );
	}

	/**
	 * Admin "Check in now" — one short poll via the shared runner pipeline.
	 */
	private function handle_checkin() {
		$status = function_exists( 'felix_connector_checkin_now' )
			? felix_connector_checkin_now()
			: 'skipped';
		if ( 'success' === $status ) {
			add_settings_error( 'felix_connector', 'checkin_ok', __( 'Check-in succeeded. Felix should show Connected shortly.', 'felix-connector' ), 'updated' );
			return;
		}
		if ( 'skipped' === $status ) {
			add_settings_error( 'felix_connector', 'checkin_skip', __( 'Check-in skipped — another runner is already active, or the store is not paired.', 'felix-connector' ), 'info' );
			return;
		}
		$err = get_option( FELIX_OPT_LAST_POLL_ERROR, array() );
		$msg = is_array( $err ) && ! empty( $err['message'] )
			? $err['message']
			: __( 'Unknown poll error. See Advanced & Troubleshooting.', 'felix-connector' );
		add_settings_error(
			'felix_connector',
			'checkin_fail',
			sprintf(
				/* translators: %s: last poll error */
				__( 'Check-in failed: %s', 'felix-connector' ),
				$msg
			),
			'error'
		);
	}

	/**
	 * Stream the connector log file as a download.
	 */
	private function handle_download_log() {
		$path = WP_CONTENT_DIR . '/uploads/felix-connector.log';
		if ( ! is_readable( $path ) ) {
			add_settings_error( 'felix_connector', 'no_log', __( 'No connector log file yet. It is created the first time the runner runs.', 'felix-connector' ), 'error' );
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="felix-connector.log"' );
		header( 'Content-Length: ' . (string) filesize( $path ) );
		readfile( $path );
		exit;
	}

	/**
	 * Map backend pairing HTTP errors to operator-facing copy.
	 *
	 * @param int   $code
	 * @param mixed $response_body
	 * @return string
	 */
	public static function format_pair_error( $code, $response_body ) {
		$backend = '';
		if ( is_array( $response_body ) ) {
			$backend = (string) ( $response_body['message'] ?? $response_body['error'] ?? '' );
		}

		$lower = strtolower( $backend );
		if ( false !== strpos( $lower, 'already used' ) ) {
			return __( 'That pairing code was already used. Mint a new code in Felix and try again.', 'felix-connector' );
		}
		if ( false !== strpos( $lower, 'expired' ) ) {
			return __( 'That pairing code has expired. Mint a new code in Felix and try again.', 'felix-connector' );
		}
		if ( false !== strpos( $lower, 'not found' ) || 404 === (int) $code ) {
			return __( 'That pairing code was not found. Check you typed it exactly as shown in Felix, or mint a new one.', 'felix-connector' );
		}
		if ( $backend ) {
			return sprintf(
				/* translators: %s: backend error message */
				__( 'Pairing failed: %s', 'felix-connector' ),
				$backend
			);
		}
		return sprintf(
			/* translators: %d: HTTP status */
			__( 'Pairing failed (HTTP %d). Mint a new code in Felix and try again.', 'felix-connector' ),
			(int) $code
		);
	}

	private function gather_environment() {
		$hpos_enabled = false;
		if ( class_exists( '\Automattic\WooCommerce\Utilities\OrderUtil' ) ) {
			$hpos_enabled = \Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled();
		}

		$gateways    = WC()->payment_gateways()->payment_gateways();
		$gateway_map = array();
		foreach ( $gateways as $id => $gateway ) {
			$gateway_map[ $id ] = array(
				'title'   => $gateway->title,
				'enabled' => 'yes' === $gateway->enabled,
			);
		}

		$subs_version = null;
		if ( class_exists( 'WC_Subscriptions' ) && defined( 'WC_Subscriptions::$version' ) ) {
			$subs_version = WC_Subscriptions::$version;
		} elseif ( function_exists( 'wcs_get_subscription' ) ) {
			$subs_version = get_option( 'woocommerce_subscriptions_version' );
		}

		$host = 'unknown';
		if ( defined( 'SG2_VHOST' ) ) {
			$host = 'siteground-shared';
		}

		return array(
			'wpVersion'            => get_bloginfo( 'version' ),
			'wcVersion'            => defined( 'WC_VERSION' ) ? WC_VERSION : null,
			'subscriptionsVersion' => $subs_version,
			'hposEnabled'          => $hpos_enabled,
			'gatewayMap'           => $gateway_map,
			'phpVersion'           => PHP_VERSION,
			'hostFingerprint'      => $host,
		);
	}

	/**
	 * Files that MUST ship in the release ZIP. The settings UI and cron docs
	 * reference these by path; CI fails the build if any are missing.
	 *
	 * @return string[] Paths relative to the plugin root.
	 */
	public static function required_release_files() {
		return array(
			'felix-connector.php',
			'runner.php',
			'uninstall.php',
			'readme.txt',
			'includes/class-felix-settings.php',
			'includes/class-felix-runner.php',
			'includes/class-felix-pairing.php',
			'includes/class-felix-crypto.php',
			'includes/class-felix-command-handlers.php',
			'includes/class-felix-command-processor.php',
			'includes/class-felix-command-ledger.php',
			'includes/class-felix-rest.php',
		);
	}

	/**
	 * Absolute path of the CLI runner entry point.
	 *
	 * @return string
	 */
	public static function runner_file_path() {
		return FELIX_CONNECTOR_PLUGIN_DIR . 'runner.php';
	}

	/**
	 * Whether runner.php is actually on disk (false if a ZIP omitted it).
	 *
	 * @return bool
	 */
	public static function runner_file_present() {
		return is_readable( self::runner_file_path() );
	}

	/**
	 * wget command that hits wp-cron.php. Works even when DISABLE_WP_CRON is
	 * set (that flag only blocks spawn-on-page-view, not the HTTP endpoint).
	 *
	 * @param string $home_url Site home URL.
	 * @return string
	 */
	public static function wp_cron_http_command( $home_url ) {
		$url = rtrim( (string) $home_url, '/' ) . '/wp-cron.php?doing_wp_cron';
		return 'wget -q -O - ' . escapeshellarg( $url ) . ' >/dev/null 2>&1';
	}

	/**
	 * PHP CLI command for runner.php. Empty string if the file is missing.
	 *
	 * @return string
	 */
	public static function php_runner_command() {
		if ( ! self::runner_file_present() ) {
			return '';
		}
		$php_binary  = defined( 'PHP_BINARY' ) ? PHP_BINARY : 'php';
		$runner_path = self::runner_file_path();
		return "{$php_binary} {$runner_path} >/dev/null 2>&1";
	}

	/**
	 * Honest Connecting… copy. Never claims a page view already triggered
	 * check-in — that is false when DISABLE_WP_CRON is set.
	 *
	 * @param bool $wp_cron_disabled
	 * @return string
	 */
	public static function connecting_notice( $wp_cron_disabled ) {
		if ( $wp_cron_disabled ) {
			return __( 'WordPress\'s built-in scheduler is disabled (DISABLE_WP_CRON), so visiting this page will not connect Felix. Click Check in now, or add a scheduled task using the command below.', 'felix-connector' );
		}
		return __( 'Felix connects automatically when someone visits your site. You can also click Check in now to check in immediately.', 'felix-connector' );
	}

	/**
	 * Get the cron command with the correct PHP binary and path.
	 *
	 * @deprecated 0.4.2 Use php_runner_command() / wp_cron_http_command().
	 */
	private function get_cron_command() {
		$php = self::php_runner_command();
		return '' !== $php ? $php : self::wp_cron_http_command( home_url() );
	}

	/**
	 * Determine connection status for the UI.
	 *
	 * Connected is keyed off heartbeat (updated only inside the poll loop after
	 * the lease is held), not last_run_at. Skipped runs stamp last_run_at in
	 * older builds and must not look Connected.
	 *
	 * @param bool $paired
	 * @param int  $heartbeat        Unix timestamp of last poll-loop heartbeat, or 0.
	 * @param bool $wp_cron_disabled
	 * @param int  $now              Unix timestamp (injectable for tests).
	 * @return array {status: string, color: string, label: string, show_cron_fallback: bool}
	 */
	public static function connection_status_from_state( $paired, $heartbeat, $wp_cron_disabled, $now ) {
		if ( ! $paired ) {
			return array(
				'status'             => 'not_paired',
				'color'              => 'gray',
				'label'              => __( 'Not connected', 'felix-connector' ),
				'show_cron_fallback' => false,
			);
		}

		$heartbeat = (int) $heartbeat;
		$now       = (int) $now;
		$age       = $heartbeat > 0 ? ( $now - $heartbeat ) : -1;

		// Fresh poll-loop heartbeat (< 15 min) — actually talking to Felix.
		if ( $age >= 0 && $age < 900 ) {
			return array(
				'status'             => 'connected',
				'color'              => 'green',
				'label'              => __( 'Connected', 'felix-connector' ),
				'show_cron_fallback' => (bool) $wp_cron_disabled,
			);
		}

		// Paired but no heartbeat yet, or heartbeat < 2 hours old — "Connecting…".
		if ( $age < 0 || ( $age >= 900 && $age < 7200 ) ) {
			return array(
				'status'             => 'connecting',
				'color'              => 'blue',
				'label'              => __( 'Connecting…', 'felix-connector' ),
				'show_cron_fallback' => (bool) $wp_cron_disabled,
			);
		}

		return array(
			'status'             => $wp_cron_disabled ? 'wp_cron_disabled' : 'stale',
			'color'              => 'orange',
			'label'              => $wp_cron_disabled
				? __( 'WP-Cron is disabled — add a scheduled task to keep Felix connected', 'felix-connector' )
				: __( 'Connection appears inactive — add a scheduled task to keep it running', 'felix-connector' ),
			'show_cron_fallback' => true,
		);
	}

	/**
	 * Determine connection status for the UI.
	 *
	 * @return array {status: string, color: string, label: string, show_cron_fallback: bool}
	 */
	private function get_connection_status() {
		$paired           = (bool) get_option( FELIX_OPT_PAIRED, false );
		$heartbeat        = (int) get_option( FELIX_OPT_RUNNER_HEARTBEAT, 0 );
		$wp_cron_disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;

		return self::connection_status_from_state( $paired, $heartbeat, $wp_cron_disabled, time() );
	}

	public function render_page() {
		$paired    = get_option( FELIX_OPT_PAIRED, false );
		$store_id  = get_option( FELIX_OPT_STORE_ID, '' );
		$heartbeat = get_option( FELIX_OPT_RUNNER_HEARTBEAT, 0 );
		$killed    = get_option( FELIX_OPT_KILL_SWITCHES, array() );

		$last_run      = (int) get_option( 'felix_last_run_at', 0 );
		$last_status   = get_option( 'felix_last_run_status', '' );
		$wp_cron_disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;

		$conn = $this->get_connection_status();

		$stale_seconds = $heartbeat > 0 ? ( time() - intval( $heartbeat ) ) : 0;

		$families = array(
			'order_read'          => __( 'Order lookups (read-only)', 'felix-connector' ),
			'product_read'        => __( 'Product lookups (read-only)', 'felix-connector' ),
			'coupon_read'         => __( 'Coupon lookups (read-only)', 'felix-connector' ),
			'subscription_read'   => __( 'Subscription lookups (read-only)', 'felix-connector' ),
			'webhook_management'  => __( 'Webhook management', 'felix-connector' ),
			'sync'                => __( 'Data synchronization', 'felix-connector' ),
			'order_write'         => __( 'Order updates (status, address)', 'felix-connector' ),
			'order_create'        => __( 'Create orders (comp/free orders)', 'felix-connector' ),
			'coupon_write'        => __( 'Coupon create/update/delete', 'felix-connector' ),
			'subscription_write'  => __( 'Subscription updates', 'felix-connector' ),
			'refund'              => __( 'Process refunds', 'felix-connector' ),
		);

		$cron_http_command = self::wp_cron_http_command( home_url() );
		$cron_php_command  = self::php_runner_command();
		$runner_present    = self::runner_file_present();
		$last_poll_error   = get_option( FELIX_OPT_LAST_POLL_ERROR, array() );
		$log_path          = WP_CONTENT_DIR . '/uploads/felix-connector.log';
		$log_exists        = is_readable( $log_path );

		settings_errors( 'felix_connector' );
		?>
		<div class="wrap">
			<h1>🤵 <?php esc_html_e( 'Felix Connector', 'felix-connector' ); ?></h1>
			<p><?php esc_html_e( 'Connect your store to Felix (agentfelix.ai) for autonomous customer service and store operations.', 'felix-connector' ); ?></p>

			<?php if ( ! $paired ) : ?>
				<!-- PAIRING FORM -->
				<div class="card">
					<h2><?php esc_html_e( 'Connect to Felix', 'felix-connector' ); ?></h2>
					<p><?php esc_html_e( 'Enter the pairing code from Felix to connect this store.', 'felix-connector' ); ?></p>

					<form method="post" action="">
						<?php wp_nonce_field( 'felix_connector_settings' ); ?>
						<input type="hidden" name="felix_action" value="pair">
						<table class="form-table">
							<tr>
								<th scope="row"><label for="pairing_code"><?php esc_html_e( 'Pairing Code', 'felix-connector' ); ?></label></th>
								<td>
									<input type="text" id="pairing_code" name="pairing_code" class="regular-text" placeholder="ABCD-EFGH" maxlength="9" autocomplete="off" autocapitalize="characters" spellcheck="false" title="<?php esc_attr_e( 'Enter the 8-character pairing code from Felix (e.g. ABCD-EFGH).', 'felix-connector' ); ?>" style="font-family: monospace; font-size: 20px; letter-spacing: 3px; text-transform: uppercase;" required>
									<p class="description"><?php esc_html_e( '8 characters, as shown in your Felix dashboard (dashes optional).', 'felix-connector' ); ?></p>
								</td>
							</tr>
						</table>
						<?php submit_button( __( 'Connect Store', 'felix-connector' ), 'primary' ); ?>
					</form>
				</div>

				<!-- DISCLOSURE -->
				<div class="card" style="margin-top: 20px;">
					<h2><?php esc_html_e( 'What does this plugin do?', 'felix-connector' ); ?></h2>
					<p><?php esc_html_e( 'Felix Connector allows your AI assistant Felix to execute actions on your WooCommerce store. Your store contacts Felix (not the other way around), so it works behind any firewall or security layer.', 'felix-connector' ); ?></p>
					<p><strong><?php esc_html_e( 'Felix can:', 'felix-connector' ); ?></strong></p>
					<ul style="list-style: disc; padding-left: 20px;">
						<li><?php esc_html_e( 'Look up orders, products, coupons, and subscriptions', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Update order status and shipping addresses', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Create comp/free orders', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Process refunds (requires explicit approval)', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Sync order and product data for analysis', 'felix-connector' ); ?></li>
					</ul>
					<p><strong><?php esc_html_e( 'Felix cannot:', 'felix-connector' ); ?></strong></p>
					<ul style="list-style: disc; padding-left: 20px;">
						<li><?php esc_html_e( 'Access your payment processor directly', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Make changes you have not authorized', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Execute arbitrary code — every command is typed and validated', 'felix-connector' ); ?></li>
					</ul>
					<p><a href="https://agentfelix.ai" target="_blank"><?php esc_html_e( 'Learn more about Felix →', 'felix-connector' ); ?></a></p>
				</div>

			<?php else : ?>
				<!-- CONNECTION STATUS CARD (happy path) -->
				<div class="card">
					<h2><?php esc_html_e( 'Connection Status', 'felix-connector' ); ?></h2>
					<table class="form-table">
						<tr>
							<th><?php esc_html_e( 'Status', 'felix-connector' ); ?></th>
							<td>
								<span style="color: <?php echo esc_attr( $conn['color'] ); ?>; font-weight: bold; font-size: 14px;">
									● <?php echo esc_html( $conn['label'] ); ?>
								</span>
							</td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Store ID', 'felix-connector' ); ?></th>
							<td><code><?php echo esc_html( $store_id ); ?></code></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Last activity', 'felix-connector' ); ?></th>
							<td>
								<?php
								if ( $last_run > 0 ) {
									$run_age = time() - $last_run;
									if ( $run_age < 60 ) {
										echo esc_html( sprintf( __( '%d seconds ago', 'felix-connector' ), $run_age ) );
									} elseif ( $run_age < 3600 ) {
										echo esc_html( sprintf( __( '%d minutes ago', 'felix-connector' ), intval( $run_age / 60 ) ) );
									} else {
										echo esc_html( sprintf( __( '%d hours ago', 'felix-connector' ), intval( $run_age / 3600 ) ) );
									}
									if ( $last_status ) {
										echo ' <code>' . esc_html( $last_status ) . '</code>';
									}
								} else {
									esc_html_e( 'Never — click Check in now', 'felix-connector' );
								}
								?>
							</td>
						</tr>
					</table>

					<?php if ( 'connecting' === $conn['status'] ) : ?>
						<p style="margin-top: 10px; padding: 10px; background: #e8f4fd; border-left: 4px solid #2271b1;">
							ℹ️ <?php echo esc_html( self::connecting_notice( $wp_cron_disabled ) ); ?>
						</p>
						<?php if ( ! $wp_cron_disabled ) : ?>
						<script>
							setTimeout(function() { window.location.reload(); }, 8000);
						</script>
						<?php endif; ?>
					<?php endif; ?>

					<div style="margin-top: 15px; display: flex; gap: 8px; flex-wrap: wrap;">
						<form method="post" action="" style="display: inline;">
							<?php wp_nonce_field( 'felix_connector_settings' ); ?>
							<input type="hidden" name="felix_action" value="checkin">
							<?php submit_button( __( 'Check in now', 'felix-connector' ), 'primary', 'submit', false ); ?>
						</form>
						<form method="post" action="" style="display: inline;">
							<?php wp_nonce_field( 'felix_connector_settings' ); ?>
							<input type="hidden" name="felix_action" value="unpair">
							<?php submit_button( __( 'Disconnect from Felix', 'felix-connector' ), 'delete', 'submit', false ); ?>
						</form>
					</div>
				</div>

				<?php
				// EXCEPTION PATH: show server cron setup ONLY when needed.
				$show_cron = $conn['show_cron_fallback'];
				if ( $show_cron ) :
				?>
				<!-- SERVER CRON FALLBACK (exception path only) -->
				<div class="card" style="margin-top: 20px; border-left: 4px solid #dba617;">
					<h2>⚙️ <?php esc_html_e( 'Add a Scheduled Task for Reliable Operation', 'felix-connector' ); ?></h2>

					<?php if ( $wp_cron_disabled ) : ?>
						<p><?php esc_html_e( 'Your WordPress site has DISABLE_WP_CRON set, which prevents the connector from running on page views. Add a scheduled task that hits wp-cron.php every 5 minutes — that endpoint still works when the built-in scheduler is disabled.', 'felix-connector' ); ?></p>
					<?php else : ?>
						<p><?php esc_html_e( 'Your site appears to have low traffic or the WordPress built-in scheduler (which runs automatically whenever people visit your site) is not firing reliably. Adding a scheduled task — also called a cron job — ensures Felix stays connected.', 'felix-connector' ); ?></p>
					<?php endif; ?>

					<p><strong><?php esc_html_e( 'Recommended (works on any host, including when DISABLE_WP_CRON is set):', 'felix-connector' ); ?></strong></p>
					<p>
						<input type="text" readonly id="felix-cron-command" class="large-text code" value="<?php echo esc_attr( $cron_http_command ); ?>" style="font-family: monospace; font-size: 13px;">
					</p>
					<p>
						<button type="button" class="button button-secondary" onclick="var e=document.getElementById('felix-cron-command');e.select();document.execCommand('copy');this.textContent='Copied!';">
							📋 <?php esc_html_e( 'Copy Command', 'felix-connector' ); ?>
						</button>
					</p>

					<?php if ( $runner_present && '' !== $cron_php_command ) : ?>
						<p style="margin-top: 15px;"><strong><?php esc_html_e( 'Optional (PHP CLI runner — more reliable on low-traffic sites):', 'felix-connector' ); ?></strong></p>
						<p>
							<input type="text" readonly id="felix-cron-php-command" class="large-text code" value="<?php echo esc_attr( $cron_php_command ); ?>" style="font-family: monospace; font-size: 13px;">
						</p>
					<?php else : ?>
						<p style="margin-top: 15px; padding: 10px; background: #fcf0f1; border-left: 4px solid #d63638;">
							<?php esc_html_e( 'The PHP CLI runner (runner.php) is not installed in this plugin copy. Use the wp-cron.php command above — do not add a cron job that points at a missing runner.php path.', 'felix-connector' ); ?>
						</p>
					<?php endif; ?>

					<details style="margin-top: 15px;">
						<summary style="cursor: pointer; font-weight: bold;"><?php esc_html_e( 'How to add the scheduled task', 'felix-connector' ); ?></summary>
						<div style="margin-top: 10px; padding-left: 15px;">
							<p><strong><?php esc_html_e( 'SiteGround:', 'felix-connector' ); ?></strong> <?php esc_html_e( 'Site Tools → Devs → Cron Jobs → Add New. Set to run every 5 minutes. Paste the command above.', 'felix-connector' ); ?></p>
							<p><strong><?php esc_html_e( 'cPanel:', 'felix-connector' ); ?></strong> <?php esc_html_e( 'Advanced → Cron Jobs → Add New Cron Job. Set to */5 in the minute field, * in all others. Paste the command above.', 'felix-connector' ); ?></p>
							<p><strong><?php esc_html_e( 'WP-CLI / SSH:', 'felix-connector' ); ?></strong> <?php esc_html_e( 'Run "crontab -e" and add the command with a 5-minute schedule.', 'felix-connector' ); ?></p>
						</div>
					</details>
				</div>
				<?php endif; ?>

				<!-- KILL SWITCHES -->
				<div class="card" style="margin-top: 20px;">
					<h2><?php esc_html_e( 'Command Permissions', 'felix-connector' ); ?></h2>
					<p><?php esc_html_e( 'Disable any command family below. Felix will be unable to perform disabled actions on this store.', 'felix-connector' ); ?></p>

					<form method="post" action="">
						<?php wp_nonce_field( 'felix_connector_settings' ); ?>
						<input type="hidden" name="felix_action" value="save_switches">
						<table class="form-table">
							<?php foreach ( $families as $family => $label ) : ?>
								<tr>
									<th scope="row"><?php echo esc_html( $label ); ?></th>
									<td>
										<label>
											<input type="checkbox" name="kill_switches[]" value="<?php echo esc_attr( $family ); ?>" <?php checked( in_array( $family, $killed, true ) ); ?>>
											<?php esc_html_e( 'Disable on this store', 'felix-connector' ); ?>
										</label>
									</td>
								</tr>
							<?php endforeach; ?>
						</table>
						<?php submit_button( __( 'Save Permissions', 'felix-connector' ), 'primary' ); ?>
					</form>
				</div>

				<!-- ADVANCED / TROUBLESHOOTING (collapsed) -->
				<details style="margin-top: 20px;">
					<summary style="cursor: pointer; font-size: 14px; color: #2271b1; font-weight: bold;"><?php esc_html_e( 'Advanced & Troubleshooting', 'felix-connector' ); ?></summary>
					<div class="card" style="margin-top: 10px;">
						<h3><?php esc_html_e( 'Advanced: Scheduled Task (Optional)', 'felix-connector' ); ?></h3>
						<p><?php esc_html_e( 'For high-reliability setups, add a scheduled task that hits wp-cron.php every 5 minutes. This is required when DISABLE_WP_CRON is set, and recommended for staging or low-traffic sites.', 'felix-connector' ); ?></p>
						<p><input type="text" readonly class="large-text code" value="<?php echo esc_attr( $cron_http_command ); ?>" style="font-family: monospace; font-size: 13px;" onclick="this.select();"></p>
						<?php if ( $runner_present && '' !== $cron_php_command ) : ?>
							<p><?php esc_html_e( 'PHP CLI runner (optional):', 'felix-connector' ); ?></p>
							<p><input type="text" readonly class="large-text code" value="<?php echo esc_attr( $cron_php_command ); ?>" style="font-family: monospace; font-size: 13px;" onclick="this.select();"></p>
						<?php endif; ?>

						<hr style="margin: 20px 0;">

						<h3><?php esc_html_e( 'Diagnostics', 'felix-connector' ); ?></h3>
						<table class="form-table">
							<tr>
								<th><?php esc_html_e( 'WordPress scheduler', 'felix-connector' ); ?></th>
								<td>
									<?php if ( $wp_cron_disabled ) : ?>
										<span style="color: red;">⚠️ <?php esc_html_e( 'The built-in scheduler is disabled (DISABLE_WP_CRON is set). It will not fire on page loads.', 'felix-connector' ); ?></span>
									<?php else : ?>
										<span style="color: green;">✅ <?php esc_html_e( 'Active (runs automatically when people visit your site)', 'felix-connector' ); ?></span>
									<?php endif; ?>
								</td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'Last run', 'felix-connector' ); ?></th>
								<td>
									<?php
									if ( $last_run > 0 ) {
										echo esc_html( gmdate( 'Y-m-d H:i:s', $last_run ) ) . ' <code>' . esc_html( $last_status ? $last_status : 'unknown' ) . '</code>';
									} else {
										esc_html_e( 'Never', 'felix-connector' );
									}
									?>
								</td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'Heartbeat', 'felix-connector' ); ?></th>
								<td>
									<?php
									if ( $heartbeat > 0 ) {
										echo esc_html(
											sprintf(
												/* translators: %d: seconds since last heartbeat */
												__( '%d seconds ago', 'felix-connector' ),
												$stale_seconds
											)
										);
									} else {
										esc_html_e( 'None yet', 'felix-connector' );
									}
									?>
								</td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'Last poll error', 'felix-connector' ); ?></th>
								<td>
									<?php
									if ( is_array( $last_poll_error ) && ! empty( $last_poll_error['message'] ) ) {
										$err_age = isset( $last_poll_error['at'] ) ? ( time() - (int) $last_poll_error['at'] ) : 0;
										echo '<span style="color:#d63638;">' . esc_html( $last_poll_error['message'] ) . '</span>';
										if ( $err_age > 0 ) {
											echo ' <span class="description">(' . esc_html( sprintf( __( '%d seconds ago', 'felix-connector' ), $err_age ) ) . ')</span>';
										}
									} else {
										esc_html_e( 'None', 'felix-connector' );
									}
									?>
								</td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'CLI runner.php', 'felix-connector' ); ?></th>
								<td>
									<?php if ( $runner_present ) : ?>
										<span style="color: green;">✅ <?php esc_html_e( 'Installed', 'felix-connector' ); ?></span>
										<code><?php echo esc_html( self::runner_file_path() ); ?></code>
									<?php else : ?>
										<span style="color: red;">⚠️ <?php esc_html_e( 'Missing from this install — use the wp-cron.php scheduled task, not a PHP CLI path.', 'felix-connector' ); ?></span>
									<?php endif; ?>
								</td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'Next scheduled run', 'felix-connector' ); ?></th>
								<td>
									<?php
									$next = wp_next_scheduled( 'felix_connector_cron' );
									echo $next ? esc_html( gmdate( 'Y-m-d H:i:s', $next + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ) ) ) : esc_html__( 'Not scheduled', 'felix-connector' );
									?>
								</td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'WordPress path', 'felix-connector' ); ?></th>
								<td><code><?php echo esc_html( ABSPATH ); ?></code></td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'Plugin path', 'felix-connector' ); ?></th>
								<td><code><?php echo esc_html( FELIX_CONNECTOR_PLUGIN_DIR ); ?></code></td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'PHP binary', 'felix-connector' ); ?></th>
								<td><code><?php echo esc_html( PHP_BINARY ); ?></code></td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'PHP version', 'felix-connector' ); ?></th>
								<td><code><?php echo esc_html( PHP_VERSION ); ?></code></td>
							</tr>
							<tr>
								<th><?php esc_html_e( 'Log file', 'felix-connector' ); ?></th>
								<td>
									<code><?php echo esc_html( $log_path ); ?></code>
									<?php if ( $log_exists ) : ?>
										<form method="post" action="" style="display:inline; margin-left: 8px;">
											<?php wp_nonce_field( 'felix_connector_settings' ); ?>
											<input type="hidden" name="felix_action" value="download_log">
											<?php submit_button( __( 'Download log', 'felix-connector' ), 'secondary', 'submit', false ); ?>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						</table>
					</div>
				</details>

			<?php endif; ?>
		</div>
		<?php
	}
}

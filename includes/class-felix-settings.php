<?php
/**
 * Felix Settings — wp-admin settings page for the connector.
 *
 * Shows pairing UI, connection status, and per-command-family kill switches.
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

	/**
	 * Add the settings menu under WooCommerce.
	 */
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

	/**
	 * Handle form submissions (pairing + kill switches).
	 */
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
		}
	}

	/**
	 * Handle pairing form submission.
	 */
	private function handle_pair() {
		$pairing_code = sanitize_text_field( wp_unslash( $_POST['pairing_code'] ?? '' ) );

		if ( empty( $pairing_code ) ) {
			add_settings_error( 'felix_connector', 'no_code', __( 'Please enter a pairing code from your Felix dashboard.', 'felix-connector' ), 'error' );
			return;
		}

		// Gather environment info.
		$keypair = get_option( FELIX_OPT_PLUGIN_KEYPAIR, array() );
		if ( empty( $keypair ) ) {
			// Generate if missing.
			$keypair = Felix_Crypto::generate_identity();
			update_option( FELIX_OPT_PLUGIN_KEYPAIR, $keypair, false );
		}

		$environment = $this->gather_environment();

		$body = array(
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
				'body'    => wp_json_encode( $body ),
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			add_settings_error( 'felix_connector', 'pair_failed', sprintf( __( 'Connection failed: %s', 'felix-connector' ), $response->get_error_message() ), 'error' );
			return;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $code !== 200 ) {
			$error_msg = $body['message'] ?? $body['error'] ?? __( 'Unknown error', 'felix-connector' );
			add_settings_error( 'felix_connector', 'pair_error', sprintf( __( 'Pairing failed: %s', 'felix-connector' ), $error_msg ), 'error' );
			return;
		}

		// Store pairing data.
		update_option( FELIX_OPT_STORE_ID, sanitize_text_field( $body['storeId'] ), false );
		update_option( FELIX_OPT_GENERATION, intval( $body['generation'] ), false );
		update_option( FELIX_OPT_POLL_ENDPOINT, esc_url_raw( $body['pollEndpoint'] ?? FELIX_API_BASE . '/connector/poll' ), false );
		update_option( FELIX_OPT_RESULT_ENDPOINT, esc_url_raw( $body['resultEndpoint'] ?? FELIX_API_BASE . '/connector/result' ), false );
		update_option( FELIX_OPT_PUSH_ENDPOINT, esc_url_raw( $body['pushEndpoint'] ?? FELIX_API_BASE . '/connector/push' ), false );
		update_option( FELIX_OPT_HOST_PROFILE, $body['hostProfile'] ?? array(), false );
		update_option( FELIX_OPT_KEY_MANIFEST, $body['keyManifest'] ?? array(), false );
		update_option( FELIX_OPT_PAIRED, true, false );
		update_option( FELIX_OPT_LIVENESS_STATE, 'pairing', false );

		add_settings_error( 'felix_connector', 'pair_success', __( 'Store connected to Felix! The connector is now running.', 'felix-connector' ), 'updated' );
	}

	/**
	 * Handle unpair.
	 */
	private function handle_unpair() {
		delete_option( FELIX_OPT_STORE_ID );
		delete_option( FELIX_OPT_GENERATION );
		delete_option( FELIX_OPT_PAIRED );
		delete_option( FELIX_OPT_POLL_ENDPOINT );
		delete_option( FELIX_OPT_RESULT_ENDPOINT );
		delete_option( FELIX_OPT_PUSH_ENDPOINT );
		delete_option( FELIX_OPT_HOST_PROFILE );
		delete_option( FELIX_OPT_KEY_MANIFEST );
		delete_option( FELIX_OPT_LIVENESS_STATE );
		delete_option( FELIX_OPT_RUNNER_HEARTBEAT );
		delete_option( FELIX_OPT_SEEN_NONCES );

		add_settings_error( 'felix_connector', 'unpaired', __( 'Store disconnected from Felix.', 'felix-connector' ), 'updated' );
	}

	/**
	 * Handle kill-switch save.
	 */
	private function handle_save_switches() {
		$killed = isset( $_POST['kill_switches'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['kill_switches'] ) ) : array();
		update_option( FELIX_OPT_KILL_SWITCHES, $killed, false );
		add_settings_error( 'felix_connector', 'switches_saved', __( 'Command permissions updated.', 'felix-connector' ), 'updated' );
	}

	/**
	 * Gather WooCommerce/WordPress environment info for pairing.
	 *
	 * @return array
	 */
	private function gather_environment() {
		// Detect HPOS.
		$hpos_enabled = false;
		if ( class_exists( '\Automattic\WooCommerce\Utilities\OrderUtil' ) ) {
			$hpos_enabled = \Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled();
		}

		// Get gateway map.
		$gateways    = WC()->payment_gateways()->payment_gateways();
		$gateway_map = array();
		foreach ( $gateways as $id => $gateway ) {
			$gateway_map[ $id ] = array(
				'title'   => $gateway->title,
				'enabled' => 'yes' === $gateway->enabled,
			);
		}

		// Detect Subscriptions version.
		$subs_version = null;
		if ( class_exists( 'WC_Subscriptions' ) && defined( 'WC_Subscriptions::$version' ) ) {
			$subs_version = WC_Subscriptions::$version;
		} elseif ( function_exists( 'wcs_get_subscription' ) ) {
			$subs_version = get_option( 'woocommerce_subscriptions_version' );
		}

		// Host fingerprint (best-effort).
		$host = 'unknown';
		if ( isset( $_SERVER['SERVER_NAME'] ) ) {
			$server_name = sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) );
			if ( strpos( $server_name, 'siteground' ) !== false || strpos( gethostname(), 'siteground' ) !== false ) {
				$host = 'siteground-shared';
			}
		}
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
	 * Render the settings page.
	 */
	public function render_page() {
		$paired        = get_option( FELIX_OPT_PAIRED, false );
		$store_id      = get_option( FELIX_OPT_STORE_ID, '' );
		$liveness      = get_option( FELIX_OPT_LIVENESS_STATE, 'unknown' );
		$heartbeat     = get_option( FELIX_OPT_RUNNER_HEARTBEAT, 0 );
		$killed        = get_option( FELIX_OPT_KILL_SWITCHES, array() );
		$stale_seconds = $heartbeat > 0 ? ( time() - intval( $heartbeat ) ) : 0;

		// Liveness label.
		$liveness_labels = array(
			'pairing'      => __( 'Connecting…', 'felix-connector' ),
			'observing'    => __( 'Verifying connection…', 'felix-connector' ),
			'connected'    => __( 'Connected', 'felix-connector' ),
			'reconnecting' => __( 'Reconnecting', 'felix-connector' ),
			'degraded'     => __( 'Degraded', 'felix-connector' ),
			'offline'      => __( 'Offline', 'felix-connector' ),
			'unknown'      => __( 'Not connected', 'felix-connector' ),
		);

		// Command families for kill switches.
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

		settings_errors( 'felix_connector' );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Felix Connector', 'felix-connector' ); ?></h1>
			<p><?php esc_html_e( 'Connect your store to Felix (agentfelix.ai) for autonomous customer service and store operations.', 'felix-connector' ); ?></p>

			<?php if ( ! $paired ) : ?>
				<!-- PAIRING FORM -->
				<div class="card">
					<h2><?php esc_html_e( 'Connect to Felix', 'felix-connector' ); ?></h2>
					<p><?php esc_html_e( 'Enter the pairing code from your Felix dashboard to connect this store.', 'felix-connector' ); ?></p>

					<form method="post" action="">
						<?php wp_nonce_field( 'felix_connector_settings' ); ?>
						<input type="hidden" name="felix_action" value="pair">
						<table class="form-table">
							<tr>
								<th scope="row"><label for="pairing_code"><?php esc_html_e( 'Pairing Code', 'felix-connector' ); ?></label></th>
								<td><input type="text" id="pairing_code" name="pairing_code" class="regular-text" placeholder="ABCXYZ" required></td>
							</tr>
						</table>
						<?php submit_button( __( 'Connect Store', 'felix-connector' ), 'primary' ); ?>
					</form>
				</div>

				<!-- DISCLOSURE -->
				<div class="card" style="margin-top: 20px;">
					<h2><?php esc_html_e( 'What does this plugin do?', 'felix-connector' ); ?></h2>
					<p><?php esc_html_e( 'Felix Connector allows your AI assistant Felix to execute actions on your WooCommerce store. Felix connects to your store via an outbound connection (your store contacts Felix, not the other way around), so it works behind any firewall or security layer.', 'felix-connector' ); ?></p>
					<p><?php esc_html_e( 'Felix can perform these actions (you can disable any of them below at any time):', 'felix-connector' ); ?></p>
					<ul style="list-style: disc; padding-left: 20px;">
						<li><?php esc_html_e( 'Look up orders, products, coupons, and subscriptions', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Update order status and shipping addresses', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Create comp/free orders', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Manage coupons', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Process refunds (requires explicit approval per refund)', 'felix-connector' ); ?></li>
						<li><?php esc_html_e( 'Sync order/product data to Felix for analysis', 'felix-connector' ); ?></li>
					</ul>
					<p><?php esc_html_e( 'Felix cannot: access your payment processor directly, make changes you haven\'t authorized, or execute arbitrary code. Every command is typed and validated.', 'felix-connector' ); ?></p>
					<p><a href="https://agentfelix.ai" target="_blank"><?php esc_html_e( 'Learn more about Felix →', 'felix-connector' ); ?></a></p>
				</div>

			<?php else : ?>
				<!-- CONNECTED STATUS -->
				<div class="card">
					<h2><?php esc_html_e( 'Connection Status', 'felix-connector' ); ?></h2>
					<table class="form-table">
						<tr>
							<th><?php esc_html_e( 'Status', 'felix-connector' ); ?></th>
							<td><strong><?php echo esc_html( $liveness_labels[ $liveness ] ?? $liveness ); ?></strong></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Store ID', 'felix-connector' ); ?></th>
							<td><code><?php echo esc_html( $store_id ); ?></code></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Last heartbeat', 'felix-connector' ); ?></th>
							<td><?php echo $stale_seconds > 0 ? esc_html( sprintf( __( '%d seconds ago', 'felix-connector' ), $stale_seconds ) ) : esc_html__( 'Never', 'felix-connector' ); ?></td>
						</tr>
					</table>

					<form method="post" action="" style="margin-top: 15px;">
						<?php wp_nonce_field( 'felix_connector_settings' ); ?>
						<input type="hidden" name="felix_action" value="unpair">
						<?php submit_button( __( 'Disconnect from Felix', 'felix-connector' ), 'delete', 'submit', false ); ?>
					</form>
				</div>

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

				<!-- CRON SETUP NOTICE -->
				<div class="notice notice-info" style="margin-top: 20px;">
					<p><strong><?php esc_html_e( 'Cron Setup Required:', 'felix-connector' ); ?></strong></p>
					<p><?php esc_html_e( 'Add this to your server crontab (Site Tools → Cron Jobs) for the connector to run:', 'felix-connector' ); ?></p>
					<code>*/30 * * * * /usr/bin/php <?php echo esc_html( FELIX_CONNECTOR_PLUGIN_DIR . 'runner.php' ); ?> >/dev/null 2>&1</code>
				</div>

			<?php endif; ?>
		</div>
		<?php
	}
}

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
		}
	}

	private function handle_pair() {
		$pairing_code = sanitize_text_field( wp_unslash( $_POST['pairing_code'] ?? '' ) );

		if ( empty( $pairing_code ) ) {
			add_settings_error( 'felix_connector', 'no_code', __( 'Please enter a pairing code from your Felix dashboard.', 'felix-connector' ), 'error' );
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
			add_settings_error( 'felix_connector', 'pair_failed', sprintf( __( 'Connection failed: %s', 'felix-connector' ), $response->get_error_message() ), 'error' );
			return;
		}

		$code          = wp_remote_retrieve_response_code( $response );
		$response_body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $code !== 200 ) {
			$error_msg = $response_body['message'] ?? $response_body['error'] ?? __( 'Unknown error', 'felix-connector' );
			add_settings_error( 'felix_connector', 'pair_error', sprintf( __( 'Pairing failed: %s', 'felix-connector' ), $error_msg ), 'error' );
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

		add_settings_error( 'felix_connector', 'pair_success', __( 'Store connected to Felix! Set up the cron job below to activate the connector.', 'felix-connector' ), 'updated' );
	}

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

	private function handle_save_switches() {
		$killed = isset( $_POST['kill_switches'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['kill_switches'] ) ) : array();
		update_option( FELIX_OPT_KILL_SWITCHES, $killed, false );
		add_settings_error( 'felix_connector', 'switches_saved', __( 'Command permissions updated.', 'felix-connector' ), 'updated' );
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
	 * Get the cron command with the correct PHP binary and path.
	 */
	private function get_cron_command() {
		$php_binary  = PHP_BINARY;
		$runner_path = FELIX_CONNECTOR_PLUGIN_DIR . 'runner.php';
		return "{$php_binary} {$runner_path} >/dev/null 2>&1";
	}

	public function render_page() {
		$paired    = get_option( FELIX_OPT_PAIRED, false );
		$store_id  = get_option( FELIX_OPT_STORE_ID, '' );
		$liveness  = get_option( FELIX_OPT_LIVENESS_STATE, 'unknown' );
		$heartbeat = get_option( FELIX_OPT_RUNNER_HEARTBEAT, 0 );
		$killed    = get_option( FELIX_OPT_KILL_SWITCHES, array() );

		$stale_seconds = $heartbeat > 0 ? ( time() - intval( $heartbeat ) ) : 0;

		$liveness_labels = array(
			'pairing'      => __( 'Connecting…', 'felix-connector' ),
			'observing'    => __( 'Verifying connection…', 'felix-connector' ),
			'connected'    => __( 'Connected', 'felix-connector' ),
			'reconnecting' => __( 'Reconnecting', 'felix-connector' ),
			'degraded'     => __( 'Degraded', 'felix-connector' ),
			'offline'      => __( 'Offline', 'felix-connector' ),
			'unknown'      => __( 'Not connected', 'felix-connector' ),
		);

		$liveness_colors = array(
			'connected'    => 'green',
			'reconnecting' => 'orange',
			'degraded'     => 'orange',
			'offline'      => 'red',
			'pairing'      => 'blue',
			'observing'    => 'blue',
			'unknown'      => 'gray',
		);

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

		$cron_command = $this->get_cron_command();

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
								<td><input type="text" id="pairing_code" name="pairing_code" class="regular-text" placeholder="ABC123" style="font-size: 18px; letter-spacing: 2px;" required></td>
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
				<!-- CONNECTED STATUS -->
				<div class="card">
					<h2><?php esc_html_e( 'Connection Status', 'felix-connector' ); ?></h2>
					<table class="form-table">
						<tr>
							<th><?php esc_html_e( 'Status', 'felix-connector' ); ?></th>
							<td>
								<span style="color: <?php echo esc_attr( $liveness_colors[ $liveness ] ?? 'gray' ); ?>; font-weight: bold;">
									● <?php echo esc_html( $liveness_labels[ $liveness ] ?? $liveness ); ?>
								</span>
							</td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Store ID', 'felix-connector' ); ?></th>
							<td><code><?php echo esc_html( $store_id ); ?></code></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Last heartbeat', 'felix-connector' ); ?></th>
							<td>
								<?php
								if ( $stale_seconds > 0 ) {
									if ( $stale_seconds > 1800 ) {
										echo '<span style="color: red;">' . esc_html( sprintf( __( '%d minutes ago — cron may not be running!', 'felix-connector' ), intval( $stale_seconds / 60 ) ) ) . '</span>';
									} elseif ( $stale_seconds > 90 ) {
										echo '<span style="color: orange;">' . esc_html( sprintf( __( '%d seconds ago', 'felix-connector' ), $stale_seconds ) ) . '</span>';
									} else {
										echo '<span style="color: green;">' . esc_html( sprintf( __( '%d seconds ago', 'felix-connector' ), $stale_seconds ) ) . '</span>';
									}
								} else {
									echo '<span style="color: red;">' . esc_html__( 'Never — cron job is not set up yet. See instructions below.', 'felix-connector' ) . '</span>';
								}
								?>
							</td>
						</tr>
					</table>

					<form method="post" action="" style="margin-top: 15px;">
						<?php wp_nonce_field( 'felix_connector_settings' ); ?>
						<input type="hidden" name="felix_action" value="unpair">
						<?php submit_button( __( 'Disconnect from Felix', 'felix-connector' ), 'delete', 'submit', false ); ?>
					</form>
				</div>

				<!-- CRON SETUP -->
				<div class="card" style="margin-top: 20px;">
					<h2><?php esc_html_e( 'Cron Job Setup (Required)', 'felix-connector' ); ?></h2>
					<p><?php esc_html_e( 'For the connector to work, you need to create a cron job on your server. Copy this command:', 'felix-connector' ); ?></p>

					<p>
						<input type="text" readonly id="felix-cron-command" class="large-text code" value="<?php echo esc_attr( $cron_command ); ?>" style="font-family: monospace; font-size: 13px;">
					</p>
					<p>
						<button type="button" class="button button-secondary" onclick="var e=document.getElementById('felix-cron-command');e.select();document.execCommand('copy');this.textContent='Copied!';">
							📋 <?php esc_html_e( 'Copy Command', 'felix-connector' ); ?>
						</button>
					</p>

					<h3><?php esc_html_e( 'How to add the cron job:', 'felix-connector' ); ?></h3>
					<p><strong><?php esc_html_e( 'SiteGround:', 'felix-connector' ); ?></strong> <?php esc_html_e( 'Site Tools → Devs → Cron Jobs → Add New. Set to run every 30 minutes. Paste the command above.', 'felix-connector' ); ?></p>
					<p><strong><?php esc_html_e( 'cPanel:', 'felix-connector' ); ?></strong> <?php esc_html_e( 'Advanced → Cron Jobs → Add New Cron Job. Set to */30 in the minute field, * in all others. Paste the command above.', 'felix-connector' ); ?></p>
					<p><strong><?php esc_html_e( 'WP-CLI:', 'felix-connector' ); ?></strong> <?php esc_html_e( 'If you have SSH access, add to your server crontab via "crontab -e" with the schedule 30 minutes.', 'felix-connector' ); ?></p>

					<p style="margin-top: 15px; padding: 10px; background: #fff8e5; border-left: 4px solid #dba617;">
						⚠️ <?php esc_html_e( 'The connector will not work until this cron job is configured. After adding it, wait 2 minutes and refresh this page — the heartbeat above should update.', 'felix-connector' ); ?>
					</p>
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

				<!-- TROUBLESHOOTING -->
				<div class="card" style="margin-top: 20px;">
					<h2><?php esc_html_e( 'Troubleshooting', 'felix-connector' ); ?></h2>
					<table class="form-table">
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
							<td><code><?php echo esc_html( WP_CONTENT_DIR . '/uploads/felix-connector.log' ); ?></code></td>
						</tr>
					</table>
				</div>

			<?php endif; ?>
		</div>
		<?php
	}
}

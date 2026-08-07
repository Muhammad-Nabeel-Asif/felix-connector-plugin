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

		add_settings_error( 'felix_connector', 'pair_success', __( 'Store connected to Felix! The connector will activate automatically — usually within seconds.', 'felix-connector' ), 'updated' );
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
		delete_option( 'felix_last_run_at' );
		delete_option( 'felix_last_run_status' );

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

	/**
	 * Determine connection status for the UI.
	 *
	 * @return array {status: string, color: string, label: string, show_cron_fallback: bool}
	 */
	private function get_connection_status() {
		$paired     = (bool) get_option( FELIX_OPT_PAIRED, false );
		$last_run   = (int) get_option( 'felix_last_run_at', 0 );
		$run_status = get_option( 'felix_last_run_status', '' );
		$paired_at  = 0; // We don't track pairing timestamp separately; infer from options.

		if ( ! $paired ) {
			return array(
				'status'             => 'not_paired',
				'color'              => 'gray',
				'label'              => __( 'Not connected', 'felix-connector' ),
				'show_cron_fallback' => false,
			);
		}

		// Check DISABLE_WP_CRON.
		$wp_cron_disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;

		$now = time();
		$age = $last_run > 0 ? ( $now - $last_run ) : -1;

		// Fresh run (< 15 min) — connected.
		if ( $age >= 0 && $age < 900 ) {
			return array(
				'status'             => 'connected',
				'color'              => 'green',
				'label'              => __( 'Connected', 'felix-connector' ),
				'show_cron_fallback' => false,
			);
		}

		// Paired but no run yet, or run < 2 hours old — "Connecting…".
		if ( $age < 0 || ( $age >= 900 && $age < 7200 ) ) {
			return array(
				'status'             => 'connecting',
				'color'              => 'blue',
				'label'              => __( 'Connecting…', 'felix-connector' ),
				'show_cron_fallback' => $wp_cron_disabled,
			);
		}

		// Run older than 2 hours (or never after 2+ hours) — show cron fallback.
		return array(
			'status'             => $wp_cron_disabled ? 'wp_cron_disabled' : 'stale',
			'color'              => 'orange',
			'label'              => $wp_cron_disabled
				? __( 'WP-Cron is disabled — add a scheduled task to keep Felix connected', 'felix-connector' )
				: __( 'Connection appears inactive — add a scheduled task to keep it running', 'felix-connector' ),
			'show_cron_fallback' => true,
		);
	}

	public function render_page() {
		$paired    = get_option( FELIX_OPT_PAIRED, false );
		$store_id  = get_option( FELIX_OPT_STORE_ID, '' );
		$liveness  = get_option( FELIX_OPT_LIVENESS_STATE, 'unknown' );
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
						<?php if ( $last_run > 0 ) : ?>
						<tr>
							<th><?php esc_html_e( 'Last activity', 'felix-connector' ); ?></th>
							<td>
								<?php
								$run_age = time() - $last_run;
								if ( $run_age < 60 ) {
									echo esc_html( sprintf( __( '%d seconds ago', 'felix-connector' ), $run_age ) );
								} elseif ( $run_age < 3600 ) {
									echo esc_html( sprintf( __( '%d minutes ago', 'felix-connector' ), intval( $run_age / 60 ) ) );
								} else {
									echo esc_html( sprintf( __( '%d hours ago', 'felix-connector' ), intval( $run_age / 3600 ) ) );
								}
								?>
							</td>
						</tr>
						<?php endif; ?>
					</table>

					<?php if ( 'connecting' === $conn['status'] ) : ?>
						<p style="margin-top: 10px; padding: 10px; background: #e8f4fd; border-left: 4px solid #2271b1;">
							ℹ️ <?php esc_html_e( 'Felix connects automatically — no setup needed. This page view has already triggered the connection; it should update shortly.', 'felix-connector' ); ?>
						</p>
						<script>
							setTimeout(function() { window.location.reload(); }, 5000);
						</script>
					<?php endif; ?>

					<form method="post" action="" style="margin-top: 15px;">
						<?php wp_nonce_field( 'felix_connector_settings' ); ?>
						<input type="hidden" name="felix_action" value="unpair">
						<?php submit_button( __( 'Disconnect from Felix', 'felix-connector' ), 'delete', 'submit', false ); ?>
					</form>
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
						<p><?php esc_html_e( 'Your WordPress site has DISABLE_WP_CRON set, which prevents the connector from running automatically. Add a scheduled task — a small instruction that tells your web host to run something automatically on a timer — to keep Felix connected.', 'felix-connector' ); ?></p>
					<?php else : ?>
						<p><?php esc_html_e( 'Your site appears to have low traffic or the WordPress built-in scheduler (which runs automatically whenever people visit your site) is not firing reliably. Adding a scheduled task — also called a cron job — ensures Felix stays connected.', 'felix-connector' ); ?></p>
					<?php endif; ?>

					<p><?php esc_html_e( 'Copy this command:', 'felix-connector' ); ?></p>
					<p>
						<input type="text" readonly id="felix-cron-command" class="large-text code" value="<?php echo esc_attr( $cron_command ); ?>" style="font-family: monospace; font-size: 13px;">
					</p>
					<p>
						<button type="button" class="button button-secondary" onclick="var e=document.getElementById('felix-cron-command');e.select();document.execCommand('copy');this.textContent='Copied!';">
							📋 <?php esc_html_e( 'Copy Command', 'felix-connector' ); ?>
						</button>
					</p>

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
						<p><?php esc_html_e( 'For high-reliability setups, you can optionally add a scheduled task (a small instruction that tells your web host to run something automatically on a timer) to run the connector independently of site traffic. This is not required for normal operation.', 'felix-connector' ); ?></p>
						<p><input type="text" readonly class="large-text code" value="<?php echo esc_attr( $cron_command ); ?>" style="font-family: monospace; font-size: 13px;" onclick="this.select();"></p>

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
								<td><code><?php echo esc_html( WP_CONTENT_DIR . '/uploads/felix-connector.log' ); ?></code></td>
							</tr>
						</table>
					</div>
				</details>

			<?php endif; ?>
		</div>
		<?php
	}
}

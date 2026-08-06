<?php
/**
 * Felix Command Handlers — typed command registry (deny-by-default).
 *
 * Each command type maps to a hand-written handler. There is NO generic
 * executor. Unknown types are rejected. No raw SQL, no arbitrary
 * rest_do_request, no PHP callback — ever.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_Command_Handlers {

	/**
	 * The command whitelist. A handler must exist here AND not be killed
	 * by the local kill-switch option.
	 *
	 * @var array<string, callable>
	 */
	private $handlers = array();

	/**
	 * Command families for kill-switch grouping.
	 *
	 * @var array<string, string>
	 */
	private static $family_map = array(
		'ping'                   => 'system',
		'get_order'              => 'order_read',
		'get_product'            => 'product_read',
		'list_products'          => 'product_read',
		'get_coupon'             => 'coupon_read',
		'list_coupons'           => 'coupon_read',
		'get_subscriptions'      => 'subscription_read',
		'list_subscriptions'     => 'subscription_read',
		'register_webhooks'      => 'webhook_management',
		'verify_webhooks'        => 'webhook_management',
		'remove_webhooks'        => 'webhook_management',
		'sync_orders'            => 'sync',
		'sync_products'          => 'sync',
		'sync_coupons'           => 'sync',
		'update_order_status'    => 'order_write',
		'update_shipping_address'=> 'order_write',
		'create_order'           => 'order_create',
		'create_coupon'          => 'coupon_write',
		'update_coupon'          => 'coupon_write',
		'delete_coupon'          => 'coupon_write',
		'update_subscription_status' => 'subscription_write',
		'renew_subscription'     => 'subscription_write',
		'refund.create'          => 'refund',
	);

	/**
	 * Initialize handlers. Only Phase 1 types are wired in this version.
	 */
	public function __construct() {
		$this->handlers = array(
			'ping'      => array( $this, 'handle_ping' ),
			'get_order' => array( $this, 'handle_get_order' ),
		);
	}

	/**
	 * Execute a command.
	 *
	 * @param string $command_id
	 * @param string $type
	 * @param array  $args
	 * @param array  $authorization_basis
	 * @return array Result envelope: {status, result, error, processorTxnIds}
	 */
	public function execute( $command_id, $type, $args, $authorization_basis = null ) {
		// 1. Check handler exists (deny-by-default).
		if ( ! isset( $this->handlers[ $type ] ) ) {
			return array(
				'status' => 'rejected',
				'error'  => array(
					'code'    => 'unknown_type',
					'message' => sprintf( 'Unknown command type: %s', $type ),
				),
			);
		}

		// 2. Check kill-switch.
		$family = self::$family_map[ $type ] ?? 'system';
		if ( $this->is_family_killed( $family ) ) {
			return array(
				'status' => 'rejected',
				'error'  => array(
					'code'    => 'family_disabled',
					'message' => sprintf( 'Command family "%s" is disabled on this store', $family ),
				),
			);
		}

		// 3. Execute the handler.
		try {
			$result = call_user_func( $this->handlers[ $type ], $args, $command_id );

			return array(
				'status'           => 'done',
				'result'           => $result['result'] ?? null,
				'processorTxnIds'  => $result['processorTxnIds'] ?? array(),
			);
		} catch ( Exception $e ) {
			return array(
				'status' => 'failed',
				'error'  => array(
					'code'    => 'execution_error',
					'message' => $e->getMessage(),
				),
			);
		}
	}

	/**
	 * Check if a command family is killed by the local kill-switch.
	 *
	 * @param string $family
	 * @return bool True if the family is disabled.
	 */
	private function is_family_killed( $family ) {
		$killed = get_option( FELIX_OPT_KILL_SWITCHES, array() );
		return in_array( $family, $killed, true );
	}

	// -------------------------------------------------------------------------
	// Handlers — Phase 1
	// -------------------------------------------------------------------------

	/**
	 * Handler: ping — health check.
	 *
	 * @param array  $args
	 * @param string $command_id
	 * @return array
	 */
	private function handle_ping( $args, $command_id ) {
		return array(
			'result' => array(
				'pong'      => true,
				'time'      => current_time( 'c' ),
				'wcVersion' => defined( 'WC_VERSION' ) ? WC_VERSION : null,
				'wpVersion' => get_bloginfo( 'version' ),
			),
		);
	}

	/**
	 * Handler: get_order — fetch a single order or search by email.
	 *
	 * @param array  $args  {orderId} or {orderNumber} or {search:{email}}.
	 * @param string $command_id
	 * @return array
	 * @throws Exception If order not found or Woo not active.
	 */
	private function handle_get_order( $args, $command_id ) {
		if ( ! function_exists( 'wc_get_order' ) ) {
			throw new Exception( 'WooCommerce is not active' );
		}

		// By order ID.
		if ( isset( $args['orderId'] ) ) {
			$order = wc_get_order( $args['orderId'] );
			if ( ! $order ) {
				throw new Exception( sprintf( 'Order %s not found', $args['orderId'] ) );
			}
			return array(
				'result' => array( 'order' => $this->serialize_order( $order ) ),
			);
		}

		// By order number (some stores use sequential numbering).
		if ( isset( $args['orderNumber'] ) ) {
			// Try as ID first, then as order number.
			$order = wc_get_order( $args['orderNumber'] );
			if ( ! $order ) {
				$orders = wc_get_orders(
					array(
						'limit'      => 1,
						'type'       => 'shop_order',
						'meta_key'   => '_order_number',
						'meta_value' => $args['orderNumber'],
					)
				);
				$order = ! empty( $orders ) ? $orders[0] : false;
			}
			if ( ! $order ) {
				throw new Exception( sprintf( 'Order number %s not found', $args['orderNumber'] ) );
			}
			return array(
				'result' => array( 'order' => $this->serialize_order( $order ) ),
			);
		}

		// Search by email.
		if ( isset( $args['search']['email'] ) ) {
			$orders = wc_get_orders(
				array(
					'limit'      => 20,
					'orderby'    => 'date',
					'order'      => 'DESC',
					'customer'   => $args['search']['email'],
				)
			);

			$serialized = array();
			foreach ( $orders as $order ) {
				$serialized[] = $this->serialize_order( $order );
			}

			return array(
				'result' => array( 'orders' => $serialized ),
			);
		}

		throw new Exception( 'get_order requires orderId, orderNumber, or search.email' );
	}

	/**
	 * Serialize a WC_Order to an array.
	 *
	 * @param WC_Order $order
	 * @return array
	 */
	private function serialize_order( $order ) {
		return array(
			'id'               => $order->get_id(),
			'number'           => $order->get_order_number(),
			'status'           => $order->get_status(),
			'dateCreated'      => $order->get_date_created() ? $order->get_date_created()->date( 'c' ) : null,
			'datePaid'         => $order->get_date_paid() ? $order->get_date_paid()->date( 'c' ) : null,
			'total'            => $order->get_total(),
			'currency'         => $order->get_currency(),
			'customerId'       => $order->get_customer_id(),
			'billing'          => array(
				'firstName' => $order->get_billing_first_name(),
				'lastName'  => $order->get_billing_last_name(),
				'email'     => $order->get_billing_email(),
				'phone'     => $order->get_billing_phone(),
				'address1'  => $order->get_billing_address_1(),
				'address2'  => $order->get_billing_address_2(),
				'city'      => $order->get_billing_city(),
				'state'     => $order->get_billing_state(),
				'postcode'  => $order->get_billing_postcode(),
				'country'   => $order->get_billing_country(),
			),
			'shipping'         => array(
				'firstName' => $order->get_shipping_first_name(),
				'lastName'  => $order->get_shipping_last_name(),
				'address1'  => $order->get_shipping_address_1(),
				'address2'  => $order->get_shipping_address_2(),
				'city'      => $order->get_shipping_city(),
				'state'     => $order->get_shipping_state(),
				'postcode'  => $order->get_shipping_postcode(),
				'country'   => $order->get_shipping_country(),
			),
			'paymentMethod'    => $order->get_payment_method(),
			'paymentMethodTitle' => $order->get_payment_method_title(),
			'lineItems'        => array_map(
				function ( $item ) {
					return array(
						'id'        => $item->get_id(),
						'name'      => $item->get_name(),
						'productId' => $item->get_product_id(),
						'quantity'  => $item->get_quantity(),
						'total'     => $item->get_total(),
					);
				},
				$order->get_items()
			),
			'refunds'          => array_map(
				function ( $refund ) {
					return array(
						'id'     => $refund->get_id(),
						'amount' => $refund->get_amount(),
						'reason' => $refund->get_reason(),
					);
				},
				$order->get_refunds()
			),
		);
	}
}

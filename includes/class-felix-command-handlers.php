<?php
/**
 * Felix Command Handlers — typed command registry (deny-by-default).
 *
 * Each command type maps to a hand-written handler. There is NO generic
 * executor. Unknown types are rejected. No raw SQL, no arbitrary
 * rest_do_request, no PHP callback — ever.
 *
 * Command families:
 *   - system: ping
 *   - order_read: get_order, search_orders
 *   - product_read: get_product, list_products
 *   - subscription_read: get_subscription, get_subscriptions, list_subscriptions, list_subscriptions_for_customer
 *   - coupon_read: get_coupon, list_coupons
 *   - customer_read: list_customers
 *   - order_write: update_order_status, update_order_shipping_address
 *   - coupon_write: create_coupon, update_coupon, deactivate_coupon
 *   - subscription_write: update_subscription_status, renew_subscription
 *   - webhook_management: register_webhooks, verify_webhooks, remove_webhooks
 *   - sync: sync_orders, sync_products, sync_coupons
 *   - refund: refund.create
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
		'ping'                        => 'system',
		'get_order'                   => 'order_read',
		'search_orders'               => 'order_read',
		'get_product'                 => 'product_read',
		'list_products'               => 'product_read',
		'get_subscription'            => 'subscription_read',
		'get_subscriptions'           => 'subscription_read',
		'list_subscriptions'          => 'subscription_read',
		'list_subscriptions_for_customer' => 'subscription_read',
		'get_coupon'                  => 'coupon_read',
		'list_coupons'                => 'coupon_read',
		'list_customers'              => 'customer_read',
		'register_webhooks'           => 'webhook_management',
		'verify_webhooks'             => 'webhook_management',
		'remove_webhooks'             => 'webhook_management',
		'sync_orders'                 => 'sync',
		'sync_products'               => 'sync',
		'sync_coupons'                => 'sync',
		'update_order_status'         => 'order_write',
		'update_order_shipping_address' => 'order_write',
		'create_coupon'               => 'coupon_write',
		'update_coupon'               => 'coupon_write',
		'deactivate_coupon'           => 'coupon_write',
		'update_subscription_status'  => 'subscription_write',
		'renew_subscription'          => 'subscription_write',
		'refund.create'               => 'refund',
	);

	/**
	 * Initialize handlers.
	 */
	public function __construct() {
		$this->handlers = array(
			// System
			'ping'      => array( $this, 'handle_ping' ),

			// Order reads
			'get_order'     => array( $this, 'handle_get_order' ),
			'search_orders' => array( $this, 'handle_search_orders' ),

			// Product reads
			'list_products' => array( $this, 'handle_list_products' ),

			// Customer reads
			'list_customers' => array( $this, 'handle_list_customers' ),

			// Subscription reads
			'get_subscription'                 => array( $this, 'handle_get_subscription' ),
			'list_subscriptions'               => array( $this, 'handle_list_subscriptions' ),
			'list_subscriptions_for_customer'  => array( $this, 'handle_list_subscriptions_for_customer' ),

			// Order writes
			'update_order_status'         => array( $this, 'handle_update_order_status' ),
			'update_order_shipping_address' => array( $this, 'handle_update_order_shipping_address' ),

			// Coupon writes
			'create_coupon'     => array( $this, 'handle_create_coupon' ),
			'update_coupon'     => array( $this, 'handle_update_coupon' ),
			'deactivate_coupon' => array( $this, 'handle_deactivate_coupon' ),

			// Subscription writes
			'update_subscription_status' => array( $this, 'handle_update_subscription_status' ),
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
		} catch ( Felix_Plugin_Not_Active_Exception $e ) {
			return array(
				'status' => 'failed',
				'error'  => array(
					'code'    => 'plugin_not_active',
					'message' => $e->getMessage(),
				),
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
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Check WooCommerce is active.
	 *
	 * @throws Felix_Plugin_Not_Active_Exception
	 */
	private function require_woocommerce() {
		if ( ! function_exists( 'wc_get_order' ) ) {
			throw new Felix_Plugin_Not_Active_Exception( 'WooCommerce is not active' );
		}
	}

	/**
	 * Check WooCommerce Subscriptions is active.
	 *
	 * @throws Felix_Plugin_Not_Active_Exception
	 */
	private function require_subscriptions() {
		if ( ! function_exists( 'wcs_get_subscription' ) ) {
			throw new Felix_Plugin_Not_Active_Exception( 'WooCommerce Subscriptions plugin is not active' );
		}
	}

	// -------------------------------------------------------------------------
	// Handlers — System
	// -------------------------------------------------------------------------

	/**
	 * Handler: ping — health check.
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

	// -------------------------------------------------------------------------
	// Handlers — Order Reads
	// -------------------------------------------------------------------------

	/**
	 * Handler: get_order — fetch a single order by ID, number, or search by email.
	 */
	private function handle_get_order( $args, $command_id ) {
		$this->require_woocommerce();

		if ( isset( $args['orderId'] ) ) {
			$order = wc_get_order( $args['orderId'] );
			if ( ! $order ) {
				throw new Exception( sprintf( 'Order %s not found', $args['orderId'] ) );
			}
			return array(
				'result' => array( 'order' => $this->serialize_order( $order ) ),
			);
		}

		if ( isset( $args['orderNumber'] ) ) {
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

		if ( isset( $args['search']['email'] ) ) {
			return $this->search_orders_by_email( $args['search']['email'] );
		}

		throw new Exception( 'get_order requires orderId, orderNumber, or search.email' );
	}

	/**
	 * Handler: search_orders — search orders by customer email.
	 */
	private function handle_search_orders( $args, $command_id ) {
		$this->require_woocommerce();

		$email = $args['email'] ?? ( $args['search']['email'] ?? null );
		if ( ! $email ) {
			throw new Exception( 'search_orders requires an email address' );
		}

		return $this->search_orders_by_email( $email, $args['limit'] ?? 20 );
	}

	/**
	 * Search orders by customer email.
	 */
	private function search_orders_by_email( $email, $limit = 20 ) {
		$orders = wc_get_orders(
			array(
				'limit'    => $limit,
				'orderby'  => 'date',
				'order'    => 'DESC',
				'customer' => $email,
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

	// -------------------------------------------------------------------------
	// Handlers — Product Reads
	// -------------------------------------------------------------------------

	/**
	 * Handler: list_products — list products with optional filters.
	 */
	private function handle_list_products( $args, $command_id ) {
		$this->require_woocommerce();

		$query_args = array(
			'limit'   => $args['limit'] ?? 50,
			'orderby' => 'date',
			'order'   => 'DESC',
			'status'  => $args['status'] ?? 'publish',
			'return'  => 'objects',
		);

		if ( isset( $args['search'] ) ) {
			$query_args['s'] = $args['search'];
		}

		$products = wc_get_products( $query_args );

		$serialized = array();
		foreach ( $products as $product ) {
			$serialized[] = $this->serialize_product( $product );
		}

		return array(
			'result' => array( 'products' => $serialized ),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Customer Reads
	// -------------------------------------------------------------------------

	/**
	 * Handler: list_customers — list customers with optional email filter.
	 */
	private function handle_list_customers( $args, $command_id ) {
		$this->require_woocommerce();

		$query_args = array(
			'limit'   => $args['limit'] ?? 50,
			'orderby' => 'date',
			'order'   => 'DESC',
		);

		if ( isset( $args['email'] ) ) {
			$query_args['email'] = $args['email'];
		}

		$customers = wc_get_customers( $query_args );

		$serialized = array();
		foreach ( $customers as $customer ) {
			$serialized[] = array(
				'id'        => $customer['id'] ?? null,
				'email'     => $customer['email'] ?? null,
				'firstName' => $customer['first_name'] ?? null,
				'lastName'  => $customer['last_name'] ?? null,
				'username'  => $customer['username'] ?? null,
				'orders'    => $customer['orders_count'] ?? 0,
				'totalSpent'=> $customer['total_spent'] ?? '0',
			);
		}

		return array(
			'result' => array( 'customers' => $serialized ),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Subscription Reads
	// -------------------------------------------------------------------------

	/**
	 * Handler: get_subscription — fetch a single subscription by ID.
	 */
	private function handle_get_subscription( $args, $command_id ) {
		$this->require_subscriptions();

		$sub_id = $args['subscriptionId'] ?? ( $args['id'] ?? null );
		if ( ! $sub_id ) {
			throw new Exception( 'get_subscription requires subscriptionId' );
		}

		$subscription = wcs_get_subscription( $sub_id );
		if ( ! $subscription ) {
			throw new Exception( sprintf( 'Subscription %s not found', $sub_id ) );
		}

		return array(
			'result' => array( 'subscription' => $this->serialize_subscription( $subscription ) ),
		);
	}

	/**
	 * Handler: list_subscriptions — list subscriptions store-wide by status.
	 *
	 * @param array $args {status: string, limit: int, page: int}
	 */
	private function handle_list_subscriptions( $args, $command_id ) {
		$this->require_subscriptions();

		$status   = $args['status'] ?? 'active';
		$per_page = min( $args['limit'] ?? 100, 500 );
		$page     = max( $args['page'] ?? 1, 1 );

		// wcs_get_subscriptions accepts the same args as wc_get_orders
		$subscriptions = wcs_get_subscriptions(
			array(
				'subscriptions_per_page' => $per_page,
				'page'                   => $page,
				'subscription_status'    => $status,
				'orderby'                => 'date',
				'order'                  => 'DESC',
			)
		);

		$serialized = array();
		foreach ( $subscriptions as $subscription ) {
			$serialized[] = $this->serialize_subscription( $subscription );
		}

		return array(
			'result' => array(
				'subscriptions' => $serialized,
				'status'        => $status,
				'page'          => $page,
				'count'         => count( $serialized ),
			),
		);
	}

	/**
	 * Handler: list_subscriptions_for_customer — list subscriptions for a
	 * specific customer by email or customer ID.
	 */
	private function handle_list_subscriptions_for_customer( $args, $command_id ) {
		$this->require_subscriptions();

		$email      = $args['email'] ?? null;
		$customer_id = $args['customerId'] ?? null;

		if ( ! $email && ! $customer_id ) {
			throw new Exception( 'list_subscriptions_for_customer requires email or customerId' );
		}

		// Resolve customer ID from email if needed.
		if ( ! $customer_id && $email ) {
			$customer = get_user_by( 'email', $email );
			if ( ! $customer ) {
				// Also try finding by billing email in order meta.
				$order = wc_get_orders(
					array(
						'limit'      => 1,
						'customer'   => $email,
						'return'     => 'ids',
					)
				);
				if ( ! empty( $order ) ) {
					$order_obj = wc_get_order( $order[0] );
					if ( $order_obj ) {
						$customer_id = $order_obj->get_customer_id();
					}
				}
			} else {
				$customer_id = $customer->ID;
			}

			if ( ! $customer_id ) {
				return array( 'result' => array( 'subscriptions' => array() ) );
			}
		}

		$subscriptions = wcs_get_subscriptions(
			array(
				'subscriptions_per_page' => -1,
				'customer_id'            => $customer_id,
			)
		);

		$serialized = array();
		foreach ( $subscriptions as $subscription ) {
			$serialized[] = $this->serialize_subscription( $subscription );
		}

		return array(
			'result' => array( 'subscriptions' => $serialized ),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Order Writes
	// -------------------------------------------------------------------------

	/**
	 * Handler: update_order_status — update an order's status.
	 */
	private function handle_update_order_status( $args, $command_id ) {
		$this->require_woocommerce();

		$order_id = $args['orderId'] ?? null;
		$status   = $args['status'] ?? null;

		if ( ! $order_id || ! $status ) {
			throw new Exception( 'update_order_status requires orderId and status' );
		}

		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			throw new Exception( sprintf( 'Order %s not found', $order_id ) );
		}

		$order->update_status( $status, sprintf( __( 'Status updated by Felix (command %s)', 'felix-connector' ), $command_id ) );
		$order->save();

		return array(
			'result' => array(
				'order' => $this->serialize_order( $order ),
			),
		);
	}

	/**
	 * Handler: update_order_shipping_address — update shipping address on an order.
	 */
	private function handle_update_order_shipping_address( $args, $command_id ) {
		$this->require_woocommerce();

		$order_id = $args['orderId'] ?? null;
		$address  = $args['address'] ?? null;

		if ( ! $order_id || ! $address ) {
			throw new Exception( 'update_order_shipping_address requires orderId and address' );
		}

		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			throw new Exception( sprintf( 'Order %s not found', $order_id ) );
		}

		// Apply address fields.
		$prefix = 'shipping_';
		$fields = array( 'first_name', 'last_name', 'company', 'address_1', 'address_2', 'city', 'state', 'postcode', 'country', 'phone' );
		foreach ( $fields as $field ) {
			$method = 'set_shipping_' . $field;
			if ( isset( $address[ $field ] ) ) {
				$order->$method( $address[ $field ] );
			}
		}
		$order->save();

		return array(
			'result' => array(
				'order' => $this->serialize_order( $order ),
			),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Coupon Writes
	// -------------------------------------------------------------------------

	/**
	 * Handler: create_coupon — create a new coupon.
	 */
	private function handle_create_coupon( $args, $command_id ) {
		$this->require_woocommerce();

		$code = $args['code'] ?? null;
		if ( ! $code ) {
			throw new Exception( 'create_coupon requires code' );
		}

		// Check if coupon already exists.
		$existing = new WC_Coupon( wc_sanitize_coupon_code( $code ) );
		if ( $existing->get_id() > 0 ) {
			throw new Exception( sprintf( 'Coupon code "%s" already exists', $code ) );
		}

		$coupon = new WC_Coupon();
		$coupon->set_code( wc_sanitize_coupon_code( $code ) );
		$coupon->set_discount_type( $args['type'] ?? 'percent' );
		$coupon->set_amount( $args['amount'] ?? 0 );

		if ( isset( $args['description'] ) ) {
			$coupon->set_description( $args['description'] );
		}
		if ( isset( $args['expiryDate'] ) ) {
			$coupon->set_date_expires( strtotime( $args['expiryDate'] ) );
		}
		if ( isset( $args['usageLimit'] ) ) {
			$coupon->set_usage_limit( $args['usageLimit'] );
		}
		if ( isset( $args['usageLimitPerUser'] ) ) {
			$coupon->set_usage_limit_per_user( $args['usageLimitPerUser'] );
		}
		if ( isset( $args['individualUse'] ) ) {
			$coupon->set_individual_use( (bool) $args['individualUse'] );
		}
		if ( isset( $args['freeShipping'] ) ) {
			$coupon->set_free_shipping( (bool) $args['freeShipping'] );
		}

		$coupon_id = $coupon->save();

		return array(
			'result' => array(
				'couponId' => $coupon_id,
				'code'     => $coupon->get_code(),
				'type'     => $coupon->get_discount_type(),
				'amount'   => $coupon->get_amount(),
			),
		);
	}

	/**
	 * Handler: update_coupon — update an existing coupon.
	 */
	private function handle_update_coupon( $args, $command_id ) {
		$this->require_woocommerce();

		$code = $args['code'] ?? null;
		if ( ! $code ) {
			throw new Exception( 'update_coupon requires code' );
		}

		$coupon = new WC_Coupon( wc_sanitize_coupon_code( $code ) );
		if ( ! $coupon->get_id() ) {
			throw new Exception( sprintf( 'Coupon "%s" not found', $code ) );
		}

		if ( isset( $args['amount'] ) ) {
			$coupon->set_amount( $args['amount'] );
		}
		if ( isset( $args['type'] ) ) {
			$coupon->set_discount_type( $args['type'] );
		}
		if ( isset( $args['description'] ) ) {
			$coupon->set_description( $args['description'] );
		}
		if ( isset( $args['expiryDate'] ) ) {
			$coupon->set_date_expires( strtotime( $args['expiryDate'] ) );
		}
		if ( isset( $args['usageLimit'] ) ) {
			$coupon->set_usage_limit( $args['usageLimit'] );
		}

		$coupon->save();

		return array(
			'result' => array(
				'couponId' => $coupon->get_id(),
				'code'     => $coupon->get_code(),
				'type'     => $coupon->get_discount_type(),
				'amount'   => $coupon->get_amount(),
			),
		);
	}

	/**
	 * Handler: deactivate_coupon — set a coupon's status to inactive by
	 * setting its expiry date to the past.
	 */
	private function handle_deactivate_coupon( $args, $command_id ) {
		$this->require_woocommerce();

		$code = $args['code'] ?? null;
		if ( ! $code ) {
			throw new Exception( 'deactivate_coupon requires code' );
		}

		$coupon = new WC_Coupon( wc_sanitize_coupon_code( $code ) );
		if ( ! $coupon->get_id() ) {
			throw new Exception( sprintf( 'Coupon "%s" not found', $code ) );
		}

		// Deactivate by setting expiry in the past.
		$coupon->set_date_expires( time() - 86400 );
		$coupon->save();

		return array(
			'result' => array(
				'couponId' => $coupon->get_id(),
				'code'     => $coupon->get_code(),
				'deactivated' => true,
			),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Subscription Writes
	// -------------------------------------------------------------------------

	/**
	 * Handler: update_subscription_status — transition a subscription's status.
	 */
	private function handle_update_subscription_status( $args, $command_id ) {
		$this->require_subscriptions();

		$sub_id = $args['subscriptionId'] ?? null;
		$status = $args['status'] ?? null;

		if ( ! $sub_id || ! $status ) {
			throw new Exception( 'update_subscription_status requires subscriptionId and status' );
		}

		$subscription = wcs_get_subscription( $sub_id );
		if ( ! $subscription ) {
			throw new Exception( sprintf( 'Subscription %s not found', $sub_id ) );
		}

		// Validate the status transition.
		$valid_statuses = array( 'active', 'on-hold', 'cancelled', 'pending-cancel', 'expired' );
		if ( ! in_array( $status, $valid_statuses, true ) ) {
			throw new Exception( sprintf( 'Invalid subscription status: %s', $status ) );
		}

		$subscription->update_status( $status, sprintf( __( 'Status updated by Felix (command %s)', 'felix-connector' ), $command_id ) );
		$subscription->save();

		return array(
			'result' => array(
				'subscription' => $this->serialize_subscription( $subscription ),
			),
		);
	}

	// -------------------------------------------------------------------------
	// Serialization
	// -------------------------------------------------------------------------

	/**
	 * Serialize a WC_Order to an array.
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

	/**
	 * Serialize a WC_Subscription to an array.
	 */
	private function serialize_subscription( $subscription ) {
		$line_items = array();
		foreach ( $subscription->get_items() as $item ) {
			$line_items[] = array(
				'name'       => $item->get_name(),
				'productId'  => $item->get_product_id(),
				'quantity'   => $item->get_quantity(),
				'total'      => $item->get_total(),
			);
		}

		return array(
			'id'                  => $subscription->get_id(),
			'status'              => $subscription->get_status(),
			'customerId'          => $subscription->get_customer_id(),
			'billing'             => array(
				'firstName' => $subscription->get_billing_first_name(),
				'lastName'  => $subscription->get_billing_last_name(),
				'email'     => $subscription->get_billing_email(),
			),
			'lineItems'           => $line_items,
			'nextPaymentDateGmt'  => $subscription->get_date( 'next_payment' ) ? $subscription->get_date( 'next_payment' ) : null,
			'billingPeriod'       => $subscription->get_billing_period(),
			'billingInterval'     => $subscription->get_billing_interval(),
			'total'               => $subscription->get_total(),
			'paymentMethod'       => $subscription->get_payment_method(),
			'requiresManualRenewal' => $subscription->requires_manual_renewal(),
			'dateCreated'         => $subscription->get_date( 'date_created' ) ? $subscription->get_date( 'date_created' ) : null,
		);
	}

	/**
	 * Serialize a WC_Product to an array.
	 */
	private function serialize_product( $product ) {
		return array(
			'id'          => $product->get_id(),
			'name'        => $product->get_name(),
			'slug'        => $product->get_slug(),
			'status'      => $product->get_status(),
			'type'        => $product->get_type(),
			'price'       => $product->get_price(),
			'regularPrice'=> $product->get_regular_price(),
			'salePrice'   => $product->get_sale_price(),
			'sku'         => $product->get_sku(),
			'manageStock' => $product->get_manage_stock(),
			'stockStatus' => $product->get_stock_status(),
			'stockQuantity' => $product->get_stock_quantity(),
			'description' => $product->get_description(),
			'shortDescription' => $product->get_short_description(),
			'permalink'   => $product->get_permalink(),
		);
	}
}

/**
 * Custom exception for when a required plugin (WC, WC Subscriptions) is not active.
 */
class Felix_Plugin_Not_Active_Exception extends Exception {
}

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
 *   - order_create: create_order
 *   - coupon_write: create_coupon, update_coupon, deactivate_coupon
 *   - subscription_write: update_subscription_status, renew_subscription
 *   - customer_write: delete_customer
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
		'create_order'                => 'order_create',
		'create_coupon'               => 'coupon_write',
		'update_coupon'               => 'coupon_write',
		'deactivate_coupon'           => 'coupon_write',
		'update_subscription_status'  => 'subscription_write',
		'renew_subscription'          => 'subscription_write',
		'refund.create'               => 'refund',
		'delete_customer'             => 'customer_write',
	);

	/**
	 * Read-only families. Every other family in the map is treated as a
	 * write family for authorization-basis enforcement.
	 *
	 * @var string[]
	 */
	private static $read_families = array(
		'system',
		'order_read',
		'product_read',
		'subscription_read',
		'coupon_read',
		'customer_read',
		'sync',
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

			// Sync (paged backfill for the data mirror)
			'sync_orders'   => array( $this, 'handle_sync_orders' ),

			// Product reads
			'get_product'   => array( $this, 'handle_get_product' ),
			'list_products' => array( $this, 'handle_list_products' ),

			// Sync (paged product backfill)
			'sync_products' => array( $this, 'handle_sync_products' ),

			// Customer reads
			'list_customers' => array( $this, 'handle_list_customers' ),

			// Subscription reads
			'get_subscription'                 => array( $this, 'handle_get_subscription' ),
			'list_subscriptions'               => array( $this, 'handle_list_subscriptions' ),
			'list_subscriptions_for_customer'  => array( $this, 'handle_list_subscriptions_for_customer' ),

			// Coupon reads
			'get_coupon'   => array( $this, 'handle_get_coupon' ),
			'list_coupons' => array( $this, 'handle_list_coupons' ),

			// Sync (paged coupon backfill)
			'sync_coupons' => array( $this, 'handle_sync_coupons' ),

			// Webhook management
			'register_webhooks' => array( $this, 'handle_register_webhooks' ),
			'verify_webhooks'   => array( $this, 'handle_verify_webhooks' ),
			'remove_webhooks'   => array( $this, 'handle_remove_webhooks' ),

			// Order writes
			'update_order_status'         => array( $this, 'handle_update_order_status' ),
			'update_order_shipping_address' => array( $this, 'handle_update_order_shipping_address' ),

			// Order creation (write)
			'create_order' => array( $this, 'handle_create_order' ),

			// Coupon writes
			'create_coupon'     => array( $this, 'handle_create_coupon' ),
			'update_coupon'     => array( $this, 'handle_update_coupon' ),
			'deactivate_coupon' => array( $this, 'handle_deactivate_coupon' ),

			// Subscription writes
			'update_subscription_status' => array( $this, 'handle_update_subscription_status' ),
			'renew_subscription'         => array( $this, 'handle_renew_subscription' ),

			// Refunds
			'refund.create' => array( $this, 'handle_refund_create' ),

			// Customer writes
			'delete_customer' => array( $this, 'handle_delete_customer' ),
		);
	}

	/**
	 * Execute a command.
	 *
	 * Authorization-basis enforcement happens BEFORE the handler is invoked.
	 * The synthetic connector-read graduated rule is sufficient for read
	 * families but is explicitly denied for any write family; writes require
	 * real approval evidence or a non-read graduated rule.
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

		// 3. Authorize the basis against the family's read/write classification.
		$auth = self::authorize( $family, $authorization_basis );
		if ( ! $auth['ok'] ) {
			return array(
				'status' => 'rejected',
				'error'  => array(
					'code'    => $auth['code'],
					'message' => $auth['message'],
				),
			);
		}

		// 4. Execute the handler.
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
	 * Public family lookup — used by the shared processor for authorization.
	 *
	 * @param string $type
	 * @return string|null
	 */
	public static function family_for( $type ) {
		return self::$family_map[ $type ] ?? null;
	}

	/**
	 * Whether a family is in the explicit read allowlist.
	 *
	 * @param string $family
	 * @return bool
	 */
	public static function is_read_family( $family ) {
		return in_array( $family, self::$read_families, true );
	}

	/**
	 * Authorize an authorization basis against a command family.
	 *
	 * Policy:
	 *  - Deny-by-default. Missing/non-array basis or unknown kind rejects.
	 *  - Approval evidence satisfies both reads and writes.
	 *  - Graduated rule 'connector-read' satisfies reads, denies writes.
	 *  - Any other graduated rule satisfies both reads and writes.
	 *
	 * @param string $family
	 * @param mixed  $authorization_basis
	 * @return array {ok: bool, code?: string, message?: string}
	 */
	public static function authorize( $family, $authorization_basis ) {
		if ( ! is_array( $authorization_basis ) ) {
			return array(
				'ok'      => false,
				'code'    => 'missing_authorization',
				'message' => 'Authorization basis required',
			);
		}

		$kind    = $authorization_basis['kind'] ?? null;
		$rule_id = $authorization_basis['ruleId'] ?? null;

		if ( ! $kind ) {
			return array(
				'ok'      => false,
				'code'    => 'missing_authorization_kind',
				'message' => 'Authorization basis kind required',
			);
		}

		$is_read = self::is_read_family( $family );

		if ( 'approval' === $kind ) {
			return array( 'ok' => true );
		}

		if ( 'graduated_rule' === $kind ) {
			if ( ! $rule_id ) {
				return array(
					'ok'      => false,
					'code'    => 'missing_rule_id',
					'message' => 'graduated_rule authorization requires ruleId',
				);
			}

			if ( 'connector-read' === $rule_id ) {
				if ( $is_read ) {
					return array( 'ok' => true );
				}
				return array(
					'ok'      => false,
					'code'    => 'insufficient_authorization',
					'message' => 'connector-read authority is not sufficient for write commands',
				);
			}

			// Any other graduated rule satisfies both reads and writes.
			return array( 'ok' => true );
		}

		return array(
			'ok'      => false,
			'code'    => 'unknown_authorization_kind',
			'message' => sprintf( 'Unknown authorization kind: %s', $kind ),
		);
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

	/**
	 * Validate a webhook delivery URL is a safe target for the store to POST
	 * to: the scheme MUST be https, the host MUST NOT be 'localhost', and an
	 * IP-literal host MUST NOT fall in a private or reserved range (SSRF guard
	 * for register_webhooks).
	 *
	 * @throws Exception on any disallowed scheme/host.
	 *
	 * @param string $delivery_url
	 */
	private function validate_delivery_url( $delivery_url ) {
		$parsed = parse_url( (string) $delivery_url );
		if ( ! is_array( $parsed ) || empty( $parsed['scheme'] ) || empty( $parsed['host'] ) ) {
			throw new Exception( 'register_webhooks deliveryUrl must be an absolute https URL' );
		}
		if ( strtolower( (string) $parsed['scheme'] ) !== 'https' ) {
			throw new Exception( sprintf( 'register_webhooks deliveryUrl must use the https scheme (got %s)', $parsed['scheme'] ) );
		}

		// parse_url may return IPv6 literals with or without their enclosing
		// brackets depending on the PHP version; normalize by stripping [] so
		// filter_var/inet_pton see the bare address.
		$host = strtolower( (string) $parsed['host'] );
		if ( strlen( $host ) >= 2 && '[' === substr( $host, 0, 1 ) && ']' === substr( $host, -1 ) ) {
			$host = substr( $host, 1, -1 );
		}

		if ( 'localhost' === $host ) {
			throw new Exception( 'register_webhooks deliveryUrl must not target localhost' );
		}

		$is_v4 = filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
		$is_v6 = filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
		if ( false === $is_v4 && false === $is_v6 ) {
			return; // A named host (e.g. felix.example.com) — not an IP literal.
		}

		$packed = @inet_pton( $host );
		if ( false === $packed ) {
			throw new Exception( sprintf( 'register_webhooks deliveryUrl host is not a valid IP (%s)', $host ) );
		}

		$private = false;
		if ( false !== $is_v4 && 4 === strlen( $packed ) ) {
			$b0 = ord( $packed[0] );
			$b1 = ord( $packed[1] );
			// 10.0.0.0/8
			if ( 10 === $b0 ) {
				$private = true;
			} elseif ( 172 === $b0 && $b1 >= 16 && $b1 <= 31 ) {
				// 172.16.0.0/12
				$private = true;
			} elseif ( 192 === $b0 && 168 === $b1 ) {
				// 192.168.0.0/16
				$private = true;
			} elseif ( 127 === $b0 ) {
				// 127.0.0.0/8 (loopback)
				$private = true;
			} elseif ( 169 === $b0 && 254 === $b1 ) {
				// 169.254.0.0/16 (link-local)
				$private = true;
			}
		} elseif ( false !== $is_v6 && 16 === strlen( $packed ) ) {
			// ::1 (loopback).
			if ( "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" === $packed ) {
				$private = true;
			} else {
				// fc00::/7 — unique-local. Top 7 bits 1111110 => first byte 0xFC|0xFD.
				$b0 = ord( $packed[0] );
				if ( 0xFC === $b0 || 0xFD === $b0 ) {
					$private = true;
				}
			}
		}

		if ( $private ) {
			throw new Exception( sprintf( 'register_webhooks deliveryUrl must not target a private or reserved IP range (%s)', $host ) );
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
				'search'   => $email,
			)
		);

		// WC 'search' is fuzzy (matches name/email/etc), so filter to EXACT billing-email matches.
		$email_lower = strtolower( $email );
		$orders = array_filter( $orders, function ( $order ) use ( $email_lower ) {
			return strtolower( $order->get_billing_email() ) === $email_lower;
		} );

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

	/**
	 * Handler: get_product — fetch a single product by ID or SKU.
	 *
	 * Returns the list_products item shape plus the full description,
	 * stock quantity, and category names.
	 */
	private function handle_get_product( $args, $command_id ) {
		$this->require_woocommerce();

		$product_id = $args['productId'] ?? null;
		$sku        = $args['sku'] ?? null;

		if ( ! $product_id && ! $sku ) {
			throw new Exception( 'get_product requires productId or sku' );
		}

		if ( ! $product_id && $sku ) {
			if ( function_exists( 'wc_get_product_id_by_sku' ) ) {
				$product_id = wc_get_product_id_by_sku( $sku );
			}
			if ( ! $product_id ) {
				throw new Exception( sprintf( 'Product with sku %s not found', $sku ) );
			}
		}

		$product = wc_get_product( $product_id );
		if ( ! $product ) {
			throw new Exception( sprintf( 'Product %s not found', $product_id ) );
		}

		$data = $this->serialize_product( $product );

		// Append categories (list_products item shape does not include them).
		$terms              = function_exists( 'get_the_terms' ) ? get_the_terms( $product->get_id(), 'product_cat' ) : false;
		$data['categories'] = ( is_array( $terms ) )
			? array_map(
				function ( $term ) {
					return $term->name;
				},
				$terms
			)
			: array();

		return array(
			'result' => array( 'product' => $data ),
		);
	}

	// ------------------------------------------------------------------------
	// Handlers — Sync (paged backfill for the data mirror)
	// -------------------------------------------------------------------------

	/**
	 * Handler: sync_orders — paged order backfill by modified_after cursor.
	 *
	 * Used by WooCommerceSyncConnector to fill the data mirror via the
	 * connector protocol. Supports date-cursor pagination: the engine sends
	 * modifiedAfter (ISO 8601) + limit + page; this handler returns one page
	 * of orders modified after that timestamp, ordered ascending.
	 */
	private function handle_sync_orders( $args, $command_id ) {
		$this->require_woocommerce();

		$modified_after = $args['modifiedAfter'] ?? $args['modified_after'] ?? null;
		$limit          = min( intval( $args['limit'] ?? 100 ), 100 );
		$page           = max( intval( $args['page'] ?? 1 ), 1 );

		$query_args = array(
			'limit'    => $limit,
			'page'     => $page,
			'orderby'  => 'modified',
			'order'    => 'ASC',
			'type'     => 'shop_order',
			'return'   => 'objects',
		);

		if ( $modified_after ) {
			$query_args['date_modified'] = '>=' . $modified_after;
		}

		$orders = wc_get_orders( $query_args );

		$serialized = array();
		foreach ( $orders as $order ) {
			$serialized[] = $this->serialize_order( $order );
		}

		return array(
			'result' => array( 'orders' => $serialized ),
		);
	}

	/**
	 * Handler: sync_products — paged product backfill by modified_after cursor.
	 */
	private function handle_sync_products( $args, $command_id ) {
		$this->require_woocommerce();

		$modified_after = $args['modifiedAfter'] ?? $args['modified_after'] ?? null;
		$limit          = min( intval( $args['limit'] ?? 50 ), 100 );
		$page           = max( intval( $args['page'] ?? 1 ), 1 );

		$query_args = array(
			'limit'   => $limit,
			'page'    => $page,
			'orderby' => 'modified',
			'order'   => 'ASC',
			'status'  => 'any',
			'return'  => 'objects',
		);

		if ( $modified_after ) {
			$query_args['modified'] = '>=' . $modified_after;
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

	/**
	 * Handler: sync_coupons — paged coupon backfill by modified_after cursor.
	 *
	 * Mirrors handle_sync_orders: paged, modified_after cursor, ASC by
	 * modified. Coupons are a CPT (shop_coupon) so the backfill uses a
	 * WP_Query on post_modified rather than wc_get_orders.
	 */
	private function handle_sync_coupons( $args, $command_id ) {
		$this->require_woocommerce();

		$modified_after = $args['modifiedAfter'] ?? $args['modified_after'] ?? null;
		$limit          = min( intval( $args['limit'] ?? 100 ), 100 );
		$page           = max( intval( $args['page'] ?? 1 ), 1 );

		$query_args = array(
			'post_type'      => 'shop_coupon',
			'post_status'    => 'any',
			'posts_per_page' => $limit,
			'paged'          => $page,
			'orderby'        => 'modified',
			'order'          => 'ASC',
			'no_found_rows'  => true,
		);

		if ( $modified_after ) {
			$query_args['date_query'] = array(
				array(
					'column' => 'post_modified',
					'after'  => $modified_after,
				),
			);
		}

		$query = new WP_Query( $query_args );

		$serialized = array();
		foreach ( $query->posts as $post ) {
			$coupon = new WC_Coupon( $post->ID );
			if ( $coupon->get_id() ) {
				$serialized[] = $this->serialize_coupon( $coupon );
			}
		}

		return array(
			'result' => array( 'coupons' => $serialized ),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Coupon Reads
	// -------------------------------------------------------------------------

	/**
	 * Handler: get_coupon — fetch a single coupon by code or couponId.
	 */
	private function handle_get_coupon( $args, $command_id ) {
		$this->require_woocommerce();

		$code = $args['code'] ?? null;
		$id   = $args['couponId'] ?? null;

		if ( ! $code && ! $id ) {
			throw new Exception( 'get_coupon requires code or couponId' );
		}

		$coupon = $code ? new WC_Coupon( wc_sanitize_coupon_code( $code ) ) : new WC_Coupon( $id );
		if ( ! $coupon->get_id() ) {
			throw new Exception( 'Coupon not found' );
		}

		return array(
			'result' => array( 'coupon' => $this->serialize_coupon( $coupon ) ),
		);
	}

	/**
	 * Handler: list_coupons — paged coupon list with optional search.
	 *
	 * @param array $args {page?, perPage? (cap 50), search?}
	 */
	private function handle_list_coupons( $args, $command_id ) {
		$this->require_woocommerce();

		$page     = max( intval( $args['page'] ?? 1 ), 1 );
		$per_page = min( max( intval( $args['perPage'] ?? $args['per_page'] ?? 20 ), 1 ), 50 );

		$query_args = array(
			'post_type'      => 'shop_coupon',
			'post_status'    => 'any',
			'posts_per_page' => $per_page,
			'paged'          => $page,
			'orderby'        => 'date',
			'order'          => 'DESC',
			'no_found_rows'  => false,
		);

		if ( isset( $args['search'] ) ) {
			$query_args['s'] = $args['search'];
		}

		$query = new WP_Query( $query_args );

		$coupons = array();
		foreach ( $query->posts as $post ) {
			$coupon = new WC_Coupon( $post->ID );
			if ( $coupon->get_id() ) {
				$coupons[] = $this->serialize_coupon( $coupon );
			}
		}

		$has_more = ( $page * $per_page ) < (int) $query->found_posts;

		return array(
			'result' => array(
				'coupons' => $coupons,
				'page'    => $page,
				'hasMore' => $has_more,
			),
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

	/**
	 * Handler: renew_subscription — create a manual renewal order for the
	 * subscription via WooCommerce Subscriptions (wcs_create_renewal_order).
	 *
	 * HONEST SEMANTICS: WooCommerce has no first-class instant-charge endpoint.
	 * This creates the renewal order (the store's Action Scheduler processes
	 * the real charge on its next tick). The serialized subscription + the new
	 * renewal order id are returned so the caller can report the scheduled
	 * (not instant) renewal honestly.
	 *
	 * Requires the WooCommerce Subscriptions plugin + the wcs_create_renewal_order
	 * function. If the capability is unavailable, fails honestly (no fake charge).
	 */
	private function handle_renew_subscription( $args, $command_id ) {
		$this->require_subscriptions();

		$sub_id = $args['subscriptionId'] ?? null;
		if ( ! $sub_id ) {
			throw new Exception( 'renew_subscription requires subscriptionId' );
		}

		$subscription = wcs_get_subscription( $sub_id );
		if ( ! $subscription ) {
			throw new Exception( sprintf( 'Subscription %s not found', $sub_id ) );
		}

		if ( ! function_exists( 'wcs_create_renewal_order' ) ) {
			throw new Exception( 'WooCommerce Subscriptions renewal is not available on this store' );
		}

		$renewal_order = wcs_create_renewal_order( $subscription );
		if ( ! $renewal_order ) {
			throw new Exception( sprintf( 'Failed to create renewal order for subscription %s', $sub_id ) );
		}

		return array(
			'result' => array(
				'subscription'    => $this->serialize_subscription( $subscription ),
				'renewalOrderId'  => $renewal_order->get_id(),
			),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Webhook Management
	// -------------------------------------------------------------------------

	/**
	 * Handler: register_webhooks — create a WC_Webhook (active, wp_api_v3) per
	 * topic, idempotently. A webhook matching BOTH deliveryUrl and topic is
	 * skipped (not duplicated).
	 *
	 * @param array $args {deliveryUrl, secret, topics[]}
	 */
	private function handle_register_webhooks( $args, $command_id ) {
		$this->require_woocommerce();

		$delivery_url = $args['deliveryUrl'] ?? null;
		$secret       = $args['secret'] ?? '';
		$topics       = $args['topics'] ?? null;

		if ( ! $delivery_url || ! is_array( $topics ) || empty( $topics ) ) {
			throw new Exception( 'register_webhooks requires deliveryUrl and topics' );
		}

		// SSRF guard: the store will POST to this URL, so it must be https and
		// must not target localhost or a private/reserved IP range.
		$this->validate_delivery_url( $delivery_url );

		// Build an idempotency index of existing (delivery_url, topic) pairs.
		$existing = function_exists( 'wc_get_webhooks' ) ? wc_get_webhooks( array( 'status' => 'any' ) ) : array();
		$index    = array();
		foreach ( $existing as $webhook ) {
			$key = $webhook->get_delivery_url() . '|' . $webhook->get_topic();
			if ( ! isset( $index[ $key ] ) ) {
				$index[ $key ] = $webhook->get_id();
			}
		}

		$registered = array();
		$skipped    = array();

		foreach ( $topics as $topic ) {
			$key = $delivery_url . '|' . $topic;
			if ( isset( $index[ $key ] ) ) {
				$skipped[] = array(
					'topic' => $topic,
					'id'    => $index[ $key ],
				);
				continue;
			}

			$webhook = new WC_Webhook();
			$webhook->set_name( 'Felix' );
			$webhook->set_status( 'active' );
			$webhook->set_topic( $topic );
			$webhook->set_delivery_url( $delivery_url );
			$webhook->set_secret( $secret );
			if ( method_exists( $webhook, 'set_api_version' ) ) {
				$webhook->set_api_version( 3 ); // wp_api_v3.
			}
			$webhook->save();

			// Record the new pair so duplicate topics within this same call skip too.
			$index[ $key ]      = $webhook->get_id();
			$registered[] = array(
				'id'    => $webhook->get_id(),
				'topic' => $topic,
			);
		}

		return array(
			'result' => array(
				'registered' => $registered,
				'skipped'    => $skipped,
			),
		);
	}

	/**
	 * Handler: verify_webhooks — report which topics have an active webhook for
	 * the given deliveryUrl, which are missing, and which exist but are
	 * disabled (paused).
	 *
	 * @param array $args {deliveryUrl, topics[]}
	 */
	private function handle_verify_webhooks( $args, $command_id ) {
		$this->require_woocommerce();

		$delivery_url = $args['deliveryUrl'] ?? null;
		$topics       = $args['topics'] ?? null;

		if ( ! $delivery_url || ! is_array( $topics ) ) {
			throw new Exception( 'verify_webhooks requires deliveryUrl and topics' );
		}

		$existing = function_exists( 'wc_get_webhooks' ) ? wc_get_webhooks( array( 'status' => 'any' ) ) : array();
		$by_topic = array();
		foreach ( $existing as $webhook ) {
			if ( $webhook->get_delivery_url() === $delivery_url ) {
				$by_topic[ $webhook->get_topic() ] = array(
					'status' => $webhook->get_status(),
					'id'     => $webhook->get_id(),
				);
			}
		}

		$active   = array();
		$missing  = array();
		$disabled = array();

		foreach ( $topics as $topic ) {
			if ( ! isset( $by_topic[ $topic ] ) ) {
				$missing[] = $topic;
			} elseif ( 'active' === $by_topic[ $topic ]['status'] ) {
				$active[] = $topic;
			} else {
				$disabled[] = array(
					'topic'  => $topic,
					'status' => $by_topic[ $topic ]['status'],
				);
			}
		}

		return array(
			'result' => array(
				'active'   => $active,
				'missing'  => $missing,
				'disabled' => $disabled,
			),
		);
	}

	/**
	 * Handler: remove_webhooks — delete every webhook whose delivery_url matches.
	 *
	 * @param array $args {deliveryUrl}
	 */
	private function handle_remove_webhooks( $args, $command_id ) {
		$this->require_woocommerce();

		$delivery_url = $args['deliveryUrl'] ?? null;
		if ( ! $delivery_url ) {
			throw new Exception( 'remove_webhooks requires deliveryUrl' );
		}

		$existing = function_exists( 'wc_get_webhooks' ) ? wc_get_webhooks( array( 'status' => 'any' ) ) : array();
		$removed  = 0;
		foreach ( $existing as $webhook ) {
			if ( $webhook->get_delivery_url() === $delivery_url ) {
				$webhook->delete();
				$removed++;
			}
		}

		return array(
			'result' => array(
				'removed' => $removed,
			),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Refunds
	// -------------------------------------------------------------------------

	/**
	 * Handler: refund.create — issue a refund for an order via wc_create_refund.
	 *
	 * Validates the amount against the order's remaining refundable total
	 * (order total − already refunded) BEFORE calling wc_create_refund. A
	 * WP_Error or false return is surfaced with the store's own message, and
	 * success is NEVER reported without a concrete refund id.
	 *
	 * @param array $args {orderId, amount, reason, refundPayment?}
	 */
	private function handle_refund_create( $args, $command_id ) {
		$this->require_woocommerce();

		$order_id = $args['orderId'] ?? null;
		$amount   = $args['amount'] ?? null;

		if ( ! $order_id || null === $amount ) {
			throw new Exception( 'refund.create requires orderId and amount' );
		}

		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			throw new Exception( sprintf( 'Order %s not found', $order_id ) );
		}

		$total     = (float) $order->get_total();
		$refunded  = (float) $order->get_total_refunded();
		$remaining = $total - $refunded;

		// A non-positive amount must be rejected BEFORE the over-refund guard:
		// a negative amount never satisfies `> $remaining`, so it would slip
		// past the upper-bound check and reach wc_create_refund unchecked.
		if ( (float) $amount <= 0 ) {
			throw new Exception( sprintf( 'Refund amount %s must be greater than zero', $amount ) );
		}

		if ( (float) $amount > $remaining ) {
			throw new Exception( sprintf( 'Refund amount %s exceeds remaining refundable total %s', $amount, $remaining ) );
		}

		$refund = wc_create_refund(
			array(
				'amount'         => $amount,
				'reason'         => $args['reason'] ?? '',
				'order_id'       => $order_id,
				'refund_payment' => isset( $args['refundPayment'] ) ? (bool) $args['refundPayment'] : true,
				'restock_items'  => true,
			)
		);

		if ( is_wp_error( $refund ) || ! $refund ) {
			$message = is_wp_error( $refund ) ? $refund->get_error_message() : 'wc_create_refund returned no refund';
			throw new Exception( $message );
		}

		$refund_id = $refund->get_id();
		if ( ! $refund_id ) {
			throw new Exception( 'wc_create_refund returned a refund without an id' );
		}

		// Re-fetch the order so the order projection reflects the new totals.
		$order = wc_get_order( $order_id );

		$date_created = method_exists( $refund, 'get_date_created' ) ? $refund->get_date_created() : null;

		return array(
			'result' => array(
				'refund' => array(
					'id'          => $refund_id,
					'amount'      => $refund->get_amount(),
					'reason'      => $refund->get_reason(),
					'dateCreated' => ( $date_created && method_exists( $date_created, 'date' ) ) ? $date_created->date( 'c' ) : null,
				),
				'order'  => array(
					'id'            => $order->get_id(),
					'status'        => $order->get_status(),
					'totalRefunded' => $order->get_total_refunded(),
				),
			),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Order Creation (write)
	// -------------------------------------------------------------------------

	/**
	 * Handler: create_order — create a new order from line items.
	 *
	 * Resolution: customerId or email → set_customer_id. Products are added,
	 * addresses applied, totals calculated, then zero-price (complimentary-
	 * order) overrides are applied AFTER calculate_totals so they stick.
	 *
	 * @param array $args {
	 *   customerId? or email, lineItems:[{productId, quantity, priceOverride?}],
	 *   shippingAddress?, status? default 'processing', note?
	 * }
	 */
	private function handle_create_order( $args, $command_id ) {
		$this->require_woocommerce();

		$line_items = $args['lineItems'] ?? null;
		if ( ! is_array( $line_items ) || empty( $line_items ) ) {
			throw new Exception( 'create_order requires lineItems' );
		}

		// Arg-validation: a negative priceOverride would invert a line total,
		// so reject any negative value up front — before any order is created.
		foreach ( $line_items as $li ) {
			if ( array_key_exists( 'priceOverride', $li ) && (float) $li['priceOverride'] < 0 ) {
				throw new Exception( sprintf( 'priceOverride must be greater than or equal to zero (productId %s got %s)', $li['productId'] ?? '', $li['priceOverride'] ) );
			}
		}

		// Resolve customer.
		$customer_id = $args['customerId'] ?? null;
		$email       = $args['email'] ?? null;
		if ( ! $customer_id && $email && function_exists( 'get_user_by' ) ) {
			$user = get_user_by( 'email', $email );
			if ( $user ) {
				$customer_id = $user->ID;
			}
		}

		$order = wc_create_order();

		if ( $customer_id ) {
			$order->set_customer_id( (int) $customer_id );
		}

		// Add products (records the catalog price per line).
		foreach ( $line_items as $li ) {
			$product_id = $li['productId'] ?? null;
			if ( ! $product_id ) {
				throw new Exception( 'each lineItem requires productId' );
			}
			$qty = isset( $li['quantity'] ) ? max( (int) $li['quantity'], 1 ) : 1;

			$product = wc_get_product( $product_id );
			if ( ! $product ) {
				throw new Exception( sprintf( 'Product %s not found', $product_id ) );
			}
			$order->add_product( $product, $qty );
		}

		// Addresses.
		if ( isset( $args['shippingAddress'] ) && is_array( $args['shippingAddress'] ) ) {
			$order->set_address( $this->map_address( $args['shippingAddress'] ), 'shipping' );
		}
		if ( isset( $args['billingAddress'] ) && is_array( $args['billingAddress'] ) ) {
			$order->set_address( $this->map_address( $args['billingAddress'] ), 'billing' );
		}

		$order->calculate_totals();

		// Zero-price (comp-order) overrides applied AFTER calculate_totals so
		// the override survives (calculate would otherwise re-price from the
		// catalog). The order total is recomputed from the overridden lines.
		//
		// Overrides are correlated to order items by productId, NOT by line
		// position: the created order's item ordering need not match the input
		// lineItems ordering, so positional matching could re-price the wrong
		// line. Index items by productId and throw if an override is ambiguous
		// (two order items share the productId) or unmatched (no item carries
		// that productId).
		$items      = $order->get_items();
		$by_product = array();
		foreach ( $items as $item ) {
			$pid = method_exists( $item, 'get_product_id' ) ? $item->get_product_id() : null;
			if ( ! isset( $by_product[ $pid ] ) ) {
				$by_product[ $pid ] = array();
			}
			$by_product[ $pid ][] = $item;
		}

		$recalc = false;
		foreach ( $line_items as $li ) {
			if ( ! array_key_exists( 'priceOverride', $li ) ) {
				continue;
			}
			$pid = $li['productId'] ?? null;
			if ( ! isset( $by_product[ $pid ] ) ) {
				throw new Exception( sprintf( 'priceOverride for productId %s does not match any order line', $pid ) );
			}
			if ( count( $by_product[ $pid ] ) > 1 ) {
				throw new Exception( sprintf( 'priceOverride for productId %s is ambiguous (%d order lines share it)', $pid, count( $by_product[ $pid ] ) ) );
			}
			$item           = $by_product[ $pid ][0];
			$override_total = (float) $li['priceOverride'] * (int) ( $item->get_quantity() ? $item->get_quantity() : ( $li['quantity'] ?? 1 ) );
			if ( method_exists( $item, 'set_subtotal' ) ) {
				$item->set_subtotal( $override_total );
			}
			if ( method_exists( $item, 'set_total' ) ) {
				$item->set_total( $override_total );
			}
			if ( method_exists( $item, 'save' ) ) {
				$item->save();
			}
			$recalc = true;
		}

		if ( $recalc ) {
			// Recompute the order total from the overridden line totals WITHOUT
			// calling calculate_totals() again (which would revert overrides).
			$sum = 0;
			foreach ( $order->get_items() as $item ) {
				$sum += (float) $item->get_total();
			}
			if ( method_exists( $order, 'set_total' ) ) {
				$order->set_total( $sum );
			}
		}

		if ( ! empty( $args['note'] ) ) {
			$order->add_order_note( $args['note'] );
		}

		$status = $args['status'] ?? 'processing';
		$order->set_status( $status );
		$order->save();

		$line_projection = array_map(
			function ( $item ) {
				return array(
					'productId' => $item->get_product_id(),
					'name'      => $item->get_name(),
					'quantity'  => $item->get_quantity(),
					'total'     => $item->get_total(),
				);
			},
			$order->get_items()
		);

		return array(
			'result' => array(
				'order' => array(
					'id'        => $order->get_id(),
					'number'    => $order->get_order_number(),
					'status'    => $order->get_status(),
					'total'     => $order->get_total(),
					'lineItems' => $line_projection,
				),
			),
		);
	}

	// -------------------------------------------------------------------------
	// Handlers — Customer Writes
	// -------------------------------------------------------------------------

	/**
	 * Handler: delete_customer — delete a WP user that MUST hold the customer
	 * role. Admins and shop-managers are explicitly refused (never deleted),
	 * regardless of who authorized the command.
	 *
	 * Orders are retained (wp_delete_user's default reassigns their authorship
	 * rather than destroying order history).
	 *
	 * @param array $args {customerId? or email}
	 */
	private function handle_delete_customer( $args, $command_id ) {
		$this->require_woocommerce();

		$customer_id = $args['customerId'] ?? null;
		$email       = $args['email'] ?? null;

		if ( ! $customer_id && ! $email ) {
			throw new Exception( 'delete_customer requires customerId or email' );
		}

		$user = null;
		if ( $customer_id ) {
			$user = function_exists( 'get_userdata' ) ? get_userdata( $customer_id ) : null;
		} else {
			$user = function_exists( 'get_user_by' ) ? get_user_by( 'email', $email ) : null;
		}

		if ( ! $user ) {
			throw new Exception( 'Customer not found' );
		}

		// Role enforcement: a deletable user must hold the customer role —
		// AND ONLY that role. WooCommerce adds the customer role to
		// administrators who place orders, so a mere membership check
		// (in_array) would let a multi-role admin (customer+administrator)
		// through. Require customer to be the ONLY role, and surface the
		// actual roles on refusal so the operator can see what blocked it.
		$roles = isset( $user->roles ) ? array_values( (array) $user->roles ) : array();
		if ( array( 'customer' ) !== $roles ) {
			$role_label = ! empty( $roles ) ? implode( ',', $roles ) : 'unknown';
			throw new Exception( sprintf( 'Refusing to delete non-customer user (roles: %s)', $role_label ) );
		}

		if ( ! function_exists( 'wp_delete_user' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}
		$ok = wp_delete_user( $user->ID );
		if ( ! $ok ) {
			throw new Exception( 'wp_delete_user failed' );
		}

		return array(
			'result' => array(
				'deleted'        => true,
				'customerId'     => $user->ID,
				'ordersRetained' => true,
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

	/**
	 * Serialize a WC_Coupon to the projection shared by get_coupon / list_coupons /
	 * sync_coupons.
	 *
	 * dateExpires is tolerant: WC_Coupon::get_date_expires() returns a
	 * WC_DateTime|null in modern WC, but historically returned a timestamp.
	 */
	private function serialize_coupon( $coupon ) {
		$expires_raw = method_exists( $coupon, 'get_date_expires' ) ? $coupon->get_date_expires() : null;
		$date_expires = null;
		if ( $expires_raw ) {
			if ( is_object( $expires_raw ) && method_exists( $expires_raw, 'date' ) ) {
				$date_expires = $expires_raw->date( 'c' );
			} else {
				$date_expires = date( 'c', (int) $expires_raw );
			}
		}

		return array(
			'id'           => $coupon->get_id(),
			'code'         => $coupon->get_code(),
			'discountType' => $coupon->get_discount_type(),
			'amount'       => $coupon->get_amount(),
			'status'       => $coupon->get_status(),
			'dateExpires'  => $date_expires,
			'usageCount'   => $coupon->get_usage_count(),
			'usageLimit'   => $coupon->get_usage_limit(),
			'freeShipping' => (bool) $coupon->get_free_shipping(),
			'productIds'   => $coupon->get_product_ids(),
		);
	}

	/**
	 * Map a camelCase address payload to the snake_case keys WC_Order::set_address
	 * expects ('first_name', 'address_1', etc.). Accepts both shapes.
	 *
	 * @param array $address
	 * @return array
	 */
	private function map_address( $address ) {
		$keys = array(
			'firstName' => 'first_name',
			'lastName'  => 'last_name',
			'company'   => 'company',
			'address1'  => 'address_1',
			'address2'  => 'address_2',
			'city'      => 'city',
			'state'     => 'state',
			'postcode'  => 'postcode',
			'country'   => 'country',
			'phone'     => 'phone',
			'email'     => 'email',
		);

		$out = array();
		foreach ( $keys as $camel => $snake ) {
			if ( isset( $address[ $camel ] ) ) {
				$out[ $snake ] = $address[ $camel ];
			} elseif ( isset( $address[ $snake ] ) ) {
				$out[ $snake ] = $address[ $snake ];
			}
		}
		return $out;
	}
}

/**
 * Custom exception for when a required plugin (WC, WC Subscriptions) is not active.
 */
class Felix_Plugin_Not_Active_Exception extends Exception {
}

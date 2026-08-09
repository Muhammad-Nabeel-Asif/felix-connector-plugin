<?php
/**
 * Test bootstrap for Felix Connector behavioral tests.
 *
 * Provides a minimal, deterministic WordPress shim so the plugin's pure-PHP
 * classes (crypto, ledger, handlers, processor, REST) can be exercised
 * without a WordPress or MySQL installation.
 *
 * The centerpiece is FakeWPDB: an in-memory database that emulates the
 * PRIMARY KEY uniqueness and WHERE-clause semantics the ledger relies on for
 * its atomic reservation. This is what lets the tests prove the
 * exactly-once / never-steal / reserved→terminal behavior deterministically.
 *
 * @package FelixConnector
 */

// Pretend we are inside WordPress.
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/../' );
}

// --- Plugin constants (mirror felix-connector.php) ---------------------------
define( 'FELIX_CONNECTOR_VERSION', '0.4.1' );
define( 'FELIX_CONNECTOR_PLUGIN_FILE', __FILE__ );
define( 'FELIX_CONNECTOR_PLUGIN_DIR', __DIR__ . '/../' );
define( 'FELIX_CONNECTOR_PLUGIN_URL', '' );

define( 'FELIX_OPT_STORE_ID', 'felix_store_id' );
define( 'FELIX_OPT_GENERATION', 'felix_generation' );
define( 'FELIX_OPT_PAIRED', 'felix_paired' );
define( 'FELIX_OPT_HOST_PROFILE', 'felix_host_profile' );
define( 'FELIX_OPT_KEY_MANIFEST', 'felix_key_manifest' );
define( 'FELIX_OPT_PLUGIN_KEYPAIR', 'felix_plugin_keypair' );
define( 'FELIX_OPT_POLL_ENDPOINT', 'felix_poll_endpoint' );
define( 'FELIX_OPT_RESULT_ENDPOINT', 'felix_result_endpoint' );
define( 'FELIX_OPT_PUSH_ENDPOINT', 'felix_push_endpoint' );
define( 'FELIX_OPT_KILL_SWITCHES', 'felix_kill_switches' );
define( 'FELIX_OPT_RUNNER_HEARTBEAT', 'felix_runner_heartbeat' );
define( 'FELIX_OPT_RUNNER_LEASE', 'felix_runner_lease' );
define( 'FELIX_OPT_SEEN_NONCES', 'felix_seen_nonces' );
define( 'FELIX_OPT_LIVENESS_STATE', 'felix_liveness_state' );

if ( ! defined( 'FELIX_API_BASE' ) ) {
	define( 'FELIX_API_BASE', 'https://api.test.local' );
}
if ( ! defined( 'FELIX_PROTOCOL_VERSION' ) ) {
	define( 'FELIX_PROTOCOL_VERSION', 2 );
}

// Mirror felix-connector.php pairing-code format constants.
if ( ! defined( 'FELIX_PAIRING_CODE_LENGTH' ) ) {
	define( 'FELIX_PAIRING_CODE_LENGTH', 8 );
}
if ( ! defined( 'FELIX_PAIRING_CODE_ALPHABET' ) ) {
	define( 'FELIX_PAIRING_CODE_ALPHABET', 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' );
}

// --- Global mutable test state ----------------------------------------------
$GLOBALS['__felix_options']      = array();
$GLOBALS['__felix_handler_calls'] = 0;

// --- WordPress function shims ------------------------------------------------

function get_option( $key, $default = false ) {
	if ( array_key_exists( $key, $GLOBALS['__felix_options'] ) ) {
		return $GLOBALS['__felix_options'][ $key ];
	}
	return $default;
}

function update_option( $key, $value, $autoload = null ) {
	$GLOBALS['__felix_options'][ $key ] = $value;
	return true;
}

function delete_option( $key ) {
	unset( $GLOBALS['__felix_options'][ $key ] );
	return true;
}

/**
 * wp_json_encode shim — MUST match production WordPress behavior: json_encode
 * with DEFAULT flags (escapes forward slashes as \/ and non-ASCII as \uXXXX).
 * The canonical JSON signature contract (#4) depends on this exact escaping;
 * a test-only JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE override would mask
 * the real cross-language byte contract and let a signature bug pass tests.
 */
function wp_json_encode( $data, $options = 0, $depth = 512 ) {
	return json_encode( $data, (int) $options, $depth );
}

function wp_salt( $scheme = 'auth' ) {
	return 'felix-test-salt-' . $scheme;
}

function current_time( $type = 'mysql' ) {
	if ( 'c' === $type ) {
		return date( 'c' );
	}
	return date( 'Y-m-d H:i:s' );
}

/**
 * get_bloginfo is also a handler-execution canary: ping calls it, so the test
 * suite uses the call counter to prove a handler did (or did not) run.
 */
function get_bloginfo( $show = '' ) {
	if ( 'version' === $show ) {
		$GLOBALS['__felix_handler_calls']++;
		return '6.5-test';
	}
	return '';
}

function wp_generate_uuid4() {
	$bytes = random_bytes( 16 );
	$bytes[6] = chr( ( ord( $bytes[6] ) & 0x0f ) | 0x40 );
	$bytes[8] = chr( ( ord( $bytes[8] ) & 0x3f ) | 0x80 );
	return vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split( bin2hex( $bytes ), 4 ) );
}

function __( $text, $domain = 'default' ) {
	return $text;
}
function esc_html( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES );
}
function esc_url( $url ) {
	return $url;
}
function admin_url( $path = '' ) {
	return 'http://test.local/wp-admin/' . $path;
}
function apply_filters( $tag, $value ) {
	return $value;
}
function add_action( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
	return true;
}
function add_filter( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
	return true;
}
function do_action( $tag, ...$args ) {
	return true;
}
function register_rest_route( $namespace, $route, $args = array(), $override = false ) {
	return true;
}
function is_wp_error( $thing ) {
	return $thing instanceof WP_Error;
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public $errors = array();
		public function __construct( $code = '', $message = '' ) {
			if ( $code ) {
				$this->errors[ $code ] = array( $message );
			}
		}
		public function get_error_message( $code = '' ) {
			$codes = array_keys( $this->errors );
			$code  = $code ? $code : ( $codes ? $codes[0] : '' );
			return $code && isset( $this->errors[ $code ][0] ) ? $this->errors[ $code ][0] : '';
		}
	}
}

if ( ! class_exists( 'WP_REST_Response' ) ) {
	class WP_REST_Response {
		public $data;
		public $status  = 200;
		public $headers = array();
		public function __construct( $data = null, $status = 200, $headers = array() ) {
			$this->data    = $data;
			$this->status  = $status;
			$this->headers = $headers;
		}
		public function get_data() {
			return $this->data;
		}
		public function get_status() {
			return $this->status;
		}
	}
}

// --- Deterministic in-memory $wpdb ------------------------------------------

if ( ! class_exists( 'FakeWPDB' ) ) {
	class FakeWPDB {

		public $prefix = 'wp_';
		public $last_error  = '';
		public $fail_updates = false; // Test toggle: make update() fail.

		/** @var array<string, array<int|string, stdClass>> table-suffix => rows keyed by id */
		private $tables = array();

		public function get_charset_collate() {
			return 'utf8mb4';
		}

		private function suffix( $table ) {
			if ( strpos( (string) $table, $this->prefix ) === 0 ) {
				return substr( (string) $table, strlen( $this->prefix ) );
			}
			return (string) $table;
		}

		private function &store_ref( $table ) {
			$sfx = $this->suffix( $table );
			if ( ! isset( $this->tables[ $sfx ] ) ) {
				$this->tables[ $sfx ] = array();
			}
			return $this->tables[ $sfx ];
		}

		public function prepare( $sql, ...$args ) {
			if ( empty( $args ) ) {
				return $sql;
			}
			$idx = 0;
			return preg_replace_callback(
				'/%([sdf])/',
				function ( $m ) use ( &$args, &$idx ) {
					$v = array_key_exists( $idx, $args ) ? $args[ $idx ] : '';
					$idx++;
					if ( 's' === $m[1] ) {
						return "'" . addslashes( (string) $v ) . "'";
					}
					return (string) (int) $v;
				},
				(string) $sql
			);
		}

		/**
		 * Emulate an INSERT honoring PRIMARY KEY (id) uniqueness.
		 */
		public function insert( $table, $data, $format = null ) {
			$this->last_error = '';
			$store            = &$this->store_ref( $table );
			$id               = array_key_exists( 'id', $data ) ? $data['id'] : null;

			if ( null !== $id && array_key_exists( $id, $store ) ) {
				$this->last_error = "Duplicate entry '" . addslashes( (string) $id ) . "' for key 'PRIMARY'";
				return false;
			}

			$row              = new stdClass();
			foreach ( (array) $data as $k => $v ) {
				$row->$k = $v;
			}
			$row->created_at = date( 'Y-m-d H:i:s' );
			$store[ $id ]    = $row;
			return 1;
		}

		/**
		 * Emulate UPDATE with a multi-column WHERE clause. Returns the number
		 * of matched rows actually changed (respecting the status='reserved'
		 * guard), or false on a simulated failure.
		 */
		public function update( $table, $data, $where, $format = null, $where_format = null ) {
			$this->last_error = '';
			if ( $this->fail_updates ) {
				$this->last_error = 'Simulated update failure';
				return false;
			}
			$sfx    = $this->suffix( $table );
			$store  = &$this->store_ref( $table );
			$matched = 0;
			foreach ( $store as $id => $row ) {
				$ok = true;
				foreach ( (array) $where as $wk => $wv ) {
					if ( ! isset( $row->$wk ) || (string) $row->$wk !== (string) $wv ) {
						$ok = false;
						break;
					}
				}
				if ( $ok ) {
					foreach ( (array) $data as $dk => $dv ) {
						$row->$dk = $dv;
					}
					$matched++;
				}
			}
			unset( $sfx );
			return $matched;
		}

		/**
		 * Parse "SELECT * FROM <table> WHERE id = '<id>'".
		 */
		public function get_row( $sql ) {
			$this->last_error = '';
			if ( preg_match( '/FROM\s+`?(\S+?)`?\s+WHERE\s+id\s*=\s*\'([^\']*)\'/i', (string) $sql, $m ) ) {
				$table = $m[1];
				$id    = $m[2];
				$store = &$this->store_ref( $table );
				return array_key_exists( $id, $store ) ? $store[ $id ] : null;
			}
			return null;
		}

		public function query( $sql ) {
			return 0;
		}

		// --- Test helpers ---------------------------------------------------

		public function seed_row( $table, $data ) {
			$store = &$this->store_ref( $table );
			$row   = new stdClass();
			foreach ( (array) $data as $k => $v ) {
				$row->$k = $v;
			}
			if ( ! isset( $row->created_at ) ) {
				$row->created_at = date( 'Y-m-d H:i:s' );
			}
			$store[ $row->id ] = $row;
		}

		public function get_row_raw( $table, $id ) {
			$store = &$this->store_ref( $table );
			return array_key_exists( $id, $store ) ? $store[ $id ] : null;
		}

		public function reset_all() {
			$this->tables      = array();
			$this->last_error  = '';
			$this->fail_updates = false;
		}
	}
}

$GLOBALS['wpdb'] = new FakeWPDB();

// --- WooCommerce + WP function/class shims for handler happy-path tests ------
// These emulate just enough of the WC + WP object API for the typed handlers
// to be exercised end-to-end without a WordPress/WooCommerce install. They are
// in-memory and deterministic; tests seed the $GLOBALS['__felix_*'] stores and
// call felix_reset_wc() between groups.
$GLOBALS['__felix_orders_meta']   = array(); // id => order state array
$GLOBALS['__felix_products_meta'] = array(); // id => product state array
$GLOBALS['__felix_coupons']       = array(); // id => coupon state array
$GLOBALS['__felix_coupon_code_index'] = array(); // lowercase code => id
$GLOBALS['__felix_coupon_posts']  = array(); // id => stdClass post (post_modified/post_date/post_title)
$GLOBALS['__felix_webhooks']      = array(); // id => webhook state array
$GLOBALS['__felix_users']         = array(); // id => WP_User
$GLOBALS['__felix_terms']         = array(); // post_id => taxonomy => terms[]
$GLOBALS['__felix_refunds']       = array(); // id => refund state array
$GLOBALS['__felix_next_id']       = array(
	'order'   => 1000,
	'product' => 2000,
	'coupon'  => 3000,
	'webhook' => 4000,
	'user'    => 5000,
	'refund'  => 6000,
);

/**
 * Reset all in-memory WooCommerce/WP state. Called by run.php reset_state().
 */
function felix_reset_wc() {
	$GLOBALS['__felix_orders_meta']       = array();
	$GLOBALS['__felix_products_meta']     = array();
	$GLOBALS['__felix_coupons']           = array();
	$GLOBALS['__felix_coupon_code_index'] = array();
	$GLOBALS['__felix_coupon_posts']      = array();
	$GLOBALS['__felix_webhooks']          = array();
	$GLOBALS['__felix_users']             = array();
	$GLOBALS['__felix_terms']             = array();
	$GLOBALS['__felix_refunds']           = array();
	$GLOBALS['__felix_next_id']           = array(
		'order'   => 1000,
		'product' => 2000,
		'coupon'  => 3000,
		'webhook' => 4000,
		'user'    => 5000,
		'refund'  => 6000,
	);
}

/**
 * Minimal WC_DateTime-like helper whose date() method mirrors the
 * WC_DateTime/WC_DateTime contract the production serializer relies on
 * ($order->get_date_created()->date( 'c' )).
 */
if ( ! class_exists( 'Felix_DateTime' ) ) {
	class Felix_DateTime {
		private $ts;
		public function __construct( $ts ) {
			$this->ts = (int) $ts;
		}
		public function date( $fmt ) {
			return date( $fmt, $this->ts );
		}
	}
}

// --- WP function shims -------------------------------------------------------

function get_user_by( $field, $value ) {
	foreach ( $GLOBALS['__felix_users'] as $u ) {
		if ( 'email' === $field && 0 === strcasecmp( $u->user_email, (string) $value ) ) {
			return $u;
		}
		if ( 'id' === $field && (int) $u->ID === (int) $value ) {
			return $u;
		}
	}
	return false;
}

function get_userdata( $id ) {
	return get_user_by( 'id', $id );
}

function wp_delete_user( $id, $reassign = null ) {
	if ( ! isset( $GLOBALS['__felix_users'][ (int) $id ] ) ) {
		return false;
	}
	unset( $GLOBALS['__felix_users'][ (int) $id ] );
	return true;
}

function get_the_terms( $post_id, $taxonomy ) {
	if ( isset( $GLOBALS['__felix_terms'][ (int) $post_id ][ $taxonomy ] ) ) {
		return $GLOBALS['__felix_terms'][ (int) $post_id ][ $taxonomy ];
	}
	return false;
}

if ( ! class_exists( 'WP_User' ) ) {
	class WP_User {
		public $ID;
		public $user_email;
		public $roles;
		public $display_name;
		public function __construct( $data = array() ) {
			foreach ( (array) $data as $k => $v ) {
				$this->$k = $v;
			}
			if ( ! isset( $this->roles ) ) {
				$this->roles = array();
			}
		}
	}
}

// --- WooCommerce function shims ----------------------------------------------

function wc_get_order( $the_order = false ) {
	$id = is_object( $the_order ) ? (int) $the_order->id : (int) $the_order;
	if ( ! $id || ! isset( $GLOBALS['__felix_orders_meta'][ $id ] ) ) {
		return false;
	}
	return new WC_Order( $id );
}

function wc_create_order( $args = array() ) {
	$id                                       = ++$GLOBALS['__felix_next_id']['order'];
	$GLOBALS['__felix_orders_meta'][ $id ]    = array(
		'status'         => 'processing',
		'total'          => 0,
		'total_refunded' => 0,
		'currency'       => 'USD',
		'number'         => (string) $id,
		'customer_id'    => 0,
		'created'        => time(),
		'items'          => array(),
		'billing'        => array(),
		'shipping'       => array(),
		'payment_method' => '',
	);
	return new WC_Order( $id );
}

function wc_create_refund( $args = array() ) {
	$order_id = (int) ( $args['order_id'] ?? 0 );
	$amount   = isset( $args['amount'] ) ? (float) $args['amount'] : 0.0;
	if ( ! isset( $GLOBALS['__felix_orders_meta'][ $order_id ] ) ) {
		return new WP_Error( 'felix_test_invalid_order', 'Order does not exist' );
	}
	if ( $amount <= 0 ) {
		return new WP_Error( 'felix_test_invalid_amount', 'Refund amount must be greater than zero' );
	}
	$GLOBALS['__felix_orders_meta'][ $order_id ]['total_refunded'] += $amount;
	$id                                 = ++$GLOBALS['__felix_next_id']['refund'];
	$GLOBALS['__felix_refunds'][ $id ]  = array(
		'id'      => $id,
		'amount'  => $amount,
		'reason'  => (string) ( $args['reason'] ?? '' ),
		'created' => time(),
	);
	return new WC_Order_Refund( $id );
}

function wc_get_product( $the_product = false ) {
	$id = is_object( $the_product ) ? (int) $the_product->get_id() : (int) $the_product;
	if ( ! $id || ! isset( $GLOBALS['__felix_products_meta'][ $id ] ) ) {
		return false;
	}
	return new WC_Product( $id );
}

function wc_get_product_id_by_sku( $sku ) {
	foreach ( $GLOBALS['__felix_products_meta'] as $id => $data ) {
		if ( (string) ( $data['sku'] ?? '' ) === (string) $sku ) {
			return $id;
		}
	}
	return 0;
}

function wc_get_products( $args = array() ) {
	$ids    = array_keys( $GLOBALS['__felix_products_meta'] );
	$status = $args['status'] ?? 'publish';
	if ( 'any' !== $status ) {
		$ids = array_filter(
			$ids,
			function ( $id ) use ( $status ) {
				return ( $GLOBALS['__felix_products_meta'][ $id ]['status'] ?? 'publish' ) === $status;
			}
		);
	}
	$limit = isset( $args['limit'] ) ? (int) $args['limit'] : 50;
	$page  = isset( $args['page'] ) ? max( (int) $args['page'], 1 ) : 1;
	$ids   = array_slice( $ids, ( $page - 1 ) * $limit, $limit );
	$out   = array();
	foreach ( $ids as $id ) {
		$out[] = new WC_Product( $id );
	}
	return $out;
}

function wc_sanitize_coupon_code( $code ) {
	return strtolower( (string) $code );
}

function wc_get_webhooks( $args = array() ) {
	$status = $args['status'] ?? 'any';
	$out    = array();
	foreach ( array_keys( $GLOBALS['__felix_webhooks'] ) as $id ) {
		$wh = new WC_Webhook( $id );
		if ( 'any' !== $status && $wh->get_status() !== $status ) {
			continue;
		}
		$out[] = $wh;
	}
	return $out;
}

// --- WooCommerce class shims -------------------------------------------------

if ( ! class_exists( 'WC_Order_Item_Product' ) ) {
	class WC_Order_Item_Product {
		private $data = array(
			'name'      => '',
			'productId' => 0,
			'quantity'  => 1,
			'subtotal'  => 0,
			'total'     => 0,
		);
		public function get_id() {
			return 0;
		}
		public function get_name() {
			return $this->data['name'];
		}
		public function get_product_id() {
			return $this->data['productId'];
		}
		public function get_quantity() {
			return $this->data['quantity'];
		}
		public function get_total() {
			return $this->data['total'];
		}
		public function set_name( $v ) {
			$this->data['name'] = $v;
		}
		public function set_product_id( $v ) {
			$this->data['productId'] = $v;
		}
		public function set_quantity( $v ) {
			$this->data['quantity'] = $v;
		}
		public function set_subtotal( $v ) {
			$this->data['subtotal'] = $v;
		}
		public function set_total( $v ) {
			$this->data['total'] = $v;
		}
		public function save() {
			return 0;
		}
	}
}

if ( ! class_exists( 'WC_Order_Refund' ) ) {
	class WC_Order_Refund {
		private $id;
		private $data;
		public function __construct( $id ) {
			$this->id   = (int) $id;
			$this->data = $GLOBALS['__felix_refunds'][ $this->id ] ?? array();
		}
		public function get_id() {
			return $this->id;
		}
		public function get_amount() {
			return $this->data['amount'] ?? 0;
		}
		public function get_reason() {
			return $this->data['reason'] ?? '';
		}
		public function get_date_created() {
			return new Felix_DateTime( $this->data['created'] ?? time() );
		}
	}
}

if ( ! class_exists( 'WC_Order' ) ) {
	class WC_Order {
		public $id = 0;
		private $status;
		private $total;
		private $total_refunded;
		private $currency;
		private $number;
		private $customer_id;
		private $items;
		private $billing;
		private $shipping;
		private $payment_method;
		private $created;

		public function __construct( $id = 0 ) {
			$this->id = (int) $id;
			$m        = isset( $GLOBALS['__felix_orders_meta'][ $this->id ] ) ? $GLOBALS['__felix_orders_meta'][ $this->id ] : array();
			$this->status         = $m['status'] ?? 'processing';
			$this->total          = $m['total'] ?? 0;
			$this->total_refunded = $m['total_refunded'] ?? 0;
			$this->currency       = $m['currency'] ?? 'USD';
			$this->number         = $m['number'] ?? (string) $this->id;
			$this->customer_id    = $m['customer_id'] ?? 0;
			$this->created        = $m['created'] ?? time();
			$this->items          = isset( $m['items'] ) ? $m['items'] : array();
			$this->billing        = isset( $m['billing'] ) ? $m['billing'] : array();
			$this->shipping       = isset( $m['shipping'] ) ? $m['shipping'] : array();
			$this->payment_method = $m['payment_method'] ?? '';
		}

		public function get_id() {
			return $this->id;
		}
		public function get_order_number() {
			return (string) $this->number;
		}
		public function get_status() {
			return $this->status;
		}
		public function get_total() {
			return (float) $this->total;
		}
		public function get_total_refunded() {
			return (float) $this->total_refunded;
		}
		public function get_currency() {
			return $this->currency;
		}
		public function get_customer_id() {
			return $this->customer_id;
		}
		public function get_payment_method() {
			return $this->payment_method;
		}
		public function get_payment_method_title() {
			return $this->payment_method;
		}
		public function get_date_created() {
			return new Felix_DateTime( $this->created );
		}
		public function get_date_paid() {
			return null;
		}
		public function get_billing_first_name() {
			return $this->billing['first_name'] ?? '';
		}
		public function get_billing_last_name() {
			return $this->billing['last_name'] ?? '';
		}
		public function get_billing_email() {
			return $this->billing['email'] ?? '';
		}
		public function get_billing_phone() {
			return $this->billing['phone'] ?? '';
		}
		public function get_billing_address_1() {
			return $this->billing['address_1'] ?? '';
		}
		public function get_billing_address_2() {
			return $this->billing['address_2'] ?? '';
		}
		public function get_billing_city() {
			return $this->billing['city'] ?? '';
		}
		public function get_billing_state() {
			return $this->billing['state'] ?? '';
		}
		public function get_billing_postcode() {
			return $this->billing['postcode'] ?? '';
		}
		public function get_billing_country() {
			return $this->billing['country'] ?? '';
		}
		public function get_shipping_first_name() {
			return $this->shipping['first_name'] ?? '';
		}
		public function get_shipping_last_name() {
			return $this->shipping['last_name'] ?? '';
		}
		public function get_shipping_address_1() {
			return $this->shipping['address_1'] ?? '';
		}
		public function get_shipping_address_2() {
			return $this->shipping['address_2'] ?? '';
		}
		public function get_shipping_city() {
			return $this->shipping['city'] ?? '';
		}
		public function get_shipping_state() {
			return $this->shipping['state'] ?? '';
		}
		public function get_shipping_postcode() {
			return $this->shipping['postcode'] ?? '';
		}
		public function get_shipping_country() {
			return $this->shipping['country'] ?? '';
		}
		public function get_items( $type = '' ) {
			return $this->items;
		}

		public function set_customer_id( $v ) {
			$this->customer_id = (int) $v;
		}
		public function set_status( $v ) {
			$this->status = $v;
		}
		public function set_total( $v ) {
			$this->total = (float) $v;
		}
		public function add_product( $product, $qty = 1 ) {
			$item = new WC_Order_Item_Product();
			$item->set_name( $product->get_name() );
			$item->set_product_id( $product->get_id() );
			$item->set_quantity( $qty );
			$line = (float) $product->get_price() * $qty;
			$item->set_subtotal( $line );
			$item->set_total( $line );
			$this->items[] = $item;
			return count( $this->items );
		}
		public function set_address( $address, $type = 'billing' ) {
			if ( 'shipping' === $type ) {
				$this->shipping = $address;
			} else {
				$this->billing = $address;
			}
		}
		public function calculate_totals() {
			$sum = 0;
			foreach ( $this->items as $item ) {
				$sum += (float) $item->get_total();
			}
			$this->total = (float) $sum;
		}
		public function add_order_note( $note ) {
			return true;
		}
		public function save() {
			$GLOBALS['__felix_orders_meta'][ $this->id ] = array(
				'status'         => $this->status,
				'total'          => $this->total,
				'total_refunded' => $this->total_refunded,
				'currency'       => $this->currency,
				'number'         => $this->number,
				'customer_id'    => $this->customer_id,
				'created'        => $this->created,
				'items'          => $this->items,
				'billing'        => $this->billing,
				'shipping'       => $this->shipping,
				'payment_method' => $this->payment_method,
			);
			return $this->id;
		}
	}
}

if ( ! class_exists( 'WC_Product' ) ) {
	class WC_Product {
		private $id;
		private $data;
		public function __construct( $product = 0 ) {
			$this->id   = is_object( $product ) ? (int) $product->get_id() : (int) $product;
			$this->data = $GLOBALS['__felix_products_meta'][ $this->id ] ?? array();
		}
		public function get_id() {
			return $this->id;
		}
		public function get_name() {
			return $this->data['name'] ?? '';
		}
		public function get_slug() {
			return $this->data['slug'] ?? '';
		}
		public function get_status() {
			return $this->data['status'] ?? 'publish';
		}
		public function get_type() {
			return $this->data['type'] ?? 'simple';
		}
		public function get_price() {
			return isset( $this->data['price'] ) ? $this->data['price'] : '';
		}
		public function get_regular_price() {
			return $this->data['regularPrice'] ?? '';
		}
		public function get_sale_price() {
			return $this->data['salePrice'] ?? '';
		}
		public function get_sku() {
			return $this->data['sku'] ?? '';
		}
		public function get_manage_stock() {
			return $this->data['manageStock'] ?? false;
		}
		public function get_stock_status() {
			return $this->data['stockStatus'] ?? 'instock';
		}
		public function get_stock_quantity() {
			return $this->data['stockQuantity'] ?? null;
		}
		public function get_description() {
			return $this->data['description'] ?? '';
		}
		public function get_short_description() {
			return $this->data['shortDescription'] ?? '';
		}
		public function get_permalink() {
			return 'http://test.local/?p=' . $this->id;
		}
	}
}

if ( ! class_exists( 'WC_Coupon' ) ) {
	class WC_Coupon {
		private $id = 0;
		private $data = array();

		public function __construct( $code_or_id = 0 ) {
			$resolved = false;
			if ( is_int( $code_or_id ) || (string) (int) $code_or_id === (string) $code_or_id ) {
				$id = (int) $code_or_id;
				if ( $id && isset( $GLOBALS['__felix_coupons'][ $id ] ) ) {
					$this->id   = $id;
					$this->data = $GLOBALS['__felix_coupons'][ $id ];
					$resolved   = true;
				}
			}
			if ( ! $resolved && is_string( $code_or_id ) && '' !== $code_or_id ) {
				$code = wc_sanitize_coupon_code( $code_or_id );
				if ( isset( $GLOBALS['__felix_coupon_code_index'][ $code ] ) ) {
					$this->id   = $GLOBALS['__felix_coupon_code_index'][ $code ];
					$this->data = $GLOBALS['__felix_coupons'][ $this->id ];
				}
			}
		}

		public function get_id() {
			return $this->id;
		}
		public function get_code() {
			return $this->data['code'] ?? '';
		}
		public function get_discount_type() {
			return $this->data['discountType'] ?? 'fixed_cart';
		}
		public function get_amount() {
			return $this->data['amount'] ?? 0;
		}
		public function get_description() {
			return $this->data['description'] ?? '';
		}
		public function get_status() {
			return $this->data['status'] ?? 'publish';
		}
		public function get_date_expires() {
			$exp = $this->data['dateExpires'] ?? null;
			if ( null === $exp ) {
				return null;
			}
			return is_object( $exp ) ? $exp : new Felix_DateTime( $exp );
		}
		public function get_usage_count() {
			return $this->data['usageCount'] ?? 0;
		}
		public function get_usage_limit() {
			return $this->data['usageLimit'] ?? 0;
		}
		public function get_usage_limit_per_user() {
			return $this->data['usageLimitPerUser'] ?? 0;
		}
		public function get_individual_use() {
			return $this->data['individualUse'] ?? false;
		}
		public function get_free_shipping() {
			return $this->data['freeShipping'] ?? false;
		}
		public function get_product_ids() {
			return $this->data['productIds'] ?? array();
		}

		public function set_code( $v ) {
			$this->data['code'] = $v;
		}
		public function set_discount_type( $v ) {
			$this->data['discountType'] = $v;
		}
		public function set_amount( $v ) {
			$this->data['amount'] = $v;
		}
		public function set_description( $v ) {
			$this->data['description'] = $v;
		}
		public function set_date_expires( $v ) {
			$this->data['dateExpires'] = $v;
		}
		public function set_usage_limit( $v ) {
			$this->data['usageLimit'] = $v;
		}
		public function set_usage_limit_per_user( $v ) {
			$this->data['usageLimitPerUser'] = $v;
		}
		public function set_individual_use( $v ) {
			$this->data['individualUse'] = $v;
		}
		public function set_free_shipping( $v ) {
			$this->data['freeShipping'] = $v;
		}
		public function set_product_ids( $v ) {
			$this->data['productIds'] = $v;
		}

		public function save() {
			if ( ! $this->id ) {
				$this->id = ++$GLOBALS['__felix_next_id']['coupon'];
			}
			$GLOBALS['__felix_coupons'][ $this->id ]           = $this->data;
			$GLOBALS['__felix_coupon_code_index'][ $this->data['code'] ?? '' ] = $this->id;
			return $this->id;
		}
	}
}

if ( ! class_exists( 'WC_Webhook' ) ) {
	class WC_Webhook {
		private $id = 0;
		private $data = array(
			'name'         => '',
			'status'       => '',
			'topic'        => '',
			'delivery_url' => '',
			'secret'       => '',
			'api_version'  => 3,
		);

		public function __construct( $id = 0 ) {
			$this->id = (int) $id;
			if ( $this->id && isset( $GLOBALS['__felix_webhooks'][ $this->id ] ) ) {
				$this->data = $GLOBALS['__felix_webhooks'][ $this->id ];
			}
		}

		public function get_id() {
			return $this->id;
		}
		public function get_name() {
			return $this->data['name'];
		}
		public function get_topic() {
			return $this->data['topic'];
		}
		public function get_delivery_url() {
			return $this->data['delivery_url'];
		}
		public function get_status() {
			return $this->data['status'];
		}
		public function get_secret() {
			return $this->data['secret'];
		}
		public function get_api_version() {
			return $this->data['api_version'];
		}

		public function set_name( $v ) {
			$this->data['name'] = $v;
		}
		public function set_status( $v ) {
			$this->data['status'] = $v;
		}
		public function set_topic( $v ) {
			$this->data['topic'] = $v;
		}
		public function set_delivery_url( $v ) {
			$this->data['delivery_url'] = $v;
		}
		public function set_secret( $v ) {
			$this->data['secret'] = $v;
		}
		public function set_api_version( $v ) {
			$this->data['api_version'] = $v;
		}

		public function save() {
			if ( ! $this->id ) {
				$this->id = ++$GLOBALS['__felix_next_id']['webhook'];
			}
			$GLOBALS['__felix_webhooks'][ $this->id ] = $this->data;
			return $this->id;
		}

		public function delete( $force_delete = false ) {
			unset( $GLOBALS['__felix_webhooks'][ $this->id ] );
			$this->id = 0;
			return true;
		}
	}
}

if ( ! class_exists( 'WP_Query' ) ) {
	class WP_Query {
		public $posts       = array();
		public $found_posts = 0;
		public $post_count  = 0;

		public function __construct( $args = array() ) {
			$type = $args['post_type'] ?? 'post';
			if ( 'shop_coupon' !== $type ) {
				return;
			}
			$all = array_values( $GLOBALS['__felix_coupon_posts'] );

			// date_query (after on post_modified).
			if ( isset( $args['date_query'] ) && is_array( $args['date_query'] ) ) {
				foreach ( $args['date_query'] as $dq ) {
					if ( isset( $dq['after'] ) ) {
						$after_ts = strtotime( $dq['after'] );
						$col      = ( $dq['column'] ?? 'post_modified' ) === 'post_modified' ? 'post_modified' : 'post_date';
						if ( $after_ts ) {
							$all = array_filter(
								$all,
								function ( $p ) use ( $after_ts, $col ) {
									return strtotime( $p->$col ) > $after_ts;
								}
							);
						}
					}
				}
			}

			if ( isset( $args['s'] ) && '' !== $args['s'] ) {
				$s = strtolower( (string) $args['s'] );
				$all = array_filter(
					$all,
					function ( $p ) use ( $s ) {
						return false !== strpos( strtolower( $p->post_title ), $s );
					}
				);
			}

			$orderby = $args['orderby'] ?? 'date';
			$order   = strtoupper( $args['order'] ?? 'DESC' );
			$col     = 'modified' === $orderby ? 'post_modified' : 'post_date';
			usort(
				$all,
				function ( $a, $b ) use ( $col, $order ) {
					$cmp = strcmp( $a->$col, $b->$col );
					return 'ASC' === $order ? $cmp : -$cmp;
				}
			);

			$this->found_posts = count( $all );
			$per_page          = (int) ( $args['posts_per_page'] ?? 20 );
			$page              = max( (int) ( $args['paged'] ?? 1 ), 1 );
			$this->posts       = array_slice( $all, ( $page - 1 ) * $per_page, $per_page );
			$this->post_count  = count( $this->posts );
		}
	}
}

// --- Load the plugin classes under test --------------------------------------
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-crypto.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-pairing.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-settings.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-ledger.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-handlers.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-processor.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-rest.php';

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
define( 'FELIX_CONNECTOR_VERSION', '0.4.0' );
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

// --- Load the plugin classes under test --------------------------------------
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-crypto.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-pairing.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-ledger.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-handlers.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-command-processor.php';
require_once FELIX_CONNECTOR_PLUGIN_DIR . 'includes/class-felix-rest.php';

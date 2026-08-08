<?php
/**
 * Felix REST — inbound direct command delivery endpoint.
 *
 * Registers POST /wp-json/felix/v1/command, the second transport for command
 * delivery. Felix POSTs a signed command envelope here when the store has
 * advertised the `directCommandV1` capability; otherwise the legacy
 * outbound long-poll runner remains the only path.
 *
 * This endpoint is a thin transport: it reads the raw body, hands it to the
 * shared Felix_Command_Processor (the same pipeline the poll runner uses),
 * and returns the terminal envelope as the HTTP response. It NEVER re-posts
 * the result to /connector/result — the HTTP response IS the result.
 *
 * Authentication is the Ed25519 command signature verified inside the
 * processor. There is no separate bearer token; a request with a bad or
 * missing signature is rejected before any handler runs.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_REST {

	/** @var string REST route namespace. */
	const REST_NAMESPACE = 'felix/v1';

	/** @var string REST route path. */
	const COMMAND_ROUTE = '/command';

	/** @var Felix_Command_Processor */
	private $processor;

	/**
	 * Constructor — hooks into rest_api_init.
	 */
	public function __construct() {
		$this->processor = new Felix_Command_Processor();
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register the direct command route.
	 */
	public function register_routes() {
		register_rest_route(
			self::REST_NAMESPACE,
			self::COMMAND_ROUTE,
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'handle_command' ),
					'permission_callback' => array( $this, 'permission_check' ),
					'args'                => array(),
				),
			)
		);
	}

	/**
	 * Permission gate. We always allow the request to reach the callback —
	 * real authorization is the Ed25519 command signature verified by the
	 * processor. Returning true here is intentional and safe because an
	 * unsigned/tampered envelope is rejected before any side effect.
	 *
	 * Kept as a named method so the capability advertisement (poll headers)
	 * and the endpoint exposure stay in sync: the route is only meaningful
	 * once the store is paired, but we do not 404 pre-pairing to avoid
	 * leaking pairing state to unauthenticated callers.
	 *
	 * @return bool
	 */
	public function permission_check() {
		return true;
	}

	/**
	 * Handle POST /wp-json/felix/v1/command.
	 *
	 * @param WP_REST_Request $request
	 * @return WP_REST_Response
	 */
	public function handle_command( $request ) {
		// Do not reveal the endpoint on an unpaired store.
		if ( ! Felix_Pairing::is_paired() ) {
			return new WP_REST_Response(
				array(
					'error' => array(
						'code'    => 'not_paired',
						'message' => 'Store is not paired',
					),
				),
				404
			);
		}

		$raw_body = $request->get_body();

		// Reject obviously-malformed payloads up front so we never hand the
		// processor a non-array. Signature verification also needs the raw
		// bytes, so we keep $raw_body untouched.
		$command = json_decode( $raw_body, true );
		if ( ! is_array( $command ) || empty( $command['commandId'] ) ) {
			return new WP_REST_Response(
				array(
					'error' => array(
						'code'    => 'bad_envelope',
						'message' => 'Invalid command envelope',
					),
				),
				400
			);
		}

		// Delegate to the shared pipeline. The direct path does NOT post the
		// result anywhere — the HTTP response below IS the terminal result.
		$terminal = $this->processor->process( $raw_body, $command );

		return new WP_REST_Response( $terminal, $this->http_status_for( $terminal ) );
	}

	/**
	 * Map a terminal envelope to an HTTP status code.
	 *
	 *   done / failed / unconfirmed → 200 (the command was processed)
	 *   rejected (reservation_conflict) → 409 (in-flight elsewhere)
	 *   rejected (anything else)        → 422 (bad signature/auth/envelope)
	 *
	 * @param array $terminal
	 * @return int
	 */
	private function http_status_for( $terminal ) {
		$status = isset( $terminal['status'] ) ? $terminal['status'] : '';
		$code   = isset( $terminal['error']['code'] ) ? $terminal['error']['code'] : '';

		if ( 'rejected' === $status ) {
			return ( 'reservation_conflict' === $code ) ? 409 : 422;
		}

		return 200;
	}
}

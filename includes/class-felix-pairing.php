<?php
/**
 * Felix Pairing — handles the outbound pairing flow.
 *
 * Most pairing logic lives in Felix_Settings::handle_pair() since it's
 * triggered from the settings form. This class provides helper utilities.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_Pairing {

	/**
	 * Check if the store is paired.
	 *
	 * @return bool
	 */
	public static function is_paired() {
		return (bool) get_option( FELIX_OPT_PAIRED, false );
	}

	/**
	 * Get the current pairing generation.
	 *
	 * @return int
	 */
	public static function get_generation() {
		return (int) get_option( FELIX_OPT_GENERATION, 0 );
	}

	/**
	 * Get the store ID.
	 *
	 * @return string|null
	 */
	public static function get_store_id() {
		$id = get_option( FELIX_OPT_STORE_ID, '' );
		return ! empty( $id ) ? $id : null;
	}

	/**
	 * Get the plugin's keypair from storage.
	 *
	 * @return array{publicKey: string, publicKeyHex: string, encryptedSecret: string}
	 */
	public static function get_keypair() {
		return get_option( FELIX_OPT_PLUGIN_KEYPAIR, array() );
	}
}

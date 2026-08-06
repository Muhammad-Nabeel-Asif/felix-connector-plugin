<?php
/**
 * Felix Crypto — Ed25519 signing and verification utilities.
 *
 * Uses libsodium (built into PHP 7.2+). The plugin generates its own Ed25519
 * keypair at activation. The private key never leaves the store. Felix stores
 * only the public key.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_Crypto {

	/**
	 * Generate an Ed25519 keypair.
	 *
	 * Returns array with 'publicKey' (hex) and 'secretKey' (hex, stored encrypted).
	 *
	 * @return array{publicKey: string, secretKey: string}
	 */
// generate_keypair() removed — use generate_identity() instead.

	/**
	 * Generate an Ed25519 identity keypair.
	 *
	 * @return array{publicKey: string, publicKeyHex: string, encryptedSecret: string}
	 */
	public static function generate_identity() {
		$keypair    = sodium_crypto_sign_keypair();
		$public_key = sodium_crypto_sign_publickey( $keypair );
		$secret_key = sodium_crypto_sign_secretkey( $keypair );

		$public_hex = sodium_bin2hex( $public_key );
		$secret_hex = sodium_bin2hex( $secret_key );

		// For sending to Felix: base64-encoded raw public key bytes.
		$public_b64 = base64_encode( $public_key );

		// Encrypt secret for at-rest storage.
		$encrypted_secret = self::encrypt_local( $secret_hex );

		// Clean sensitive data from memory.
		sodium_memzero( $keypair );
		sodium_memzero( $public_key );
		sodium_memzero( $secret_key );
		sodium_memzero( $secret_hex );

		return array(
			'publicKey'       => 'ed25519:' . $public_b64,
			'publicKeyHex'    => $public_hex,
			'encryptedSecret' => $encrypted_secret,
		);
	}

	/**
	 * Decrypt the secret key from storage.
	 *
	 * @param string $encrypted The encrypted secret.
	 * @return string The raw secret key bytes (32 bytes for Ed25519).
	 */
	public static function get_secret_key( $encrypted ) {
		$decrypted_hex = self::decrypt_local( $encrypted );
		if ( $decrypted_hex === false ) {
			return false;
		}
		$raw = sodium_hex2bin( $decrypted_hex );
		sodium_memzero( $decrypted_hex );
		return $raw;
	}

	/**
	 * Sign a message with the plugin's private key.
	 *
	 * @param string $message      Raw bytes to sign.
	 * @param string $secret_key   Raw secret key bytes (from get_secret_key).
	 * @return string              base64-encoded signature, prefixed with 'ed25519:'.
	 */
	public static function sign( $message, $secret_key ) {
		$signature = sodium_crypto_sign_detached( $message, $secret_key );
		$sig_b64   = base64_encode( $signature );
		sodium_memzero( $signature );
		return 'ed25519:' . $sig_b64;
	}

	/**
	 * Verify an Ed25519 signature.
	 *
	 * @param string $message       Raw bytes that were signed.
	 * @param string $signature_b64 base64-encoded signature (with or without 'ed25519:' prefix).
	 * @param string $public_key_b64 base64-encoded public key.
	 * @return bool
	 */
	public static function verify( $message, $signature_b64, $public_key_b64 ) {
		// Strip prefix if present.
		$sig_b64 = self::strip_prefix( $signature_b64, 'ed25519:' );
		$pub_b64 = self::strip_prefix( $public_key_b64, 'ed25519:' );

		$sig_raw = base64_decode( $sig_b64, true );
		$pub_raw = base64_decode( $pub_b64, true );

		if ( $sig_raw === false || $pub_raw === false ) {
			return false;
		}

		if ( strlen( $sig_raw ) !== SODIUM_CRYPTO_SIGN_BYTES ) {
			return false;
		}

		if ( strlen( $pub_raw ) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ) {
			return false;
		}

		$result = sodium_crypto_sign_verify_detached( $sig_raw, $message, $pub_raw );

		sodium_memzero( $sig_raw );
		sodium_memzero( $pub_raw );

		return $result;
	}

	/**
	 * Verify a command envelope's signature.
	 *
	 * The signature is over the raw JSON body bytes with the "signature" field's
	 * value replaced by 64 zero bytes (stable position, no re-serialization needed).
	 *
	 * @param string $raw_body     The raw HTTP response body bytes.
	 * @param string $signature_b64 The signature value from the JSON (base64, ed25519-prefixed).
	 * @param string $public_key_b64 The signer's public key (base64, ed25519-prefixed).
	 * @return bool
	 */
	public static function verify_command_signature( $raw_body, $signature_b64, $public_key_b64 ) {
		// The signed bytes are the raw body with the signature VALUE replaced by 64 zero bytes.
		// The signature field value is a JSON string like "ed25519:base64data".
		// We replace that string's content with 64 zero bytes (the raw signature size).
		// In practice: the signature field in JSON is a quoted string. We find it and replace
		// the base64 content with a fixed-length placeholder of the same byte length.

		// Strategy: extract the signature from JSON, then reconstruct the signed payload
		// by replacing the signature value in the raw body with the zero-byte placeholder.
		$sig_value = $signature_b64; // e.g. "ed25519:AAAA..."

		// The signed body = raw body with the signature string value replaced by 64 \0 bytes.
		// Since JSON serializes the signature as a string, we need to replace the string
		// value in the raw bytes. We use the known pattern: "signature":"ed25519:..."
		$zeroed = str_repeat( "\x00", 64 );

		// Replace the signature value in the raw body. The value is a JSON string,
		// so it appears as: "signature":"<value>" in the body.
		// We match the signature value and replace it with the zeroed bytes.
		$pattern      = '/"signature"\s*:\s*"[^"]*"/';
		$replacement  = '"signature":"' . $zeroed . '"';
		$signed_bytes = preg_replace( $pattern, $replacement, $raw_body, 1 );

		if ( $signed_bytes === null || $signed_bytes === $raw_body ) {
			// Pattern didn't match — the signature field wasn't found.
			return false;
		}

		return self::verify( $signed_bytes, $signature_b64, $public_key_b64 );
	}

	/**
	 * Encrypt a value for local at-rest storage using WP salt.
	 *
	 * Uses AES-256-CTR with the WP auth salt as key material.
	 * Not designed to resist a full server compromise (the key is on the same host),
	 * but protects the secret in DB dumps and backups.
	 *
	 * @param string $plaintext
	 * @return string
	 */
	private static function encrypt_local( $plaintext ) {
		$key    = hash( 'sha256', wp_salt( 'auth' ), true ); // 32 bytes.
		$iv     = random_bytes( 16 ); // AES-256-CTR IV = 16 bytes.
		$ct     = openssl_encrypt( $plaintext, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv );
		$result = base64_encode( $iv . $ct );

		sodium_memzero( $key );
		sodium_memzero( $iv );
		sodium_memzero( $ct );

		return $result;
	}

	/**
	 * Decrypt a locally encrypted value.
	 *
	 * @param string $ciphertext
	 * @return string|false
	 */
	private static function decrypt_local( $ciphertext ) {
		$raw = base64_decode( $ciphertext, true );
		if ( $raw === false || strlen( $raw ) < 17 ) {
			return false;
		}

		$iv = substr( $raw, 0, 16 );
		$ct = substr( $raw, 16 );

		$key     = hash( 'sha256', wp_salt( 'auth' ), true );
		$plaintext = openssl_decrypt( $ct, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv );

		sodium_memzero( $key );

		return $plaintext;
	}

	/**
	 * Strip a prefix from a string if present.
	 *
	 * @param string $value
	 * @param string $prefix
	 * @return string
	 */
	private static function strip_prefix( $value, $prefix ) {
		if ( strpos( $value, $prefix ) === 0 ) {
			return substr( $value, strlen( $prefix ) );
		}
		return $value;
	}

	/**
	 * Look up a public key from the key manifest by keyId.
	 *
	 * @param array  $manifest The key manifest stored at pairing.
	 * @param string $key_id   The keyId from the command envelope.
	 * @return string|null The base64 public key, or null if not found / expired.
	 */
	public static function lookup_key( $manifest, $key_id ) {
		if ( ! isset( $manifest['keys'] ) || ! is_array( $manifest['keys'] ) ) {
			return null;
		}

		$now = time();

		foreach ( $manifest['keys'] as $key ) {
			if ( ! isset( $key['keyId'] ) || $key['keyId'] !== $key_id ) {
				continue;
			}

			// Check validity window.
			if ( isset( $key['notBefore'] ) ) {
				$not_before = strtotime( $key['notBefore'] );
				if ( $not_before !== false && $now < $not_before ) {
					continue; // Key not yet valid.
				}
			}

			if ( isset( $key['notAfter'] ) && $key['notAfter'] !== null ) {
				$not_after = strtotime( $key['notAfter'] );
				if ( $not_after !== false && $now > $not_after ) {
					continue; // Key expired.
				}
			}

			return $key['publicKey'] ?? null;
		}

		return null;
	}
}

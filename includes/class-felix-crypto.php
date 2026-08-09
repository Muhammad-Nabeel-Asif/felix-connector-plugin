<?php
/**
 * Felix Crypto — Ed25519 signing and verification utilities.
 *
 * Uses libsodium (built into PHP 7.2+). The plugin generates its own Ed25519
 * keypair at activation. The private key never leaves the store. Felix stores
 * only the public key.
 *
 * Signing approach: the signature is computed over a canonical JSON string
 * with the "signature" field REMOVED entirely (not zeroed). This avoids
 * cross-language JSON canonicalization issues (null bytes, escaping order).
 * Both PHP and Node.js produce identical JSON when using json_encode /
 * JSON.stringify on an object without the signature field.
 *
 * @package FelixConnector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Felix_Crypto {

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
		$public_b64 = base64_encode( $public_key );

		$encrypted_secret = self::encrypt_local( $secret_hex );

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
	 * @param string $encrypted
	 * @return string|false Raw secret key bytes (64 bytes for Ed25519 secret).
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
	 * @param string $message    Raw bytes to sign.
	 * @param string $secret_key Raw secret key bytes.
	 * @return string            'ed25519:' + base64 signature.
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
	 * @param string $signature_b64 Signature (with or without 'ed25519:' prefix).
	 * @param string $public_key_b64 Public key (with or without 'ed25519:' prefix).
	 * @return bool
	 */
	public static function verify( $message, $signature_b64, $public_key_b64 ) {
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
	 * The signature is computed over the EXPLICIT recursive canonical JSON form
	 * (object keys sorted ascending, production wp_json_encode escaping: slashes
	 * escaped as \/, non-ASCII as \uXXXX) with the "signature" field REMOVED.
	 *
	 * This is the cross-language byte contract: the backend signs
	 * canonicalCommandJson() (Node) which sorts keys + escapes slashes/unicode
	 * to match wp_json_encode; the plugin reproduces the IDENTICAL bytes here by
	 * recursively ksort-ing the decoded structure then wp_json_encode-ing it.
	 * Signing raw JSON.stringify / wp_json_encode output (unsorted, or with
	 * differing slash/unicode escaping) would break verification whenever args
	 * contain a URL (slash) or non-ASCII text.
	 *
	 * @param string $raw_body      The raw HTTP response body.
	 * @param string $signature_b64  The signature value from the JSON.
	 * @param string $public_key_b64 The signer's public key.
	 * @return bool
	 */
	public static function verify_command_signature( $raw_body, $signature_b64, $public_key_b64 ) {
		$parsed = json_decode( $raw_body, true );
		if ( ! is_array( $parsed ) ) {
			return false;
		}

		// Remove the signature field.
		unset( $parsed['signature'] );

		// Canonical: recursively sorted object keys + wp_json_encode escaping
		// (slashes + unicode). MUST match the backend's canonicalCommandJson().
		$canonical = self::canonical_json( $parsed );
		if ( false === $canonical ) {
			return false;
		}

		return self::verify( $canonical, $signature_b64, $public_key_b64 );
	}

	/**
	 * Produce the recursive canonical JSON string for a value: object keys
	 * sorted ascending (SORT_STRING), arrays preserved in order, using
	 * wp_json_encode escaping (slashes → \/, non-ASCII → \uXXXX). This is the
	 * exact byte contract the backend's canonicalCommandJson() reproduces.
	 *
	 * @param mixed $data
	 * @return string|false
	 */
	public static function canonical_json( $data ) {
		return wp_json_encode( self::canonicalize( $data ) );
	}

	/**
	 * Recursively sort object keys of a decoded JSON structure. A JSON object
	 * (associative array) is ksort-ed; a JSON array (0-indexed) preserves order.
	 * Empty arrays are left as-is (wp_json_encode renders them as []).
	 *
	 * @param mixed $data
	 * @return mixed
	 */
	private static function canonicalize( $data ) {
		if ( ! is_array( $data ) ) {
			return $data;
		}
		if ( self::is_assoc_array( $data ) ) {
			ksort( $data, SORT_STRING );
		}
		foreach ( $data as $k => $v ) {
			$data[ $k ] = self::canonicalize( $v );
		}
		return $data;
	}

	/**
	 * True when $arr is an associative array (at least one non-sequential
	 * string key), i.e. a decoded JSON OBJECT (vs a JSON array).
	 *
	 * @param array $arr
	 * @return bool
	 */
	private static function is_assoc_array( $arr ) {
		if ( empty( $arr ) ) {
			return true; // empty → treated as object {} by canonical contract.
		}
		return array_keys( $arr ) !== range( 0, count( $arr ) - 1 );
	}

	/**
	 * Encrypt a value for local at-rest storage using WP salt + sodium.
	 *
	 * Uses sodium_crypto_secretbox (XSalsa20-Poly1305 AEAD) for authenticated
	 * encryption — an attacker modifying the DB value causes decryption to
	 * fail rather than producing a wrong key.
	 *
	 * @param string $plaintext
	 * @return string
	 */
	private static function encrypt_local( $plaintext ) {
		$key_material = hash( 'sha256', wp_salt( 'auth' ), true );
		$key          = sodium_crypto_generichash( '', $key_material, SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
		$nonce        = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

		$encrypted = sodium_crypto_secretbox( $plaintext, $nonce, $key );
		$result    = base64_encode( $nonce . $encrypted );

		sodium_memzero( $key );
		sodium_memzero( $key_material );
		sodium_memzero( $nonce );
		sodium_memzero( $encrypted );

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
		if ( $raw === false || strlen( $raw ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + 1 ) {
			return false;
		}

		$key_material = hash( 'sha256', wp_salt( 'auth' ), true );
		$key          = sodium_crypto_generichash( '', $key_material, SODIUM_CRYPTO_SECRETBOX_KEYBYTES );

		$nonce     = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$encrypted = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

		$plaintext = sodium_crypto_secretbox_open( $encrypted, $nonce, $key );

		sodium_memzero( $key );
		sodium_memzero( $key_material );
		sodium_memzero( $nonce );
		sodium_memzero( $encrypted );

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
	 * @param array  $manifest
	 * @param string $key_id
	 * @return string|null
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

			if ( isset( $key['notBefore'] ) ) {
				$not_before = strtotime( $key['notBefore'] );
				if ( $not_before !== false && $now < $not_before ) {
					continue;
				}
			}

			if ( isset( $key['notAfter'] ) && $key['notAfter'] !== null ) {
				$not_after = strtotime( $key['notAfter'] );
				if ( $not_after !== false && $now > $not_after ) {
					continue;
				}
			}

			return $key['publicKey'] ?? null;
		}

		return null;
	}
}

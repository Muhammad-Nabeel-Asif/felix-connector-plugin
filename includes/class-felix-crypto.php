<?php
/**
 * Felix Crypto — Ed25519 signing and verification utilities.
 *
 * Uses libsodium (built into PHP 7.2+). The plugin generates its own Ed25519
 * keypair at activation. The private key never leaves the store. Felix stores
 * only the public key.
 *
 * Signing approach: the signature is computed over a recursive canonical JSON
 * string (contract v2 — see CANONICAL_CONTRACT_VERSION) with the "signature"
 * field REMOVED entirely (not zeroed). The canonical form is built
 * byte-for-byte so PHP and Node.js agree across the known divergences: empty
 * object {} vs empty array [], exponent float formatting (1e-7 not 1.0e-7),
 * slash/unicode escaping, and key ordering. Non-finite numbers are rejected.
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
	 * Canonical JSON byte-contract version. MUST match the backend's
	 * CANONICAL_CONTRACT_VERSION. The cross-language signed fixture vector
	 * asserts equality so a silent drift fails tests on both sides.
	 */
	const CANONICAL_CONTRACT_VERSION = 2;

	/**
	 * Verify a command envelope's signature.
	 *
	 * The signature is computed over the EXPLICIT recursive canonical JSON form
	 * (contract v2) with the "signature" field REMOVED.
	 *
	 * The raw body is decoded with `json_decode( $raw, false )` so JSON objects
	 * arrive as stdClass and JSON arrays as PHP arrays — this PRESERVES
	 * object-vs-array identity. Decoding associatively (true) collapses both
	 * `{}` and `[]` to an empty PHP array, so an empty object the backend
	 * signed as `{}` would be re-canonicalized as `[]` and Ed25519
	 * verification would fail for every command whose args carry an empty
	 * object.
	 *
	 * @param string $raw_body      The raw HTTP response body.
	 * @param string $signature_b64  The signature value from the JSON.
	 * @param string $public_key_b64 The signer's public key.
	 * @return bool
	 */
	public static function verify_command_signature( $raw_body, $signature_b64, $public_key_b64 ) {
		$parsed = json_decode( $raw_body, false );
		if ( ! is_object( $parsed ) ) {
			return false;
		}

		// Remove the signature field (top-level property on the envelope object).
		unset( $parsed->signature );

		// Canonical: recursive object/array identity + sorted keys + slash/unicode
		// escaping + ECMAScript number formatting. MUST match the backend's
		// canonicalCommandJson() byte-for-byte.
		$canonical = self::canonical_json( $parsed );
		if ( false === $canonical ) {
			return false;
		}

		return self::verify( $canonical, $signature_b64, $public_key_b64 );
	}

	/**
	 * Produce the recursive canonical JSON string (contract v2) for a value.
	 *
	 * The string is BUILT BYTE-BY-BYTE (not via wp_json_encode of the whole
	 * structure) so that:
	 *  - Object-vs-array identity is preserved: stdClass / associative array →
	 *    object (empty → `{}`); sequential array → array (empty → `[]`).
	 *  - Finite numbers use the ECMAScript Number::toString form (matching the
	 *    backend's String(n)): `1e-7`, `1e+21`, `0.000001`, `42`, `-3.14`.
	 *    PHP's `1.0e-7` dtoa output is normalized to this exact form.
	 *  - Object keys are sorted ascending (SORT_STRING); arrays keep order.
	 *  - Strings are escaped via wp_json_encode (slashes → `\/`, non-ASCII →
	 *    `\uXXXX`), byte-identical to the backend encoder.
	 *  - Non-finite numbers (NaN / ±Infinity) cause a `false` return
	 *    (fail-closed: verification rejects, never verifies).
	 *
	 * @param mixed $data Decoded JSON value (stdClass/array/scalar).
	 * @return string|false false on a non-finite number (fail-closed).
	 */
	public static function canonical_json( $data ) {
		return self::encode_value( $data );
	}

	/**
	 * Recursively encode a decoded JSON value to canonical bytes.
	 *
	 * @param mixed $data
	 * @return string|false
	 */
	private static function encode_value( $data ) {
		if ( null === $data ) {
			return 'null';
		}
		if ( is_bool( $data ) ) {
			return $data ? 'true' : 'false';
		}
		if ( is_int( $data ) ) {
			return (string) $data;
		}
		if ( is_float( $data ) ) {
			return self::encode_float( $data );
		}
		if ( is_string( $data ) ) {
			return self::encode_string( $data );
		}
		if ( $data instanceof stdClass ) {
			return self::encode_object( (array) $data );
		}
		if ( is_array( $data ) ) {
			if ( self::is_sequential_list( $data ) ) {
				return self::encode_array( $data );
			}
			// Associative PHP array (e.g. a test-built envelope) → object.
			return self::encode_object( $data );
		}
		return 'null';
	}

	/**
	 * Encode a JSON object (stdClass or associative array): keys sorted
	 * ascending (SORT_STRING). Empty → `{}`.
	 *
	 * @param array $props
	 * @return string|false
	 */
	private static function encode_object( $props ) {
		ksort( $props, SORT_STRING );
		$parts = array();
		foreach ( $props as $k => $v ) {
			$encoded = self::encode_value( $v );
			if ( false === $encoded ) {
				return false;
			}
			$parts[] = self::encode_string( (string) $k ) . ':' . $encoded;
		}
		return '{' . implode( ',', $parts ) . '}';
	}

	/**
	 * Encode a JSON array (sequential list): order preserved. Empty → `[]`.
	 *
	 * @param array $items
	 * @return string|false
	 */
	private static function encode_array( $items ) {
		$parts = array();
		foreach ( $items as $item ) {
			$encoded = self::encode_value( $item );
			if ( false === $encoded ) {
				return false;
			}
			$parts[] = $encoded;
		}
		return '[' . implode( ',', $parts ) . ']';
	}

	/**
	 * Encode a JSON string with the byte-identical escaping the backend
	 * produces: `/` → `\/`, non-ASCII → `\uXXXX` (UTF-8 decoded to code
	 * points, supplementary as surrogate pairs), plus `"`, `\`, control chars.
	 * Delegated to wp_json_encode so multi-byte UTF-8 is handled correctly.
	 *
	 * @param string $s
	 * @return string
	 */
	private static function encode_string( $s ) {
		$encoded = wp_json_encode( (string) $s );
		if ( false === $encoded ) {
			return '""';
		}
		return $encoded;
	}

	/**
	 * Encode a finite float in the ECMAScript Number::toString byte form — the
	 * single cross-language numeric contract (matches the backend's String(n)).
	 * PHP's json_encode dtoa (serialize_precision = -1) gives the shortest
	 * round-tripping digits but a different FORMAT (e.g. `1.0e-7`, `1.0e+20`);
	 * this parses those digits into (sign, coefficient, decimal-exponent) and
	 * re-formats them through the ECMAScript algorithm so both languages emit
	 * identical bytes (e.g. `1e-7`, `100000000000000000000`).
	 *
	 * Non-finite (NaN / ±Infinity) → false (fail-closed).
	 *
	 * @param float $n
	 * @return string|false
	 */
	private static function encode_float( $n ) {
		if ( is_nan( $n ) || is_infinite( $n ) ) {
			return false;
		}
		if ( $n == 0.0 ) {
			return '0'; // +0.0 and -0.0 both canonicalize to "0".
		}
		$raw = json_encode( $n ); // shortest round-trip (serialize_precision = -1).
		if ( false === $raw ) {
			return '0';
		}
		return self::format_ecmascript_number( $raw );
	}

	/**
	 * Re-format a PHP decimal float string (`[-]d[.d][e[+-]d]`) into the
	 * ECMAScript Number::toString form. See ECMA-262 §6.1.6.1.20 / §7.1.12.1:
	 * given the shortest decimal digits `s` (length k) and decimal-point
	 * position n, the value s × 10^(n−k) is rendered as plain decimal where
	 * possible and exponential otherwise (lowercase `e` with explicit sign).
	 *
	 * @param string $raw e.g. "1.0e-7", "1.5e-7", "0.1", "-3.14", "100", "1.0e+20".
	 * @return string
	 */
	private static function format_ecmascript_number( $raw ) {
		$negative = ( '-' === $raw[0] );
		if ( $negative ) {
			$raw = substr( $raw, 1 );
		}

		// Split mantissa and exponent (case-insensitive 'e').
		$e_pos = stripos( $raw, 'e' );
		$exp   = 0;
		if ( false !== $e_pos ) {
			$mantissa = substr( $raw, 0, $e_pos );
			$exp      = (int) substr( $raw, $e_pos + 1 );
		} else {
			$mantissa = $raw;
		}

		// Split mantissa into integer/fractional digit strings.
		$dot_pos  = strpos( $mantissa, '.' );
		if ( false !== $dot_pos ) {
			$int_part  = substr( $mantissa, 0, $dot_pos );
			$frac_part = substr( $mantissa, $dot_pos + 1 );
		} else {
			$int_part  = $mantissa;
			$frac_part = '';
		}

		// Coefficient = all mantissa digits; decimal exponent compensates for
		// the fractional digits and the explicit exponent.
		$digits = $int_part . $frac_part;
		$decexp = $exp - strlen( $frac_part );

		// Strip insignificant leading zeros.
		$digits = ltrim( $digits, '0' );
		if ( '' === $digits ) {
			return '0';
		}
		// Strip trailing zeros (fold them into the decimal exponent).
		$len = strlen( $digits );
		while ( $len > 1 && '0' === $digits[ $len - 1 ] ) {
			$digits = substr( $digits, 0, -1 );
			++$decexp;
			--$len;
		}

		$k = strlen( $digits );
		$n = $decexp + $k; // decimal-point position (ECMAScript n).
		$sign = $negative ? '-' : '';

		if ( $k <= $n && $n <= 21 ) {
			// Integer with at most 21 digits: digits + trailing zeros.
			return $sign . $digits . str_repeat( '0', $n - $k );
		}
		if ( 0 < $n && $n <= 21 ) {
			// Fractional: digits[0..n-1] . digits[n..k-1].
			return $sign . substr( $digits, 0, $n ) . '.' . substr( $digits, $n );
		}
		if ( -6 < $n && $n <= 0 ) {
			// Small fraction: 0. + (-n zeros) + digits.
			return $sign . '0.' . str_repeat( '0', -$n ) . $digits;
		}

		// Exponential: d[.ddd]e[+-]ddd, exponent = n - 1.
		$mantissa_out = $digits[0];
		if ( $k > 1 ) {
			$mantissa_out .= '.' . substr( $digits, 1 );
		}
		$p         = $n - 1;
		$exp_sign = ( $p >= 0 ) ? '+' : '-';
		return $sign . $mantissa_out . 'e' . $exp_sign . (string) abs( $p );
	}

	/**
	 * True when $arr is a sequential (0-indexed) list, i.e. a decoded JSON
	 * ARRAY (vs a decoded JSON object, which arrives as stdClass). An empty
	 * array is a list → `[]`; an empty object arrives as stdClass → `{}`.
	 *
	 * @param array $arr
	 * @return bool
	 */
	private static function is_sequential_list( $arr ) {
		if ( empty( $arr ) ) {
			return true;
		}
		return array_keys( $arr ) === range( 0, count( $arr ) - 1 );
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

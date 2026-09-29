<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Handlers;

use PayloadShield\ComPHPPS\EncryptionHandlerInterface;
use PayloadShield\ComPHPPS\Internal\Hkdf;
use RuntimeException;

/**
 * Ephemeral-static ECDH (NIST P-256) key agreement + AES-256-GCM handler.
 *
 * A fresh EC key pair is generated per message; its private key is combined
 * with the recipient's static public key (ECDH) and the shared secret is
 * stretched via HKDF-SHA256 into an AES-256 key. Decryption reverses the
 * process using the static private key and the ephemeral public key.
 *
 * Requires "ECPublicKey" (encrypt) and "ECPrivateKey" (decrypt) to be set
 * via PayloadShieldEnc::init(['ECPublicKey' => ..., 'ECPrivateKey' => ...]).
 */
final class ECDHAESGCMEncryptionHandler implements EncryptionHandlerInterface
{
    private const NONCE_SIZE = 12;
    private const TAG_SIZE   = 16;
    private const HKDF_INFO  = 'ecdh-aes-gcm';

    public function encode(mixed $data, array $config = []): string
    {
        $publicKey = $this->loadPublicKey($config);

        // Generate an ephemeral EC key pair
        $ephemeralPrivate = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        if ($ephemeralPrivate === false) {
            throw new RuntimeException('Failed to generate ephemeral EC key');
        }

        // Derive shared secret via ECDH
        $sharedKey = openssl_pkey_derive($publicKey, $ephemeralPrivate);
        if ($sharedKey === false) {
            throw new RuntimeException('ECDH key agreement failed');
        }

        $aesKey = Hkdf::derive($sharedKey, 32, self::HKDF_INFO);
        $nonce  = random_bytes(self::NONCE_SIZE);
        $payload = (string) json_encode($data);

        $tag = '';
        $ciphertext = openssl_encrypt(
            $payload,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            self::TAG_SIZE
        );
        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt ecdh-aes-gcm payload');
        }

        // Export ephemeral public key PEM
        $ephemeralDetails = openssl_pkey_get_details($ephemeralPrivate);
        if ($ephemeralDetails === false) {
            throw new RuntimeException('Failed to export ephemeral public key');
        }

        openssl_pkey_export($ephemeralPrivate, $ephemeralPem);
        $ephemeralPub = openssl_pkey_get_details($ephemeralPrivate);
        $ephemeralPublicPem = $ephemeralPub['key'] ?? '';

        $bundle = [
            'ephemeral_public_key' => $ephemeralPublicPem,
            'nonce' => base64_encode($nonce),
            'data'  => base64_encode($ciphertext . $tag),
        ];
        return base64_encode((string) json_encode($bundle));
    }

    public function decode(string $encodedData, array $config = []): mixed
    {
        $privateKey = $this->loadPrivateKey($config);

        try {
            $bundle = json_decode(base64_decode($encodedData, true) ?: '', true);
            if (!is_array($bundle)) {
                throw new RuntimeException('invalid bundle format');
            }

            $ephemeralPublicPem = $bundle['ephemeral_public_key'];
            $nonce = base64_decode($bundle['nonce'], true);
            $raw   = base64_decode($bundle['data'], true);

            if ($nonce === false || $raw === false) {
                throw new RuntimeException('invalid base64 fields');
            }

            $ephemeralPublicKey = openssl_pkey_get_public($ephemeralPublicPem);
            if ($ephemeralPublicKey === false) {
                throw new RuntimeException('Failed to load ephemeral public key');
            }

            $sharedKey = openssl_pkey_derive($privateKey, $ephemeralPublicKey);
            if ($sharedKey === false) {
                throw new RuntimeException('ECDH key agreement failed');
            }

            $aesKey = Hkdf::derive($sharedKey, 32, self::HKDF_INFO);

            $ciphertext = substr($raw, 0, -self::TAG_SIZE);
            $tag        = substr($raw, -self::TAG_SIZE);

            $payload = openssl_decrypt($ciphertext, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $nonce, $tag);
            if ($payload === false) {
                throw new RuntimeException('AES-GCM decryption failed');
            }

            $result = json_decode($payload, true);
            if ($result === null && json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException(json_last_error_msg());
            }

            return $result;
        } catch (\Throwable $e) {
            throw new RuntimeException('Failed to decode ecdh-aes-gcm data: ' . $e->getMessage(), 0, $e);
        }
    }

    /** @return \OpenSSLAsymmetricKey */
    private function loadPublicKey(array $config): \OpenSSLAsymmetricKey
    {
        $pem = $config['ECPublicKey'] ?? null;
        if (!$pem) {
            throw new RuntimeException(
                "ECDH-AES-GCM encryption requires 'ECPublicKey' to be set via " .
                "PayloadShieldEnc::init(['ECPublicKey' => ...])"
            );
        }
        $key = openssl_pkey_get_public((string) $pem);
        if ($key === false) {
            throw new RuntimeException('Failed to load EC public key');
        }
        return $key;
    }

    /** @return \OpenSSLAsymmetricKey */
    private function loadPrivateKey(array $config): \OpenSSLAsymmetricKey
    {
        $pem = $config['ECPrivateKey'] ?? null;
        if (!$pem) {
            throw new RuntimeException(
                "ECDH-AES-GCM decryption requires 'ECPrivateKey' to be set via " .
                "PayloadShieldEnc::init(['ECPrivateKey' => ...])"
            );
        }
        $key = openssl_pkey_get_private((string) $pem);
        if ($key === false) {
            throw new RuntimeException('Failed to load EC private key');
        }
        return $key;
    }
}

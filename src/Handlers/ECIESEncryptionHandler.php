<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Handlers;

use PayloadShield\ComPHPPS\EncryptionHandlerInterface;
use PayloadShield\ComPHPPS\Internal\Hkdf;
use RuntimeException;

/**
 * Classic ECIES (SEC1-style) encryption handler.
 *
 * A fresh EC (P-256) key pair is generated per message and combined with
 * the recipient's static public key via ECDH. HKDF-SHA256 stretches the
 * shared secret into a 32-byte AES-256 encryption key and a 32-byte
 * HMAC-SHA256 MAC key; the payload is encrypted with AES-256-CTR and
 * authenticated with an encrypt-then-MAC tag over the IV and ciphertext.
 *
 * Requires "ECPublicKey" (encrypt) and "ECPrivateKey" (decrypt) to be set
 * via PayloadShieldEnc::init(['ECPublicKey' => ..., 'ECPrivateKey' => ...]).
 */
final class ECIESEncryptionHandler implements EncryptionHandlerInterface
{
    private const IV_SIZE   = 16;
    private const HKDF_INFO = 'ecies-encryption';

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

        [$encKey, $macKey] = $this->deriveKeys($sharedKey);

        $iv = random_bytes(self::IV_SIZE);
        $payload = (string) json_encode($data);

        $ciphertext = openssl_encrypt($payload, 'aes-256-ctr', $encKey, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt ecies payload');
        }

        $tag = hash_hmac('sha256', $iv . $ciphertext, $macKey, true);

        // Export ephemeral public key PEM
        $ephemeralPub = openssl_pkey_get_details($ephemeralPrivate);
        $ephemeralPublicPem = $ephemeralPub['key'] ?? '';

        $bundle = [
            'ephemeral_public_key' => $ephemeralPublicPem,
            'iv'   => base64_encode($iv),
            'data' => base64_encode($ciphertext),
            'tag'  => base64_encode($tag),
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
            $iv         = base64_decode($bundle['iv'], true);
            $ciphertext = base64_decode($bundle['data'], true);
            $tag        = base64_decode($bundle['tag'], true);

            if ($iv === false || $ciphertext === false || $tag === false) {
                throw new RuntimeException('invalid base64 fields');
            }

            $ephemeralPublicKey = openssl_pkey_get_public($ephemeralPublicPem);
            if ($ephemeralPublicKey === false) {
                throw new RuntimeException('Failed to load ephemeral public key');
            }

            $sharedKey = openssl_pkey_derive($ephemeralPublicKey, $privateKey);
            if ($sharedKey === false) {
                throw new RuntimeException('ECDH key agreement failed');
            }

            [$encKey, $macKey] = $this->deriveKeys($sharedKey);

            $expectedTag = hash_hmac('sha256', $iv . $ciphertext, $macKey, true);
            if (!hash_equals($expectedTag, $tag)) {
                throw new RuntimeException('MAC verification failed');
            }

            $payload = openssl_decrypt($ciphertext, 'aes-256-ctr', $encKey, OPENSSL_RAW_DATA, $iv);
            if ($payload === false) {
                throw new RuntimeException('AES-CTR decryption failed');
            }

            $result = json_decode($payload, true);
            if ($result === null && json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException(json_last_error_msg());
            }

            return $result;
        } catch (\Throwable $e) {
            throw new RuntimeException('Failed to decode ecies data: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Derive 32-byte encryption key + 32-byte MAC key from the shared secret.
     *
     * @return array{0: string, 1: string} [encKey, macKey]
     */
    private function deriveKeys(string $sharedKey): array
    {
        $derived = Hkdf::derive($sharedKey, 64, self::HKDF_INFO);
        return [substr($derived, 0, 32), substr($derived, 32, 32)];
    }

    /** @return \OpenSSLAsymmetricKey */
    private function loadPublicKey(array $config): \OpenSSLAsymmetricKey
    {
        $pem = $config['ECPublicKey'] ?? null;
        if (!$pem) {
            throw new RuntimeException(
                "ECIES encryption requires 'ECPublicKey' to be set via " .
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
                "ECIES decryption requires 'ECPrivateKey' to be set via " .
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

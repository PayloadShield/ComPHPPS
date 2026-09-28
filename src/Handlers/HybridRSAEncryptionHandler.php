<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Handlers;

use PayloadShield\ComPHPPS\EncryptionHandlerInterface;
use PayloadShield\ComPHPPS\Internal\Oaep;
use RuntimeException;

/**
 * Hybrid RSA+AES encryption handler.
 *
 * A random AES-256 key encrypts the payload (AES-GCM); the AES key itself
 * is encrypted with the RSA public key (RSA-OAEP/SHA-256). Decryption
 * reverses the process using the RSA private key.
 *
 * Requires "PublicKey" (encode) and "PrivateKey" (decode) to be set via
 * PayloadShieldEnc::init(['PublicKey' => ..., 'PrivateKey' => ...]).
 */
final class HybridRSAEncryptionHandler implements EncryptionHandlerInterface
{
    private const NONCE_SIZE = 12;
    private const TAG_SIZE   = 16;

    public function encode(mixed $data, array $config = []): string
    {
        $publicKey = $this->loadPublicKey($config);

        $aesKey = random_bytes(32);
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
            throw new RuntimeException('Failed to encrypt rsa-hybrid payload');
        }

        // RSA-OAEP-SHA256 encrypt the AES key
        $keyDetails = openssl_pkey_get_details($publicKey);
        if ($keyDetails === false) {
            throw new RuntimeException('Failed to read RSA public key details');
        }
        $modulusBytes = (int) ($keyDetails['bits'] / 8);
        $oaepEncoded  = Oaep::encode($aesKey, $modulusBytes);

        $encryptedKey = '';
        if (!openssl_public_encrypt($oaepEncoded, $encryptedKey, $publicKey, OPENSSL_NO_PADDING)) {
            throw new RuntimeException('RSA encryption failed');
        }

        $bundle = [
            'key'   => base64_encode($encryptedKey),
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

            $encryptedKey = base64_decode($bundle['key'], true);
            $nonce        = base64_decode($bundle['nonce'], true);
            $raw          = base64_decode($bundle['data'], true);

            if ($encryptedKey === false || $nonce === false || $raw === false) {
                throw new RuntimeException('invalid base64 fields');
            }

            // RSA-OAEP-SHA256 decrypt the AES key
            $keyDetails = openssl_pkey_get_details($privateKey);
            if ($keyDetails === false) {
                throw new RuntimeException('Failed to read RSA private key details');
            }
            $modulusBytes = (int) ($keyDetails['bits'] / 8);

            $decryptedOaep = '';
            if (!openssl_private_decrypt($encryptedKey, $decryptedOaep, $privateKey, OPENSSL_NO_PADDING)) {
                throw new RuntimeException('RSA decryption failed');
            }
            $aesKey = Oaep::decode($decryptedOaep, $modulusBytes);

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
            throw new RuntimeException('Failed to decode rsa-hybrid data: ' . $e->getMessage(), 0, $e);
        }
    }

    /** @return \OpenSSLAsymmetricKey */
    private function loadPublicKey(array $config): \OpenSSLAsymmetricKey
    {
        $pem = $config['PublicKey'] ?? null;
        if (!$pem) {
            throw new RuntimeException(
                "Hybrid RSA encryption requires 'PublicKey' to be set via " .
                "PayloadShieldEnc::init(['PublicKey' => ...])"
            );
        }
        $key = openssl_pkey_get_public((string) $pem);
        if ($key === false) {
            throw new RuntimeException('Failed to load RSA public key');
        }
        return $key;
    }

    /** @return \OpenSSLAsymmetricKey */
    private function loadPrivateKey(array $config): \OpenSSLAsymmetricKey
    {
        $pem = $config['PrivateKey'] ?? null;
        if (!$pem) {
            throw new RuntimeException(
                "Hybrid RSA decryption requires 'PrivateKey' to be set via " .
                "PayloadShieldEnc::init(['PrivateKey' => ...])"
            );
        }
        $key = openssl_pkey_get_private((string) $pem);
        if ($key === false) {
            throw new RuntimeException('Failed to load RSA private key');
        }
        return $key;
    }
}

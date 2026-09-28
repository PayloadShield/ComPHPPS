<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Handlers;

use PayloadShield\ComPHPPS\EncryptionHandlerInterface;
use RuntimeException;

/**
 * Fernet symmetric encryption handler (compatible with the `cryptography`
 * Python package's Fernet token format).
 * Requires "Key" to be set via PayloadShieldEnc::init(['Key' => ...]).
 */
final class FernetEncryptionHandler implements EncryptionHandlerInterface
{
    private const VERSION = "\x80";

    public function encode(mixed $data, array $config = []): string
    {
        [$signingKey, $encryptionKey] = $this->getKeyParts($config);

        $payload = (string) json_encode($data);
        $iv = random_bytes(16);
        $ciphertext = openssl_encrypt($payload, 'aes-128-cbc', $encryptionKey, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt fernet payload');
        }

        $timestamp = $this->packUint64(time());
        $signingInput = self::VERSION . $timestamp . $iv . $ciphertext;
        $hmac = hash_hmac('sha256', $signingInput, $signingKey, true);

        return $this->base64UrlEncode($signingInput . $hmac);
    }

    public function decode(string $encodedData, array $config = []): mixed
    {
        [$signingKey, $encryptionKey] = $this->getKeyParts($config);

        try {
            $token = $this->base64UrlDecode($encodedData);
            if (strlen($token) < 1 + 8 + 16 + 32) {
                throw new RuntimeException('token is too short');
            }

            $version = $token[0];
            $timestamp = substr($token, 1, 8);
            $iv = substr($token, 9, 16);
            $hmac = substr($token, -32);
            $ciphertext = substr($token, 25, -32);

            if ($version !== self::VERSION) {
                throw new RuntimeException('unsupported token version');
            }

            $signingInput = $version . $timestamp . $iv . $ciphertext;
            $expectedHmac = hash_hmac('sha256', $signingInput, $signingKey, true);
            if (!hash_equals($expectedHmac, $hmac)) {
                throw new RuntimeException('signature verification failed');
            }

            $payload = openssl_decrypt($ciphertext, 'aes-128-cbc', $encryptionKey, OPENSSL_RAW_DATA, $iv);
            if ($payload === false) {
                throw new RuntimeException('decryption failed');
            }

            $data = json_decode($payload, true);
            if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException(json_last_error_msg());
            }

            return $data;
        } catch (\Throwable $e) {
            throw new RuntimeException('Failed to decode fernet data: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * @return array{0: string, 1: string} [signingKey, encryptionKey]
     */
    private function getKeyParts(array $config): array
    {
        $key = $config['Key'] ?? null;
        if (!$key) {
            throw new RuntimeException(
                "Fernet encryption requires 'Key' to be set via PayloadShieldEnc::init(['Key' => ...])"
            );
        }

        $keyBytes = (string) $key;

        // Case 1: already a valid urlsafe-base64 32-byte Fernet key.
        $decoded = $this->base64UrlDecodeLoose($keyBytes);
        if ($decoded !== null && strlen($decoded) === 32) {
            return [substr($decoded, 0, 16), substr($decoded, 16, 16)];
        }

        // Case 2: raw 32-byte key -> derive the same way Fernet would.
        if (strlen($keyBytes) === 32) {
            return [substr($keyBytes, 0, 16), substr($keyBytes, 16, 16)];
        }

        throw new RuntimeException(
            "Invalid Fernet key. 'Key' must be either a valid URL-safe Base64-encoded " .
            "32-byte Fernet key or exactly 32 raw bytes."
        );
    }

    private function base64UrlDecodeLoose(string $value): ?string
    {
        $padded = strtr($value, '-_', '+/');
        $padLength = strlen($padded) % 4;
        if ($padLength > 0) {
            $padded .= str_repeat('=', 4 - $padLength);
        }
        $decoded = base64_decode($padded, true);
        return $decoded === false ? null : $decoded;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string
    {
        $decoded = $this->base64UrlDecodeLoose($value);
        if ($decoded === null) {
            throw new RuntimeException('invalid base64 token');
        }
        return $decoded;
    }

    private function packUint64(int $value): string
    {
        return pack('J', $value);
    }
}

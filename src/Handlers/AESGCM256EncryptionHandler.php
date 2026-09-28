<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Handlers;

use PayloadShield\ComPHPPS\EncryptionHandlerInterface;
use RuntimeException;

/**
 * AES-GCM-256 symmetric encryption handler.
 * Requires "Key" to be set via PayloadShieldEnc::init(['Key' => ...]).
 * The key must resolve to exactly 32 bytes (raw or base64 encoded).
 */
final class AESGCM256EncryptionHandler implements EncryptionHandlerInterface
{
    private const NONCE_SIZE = 12;
    private const TAG_SIZE = 16;

    public function encode(mixed $data, array $config = []): string
    {
        $key = $this->getKey($config);
        $nonce = random_bytes(self::NONCE_SIZE);
        $payload = (string) json_encode($data);

        $tag = '';
        $ciphertext = openssl_encrypt(
            $payload,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            self::TAG_SIZE
        );
        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt aes-gcm-256 payload');
        }

        return base64_encode($nonce . $ciphertext . $tag);
    }

    public function decode(string $encodedData, array $config = []): mixed
    {
        $key = $this->getKey($config);

        try {
            $raw = base64_decode($encodedData, true);
            if ($raw === false) {
                throw new RuntimeException('invalid base64 input');
            }

            $nonce = substr($raw, 0, self::NONCE_SIZE);
            $tag = substr($raw, -self::TAG_SIZE);
            $ciphertext = substr($raw, self::NONCE_SIZE, -self::TAG_SIZE);

            $payload = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
            if ($payload === false) {
                throw new RuntimeException('decryption failed');
            }

            $result = json_decode($payload, true);
            if ($result === null && json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException(json_last_error_msg());
            }

            return $result;
        } catch (\Throwable $e) {
            throw new RuntimeException('Failed to decode aes-gcm-256 data: ' . $e->getMessage(), 0, $e);
        }
    }

    private function getKey(array $config): string
    {
        $key = $config['Key'] ?? null;
        if (!$key) {
            throw new RuntimeException(
                "AES-GCM-256 encryption requires 'Key' to be set via PayloadShieldEnc::init(['Key' => ...])"
            );
        }

        $keyBytes = (string) $key;
        if (strlen($keyBytes) === 32) {
            return $keyBytes;
        }

        $decoded = base64_decode($keyBytes, true);
        if ($decoded !== false && strlen($decoded) === 32) {
            return $decoded;
        }

        throw new RuntimeException('AES-256 key must resolve to exactly 32 bytes');
    }
}

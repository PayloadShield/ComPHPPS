<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Handlers;

use PayloadShield\ComPHPPS\EncryptionHandlerInterface;
use RuntimeException;

/**
 * Base64 encoding/decoding handler.
 * Note: Base64 is encoding, not encryption. Use for obfuscation only.
 * No key configuration is required.
 */
final class Base64EncryptionHandler implements EncryptionHandlerInterface
{
    public function encode(mixed $data, array $config = []): string
    {
        $jsonStr = is_array($data) || is_object($data)
            ? (string) json_encode($data)
            : (string) $data;

        return base64_encode($jsonStr);
    }

    public function decode(string $encodedData, array $config = []): mixed
    {
        $decoded = base64_decode($encodedData, true);
        if ($decoded === false) {
            throw new RuntimeException('Failed to decode base64 data: invalid base64 input');
        }

        $data = json_decode($decoded, true);
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('Failed to decode base64 data: ' . json_last_error_msg());
        }

        return $data;
    }
}

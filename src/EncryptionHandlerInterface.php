<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS;

/**
 * Abstract contract for encryption handlers.
 *
 * Every handler receives the global key configuration produced by
 * PayloadShieldEnc::init() (an array with "Key", "PrivateKey", "PublicKey",
 * "ECPrivateKey", "ECPublicKey", "HPKEPrivateKey", "HPKEPublicKey") and is
 * responsible for pulling out whatever it needs.
 */
interface EncryptionHandlerInterface
{
    /**
     * Encode/encrypt data to a string.
     *
     * @param mixed $data JSON-serializable data.
     * @param array<string, mixed> $config Global key configuration from PayloadShieldEnc::init().
     * @return string Encoded/encrypted string.
     */
    public function encode(mixed $data, array $config = []): string;

    /**
     * Decode/decrypt a string back to data.
     *
     * @param string $encodedData Encoded/encrypted string.
     * @param array<string, mixed> $config Global key configuration from PayloadShieldEnc::init().
     * @return mixed Decoded data.
     *
     * @throws \RuntimeException If data cannot be decoded.
     */
    public function decode(string $encodedData, array $config = []): mixed;
}

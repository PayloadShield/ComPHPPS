<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS;

use PayloadShield\ComPHPPS\Handlers\AESGCM256EncryptionHandler;
use PayloadShield\ComPHPPS\Handlers\Base64EncryptionHandler;
use PayloadShield\ComPHPPS\Handlers\ChaChaEncryptionHandler;
use PayloadShield\ComPHPPS\Handlers\ECDHAESGCMEncryptionHandler;
use PayloadShield\ComPHPPS\Handlers\ECIESEncryptionHandler;
use PayloadShield\ComPHPPS\Handlers\FernetEncryptionHandler;
use PayloadShield\ComPHPPS\Handlers\HPKEEncryptionHandler;
use PayloadShield\ComPHPPS\Handlers\HybridRSAEncryptionHandler;
use RuntimeException;

/**
 * Static facade for the handler registry & factory.
 *
 * Supports all encryption types: base64, fernet, aes-gcm-256,
 * chacha20-poly1305, rsa-hybrid, ecdh-aes-gcm, ecies, hpke.
 *
 * Usage:
 *   PayloadShieldEnc::init(['Key' => '...']);
 *   $encoded = Crypto::encode('aes-gcm-256', ['secret' => 'data']);
 *   $decoded = Crypto::decode('aes-gcm-256', $encoded);
 */
final class Crypto
{
    /** @var array<string, EncryptionHandlerInterface> */
    private static array $handlers = [];

    /** Whether the built-in handlers have been registered. */
    private static bool $booted = false;

    private function __construct()
    {
    }

    // ========================================================================
    // Public static API
    // ========================================================================

    /**
     * Encode/encrypt data using the named handler.
     *
     * The global config from PayloadShieldEnc::getConfig() is passed
     * automatically to the handler.
     *
     * @param string $handlerName Handler name (e.g. "aes-gcm-256", "fernet").
     * @param mixed  $data        JSON-serializable data.
     * @return string Encoded/encrypted string.
     */
    public static function encode(string $handlerName, mixed $data): string
    {
        return self::getHandler($handlerName)
            ->encode($data, PayloadShieldEnc::getConfig());
    }

    /**
     * Decode/decrypt a string using the named handler.
     *
     * @param string $handlerName Handler name (e.g. "aes-gcm-256", "fernet").
     * @param string $encodedData Encoded/encrypted string.
     * @return mixed Decoded data.
     */
    public static function decode(string $handlerName, string $encodedData): mixed
    {
        return self::getHandler($handlerName)
            ->decode($encodedData, PayloadShieldEnc::getConfig());
    }

    /**
     * Register a custom encryption handler.
     *
     * @param string                     $name    Handler name (lower-cased automatically).
     * @param EncryptionHandlerInterface $handler Handler instance.
     */
    public static function registerHandler(string $name, EncryptionHandlerInterface $handler): void
    {
        self::boot();
        self::$handlers[strtolower($name)] = $handler;
    }

    /**
     * Get a registered encryption handler by name.
     *
     * @param string $name Handler name (e.g. "base64", "fernet", "aes-gcm-256").
     * @return EncryptionHandlerInterface
     *
     * @throws RuntimeException If the handler is not found.
     */
    public static function getHandler(string $name): EncryptionHandlerInterface
    {
        self::boot();

        $handlerName = strtolower($name);
        if (!isset(self::$handlers[$handlerName])) {
            $available = implode(', ', array_keys(self::$handlers));
            throw new RuntimeException(
                "Encryption handler '{$name}' not found. Available handlers: {$available}"
            );
        }

        return self::$handlers[$handlerName];
    }

    /**
     * Get all registered handler names.
     *
     * @return string[]
     */
    public static function getAvailableHandlers(): array
    {
        self::boot();
        return array_keys(self::$handlers);
    }

    // ========================================================================
    // Internal bootstrap
    // ========================================================================

    /** Register the built-in handlers once. */
    private static function boot(): void
    {
        if (self::$booted) {
            return;
        }

        self::$handlers = [
            'base64'           => new Base64EncryptionHandler(),
            'fernet'           => new FernetEncryptionHandler(),
            'aes-gcm-256'      => new AESGCM256EncryptionHandler(),
            'rsa-hybrid'       => new HybridRSAEncryptionHandler(),
            'chacha20-poly1305' => new ChaChaEncryptionHandler(),
            'ecdh-aes-gcm'     => new ECDHAESGCMEncryptionHandler(),
            'ecies'            => new ECIESEncryptionHandler(),
            'hpke'             => new HPKEEncryptionHandler(),
        ];

        self::$booted = true;
    }
}

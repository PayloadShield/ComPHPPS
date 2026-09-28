<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS;

/**
 * Holds the global key configuration used by PayloadShield's encryption
 * handlers. Call PayloadShieldEnc::init(...) once at application startup
 * before using any handler.
 */
final class PayloadShieldEnc
{
    /** @var array<string, string|null> */
    private static array $config = [
        'Key' => null,
        'PrivateKey' => null,
        'PublicKey' => null,
        'ECPrivateKey' => null,
        'ECPublicKey' => null,
        'HPKEPrivateKey' => null,
        'HPKEPublicKey' => null,
    ];

    private function __construct()
    {
    }

    /**
     * Initialize the global encryption configuration.
     *
     * @param array<string, mixed> $config Array with any of the following keys:
     *  - "Key": symmetric key used by handlers such as "fernet",
     *    "aes-gcm-256" and "chacha20-poly1305".
     *  - "PrivateKey"/"PublicKey": RSA/hybrid PEM keys. Accepts either a
     *    file path or the raw PEM key content.
     *  - "ECPrivateKey"/"ECPublicKey": EC (P-256) PEM keys used by
     *    "ecdh-aes-gcm" and "ecies". Accepts a file path or raw PEM content.
     *  - "HPKEPrivateKey"/"HPKEPublicKey": X25519 PEM keys used by "hpke".
     *    Accepts a file path or raw PEM content.
     */
    public static function init(array $config): void
    {
        self::$config['Key'] = $config['Key'] ?? null;
        self::$config['PrivateKey'] = self::resolveKeyMaterial($config['PrivateKey'] ?? null);
        self::$config['PublicKey'] = self::resolveKeyMaterial($config['PublicKey'] ?? null);
        self::$config['ECPrivateKey'] = self::resolveKeyMaterial($config['ECPrivateKey'] ?? null);
        self::$config['ECPublicKey'] = self::resolveKeyMaterial($config['ECPublicKey'] ?? null);
        self::$config['HPKEPrivateKey'] = self::resolveKeyMaterial($config['HPKEPrivateKey'] ?? null);
        self::$config['HPKEPublicKey'] = self::resolveKeyMaterial($config['HPKEPublicKey'] ?? null);
    }

    /**
     * Return a copy of the current global key configuration.
     *
     * @return array<string, string|null>
     */
    public static function getConfig(): array
    {
        return self::$config;
    }

    /** Resolve a key value that may be a file path or raw key content. */
    private static function resolveKeyMaterial(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (is_file($value)) {
            $contents = file_get_contents($value);
            return $contents === false ? null : $contents;
        }

        return $value;
    }
}

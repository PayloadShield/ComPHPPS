<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Internal;

use RuntimeException;

/**
 * Minimal RFC 8017 EME-OAEP implementation (SHA-256 hash + MGF1-SHA256),
 * used together with raw RSA (OPENSSL_NO_PADDING) to reproduce the same
 * OAEP-SHA256 padding used by Python's `cryptography` library, which PHP's
 * openssl extension does not expose directly (openssl_public_encrypt only
 * supports OAEP with SHA-1).
 */
final class Oaep
{
    private function __construct()
    {
    }

    public static function encode(string $message, int $modulusBytes, string $hashAlgo = 'sha256'): string
    {
        $hLen = strlen(hash($hashAlgo, '', true));
        $lHash = hash($hashAlgo, '', true);
        $psLen = $modulusBytes - strlen($message) - 2 * $hLen - 2;
        if ($psLen < 0) {
            throw new RuntimeException('OAEP message too long for RSA modulus');
        }

        $db = $lHash . str_repeat("\x00", $psLen) . "\x01" . $message;
        $seed = random_bytes($hLen);
        $dbMask = self::mgf1($seed, $modulusBytes - $hLen - 1, $hashAlgo);
        $maskedDb = $db ^ $dbMask;
        $seedMask = self::mgf1($maskedDb, $hLen, $hashAlgo);
        $maskedSeed = $seed ^ $seedMask;

        return "\x00" . $maskedSeed . $maskedDb;
    }

    public static function decode(string $encodedMessage, int $modulusBytes, string $hashAlgo = 'sha256'): string
    {
        $hLen = strlen(hash($hashAlgo, '', true));
        $lHash = hash($hashAlgo, '', true);

        $encodedMessage = str_pad($encodedMessage, $modulusBytes, "\x00", STR_PAD_LEFT);

        $y = $encodedMessage[0];
        $maskedSeed = substr($encodedMessage, 1, $hLen);
        $maskedDb = substr($encodedMessage, 1 + $hLen);

        $seedMask = self::mgf1($maskedDb, $hLen, $hashAlgo);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = self::mgf1($seed, $modulusBytes - $hLen - 1, $hashAlgo);
        $db = $maskedDb ^ $dbMask;

        $lHash2 = substr($db, 0, $hLen);
        $rest = substr($db, $hLen);
        $sepPos = strpos($rest, "\x01");

        if ($y !== "\x00" || $sepPos === false || !hash_equals($lHash, $lHash2)) {
            throw new RuntimeException('OAEP decoding error');
        }

        $ps = substr($rest, 0, $sepPos);
        if (trim($ps, "\x00") !== '') {
            throw new RuntimeException('OAEP decoding error');
        }

        return substr($rest, $sepPos + 1);
    }

    private static function mgf1(string $seed, int $maskLen, string $hashAlgo): string
    {
        $hLen = strlen(hash($hashAlgo, '', true));
        $t = '';
        $count = (int) ceil($maskLen / $hLen);
        for ($counter = 0; $counter < $count; $counter++) {
            $t .= hash($hashAlgo, $seed . self::i2osp($counter, 4), true);
        }
        return substr($t, 0, $maskLen);
    }

    private static function i2osp(int $value, int $length): string
    {
        $hex = dechex($value);
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }
        return str_pad((string) hex2bin($hex), $length, "\x00", STR_PAD_LEFT);
    }
}

<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Internal;

/** RFC 5869 HKDF (HMAC-SHA256) extract-and-expand key derivation. */
final class Hkdf
{
    private function __construct()
    {
    }

    public static function derive(string $ikm, int $length, string $info = '', string $salt = ''): string
    {
        $hashLen = 32; // sha256
        if ($salt === '') {
            $salt = str_repeat("\x00", $hashLen);
        }

        $prk = hash_hmac('sha256', $ikm, $salt, true);

        $t = '';
        $okm = '';
        $counter = 1;
        while (strlen($okm) < $length) {
            $t = hash_hmac('sha256', $t . $info . chr($counter), $prk, true);
            $okm .= $t;
            $counter++;
        }

        return substr($okm, 0, $length);
    }
}

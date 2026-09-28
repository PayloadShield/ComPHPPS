<?php

declare(strict_types=1);

namespace PayloadShield\ComPHPPS\Handlers;

use PayloadShield\ComPHPPS\EncryptionHandlerInterface;
use RuntimeException;

/**
 * RFC 9180 Hybrid Public Key Encryption, base mode, single-shot semantics:
 * DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305.
 *
 * A fresh X25519 encapsulation key pair is generated per message and
 * combined with the recipient's static public key (DHKEM) to derive a
 * shared secret, which is run through the HPKE key schedule to produce a
 * ChaCha20-Poly1305 key/nonce used for a single AEAD seal/open.
 *
 * Requires "HPKEPublicKey" (encrypt) and "HPKEPrivateKey" (decrypt) to be
 * set via PayloadShieldEnc::init(['HPKEPublicKey' => ..., 'HPKEPrivateKey' => ...]).
 *
 * @requires ext-sodium
 */
final class HPKEEncryptionHandler implements EncryptionHandlerInterface
{
    // Ciphersuite identifiers
    private const KEM_ID  = 0x0020;
    private const KDF_ID  = 0x0001;
    private const AEAD_ID = 0x0003;
    private const NSECRET = 32;
    private const NK      = 32;
    private const NN      = 12;

    public function encode(mixed $data, array $config = []): string
    {
        $this->ensureSodium();
        $recipientPublicKey = $this->loadPublicKey($config);

        // Generate ephemeral X25519 key pair
        $ephemeralSk = sodium_crypto_box_keypair();
        $ephemeralPrivate = sodium_crypto_box_secretkey($ephemeralSk);
        $ephemeralPublic  = sodium_crypto_box_publickey($ephemeralSk);
        $enc = $ephemeralPublic; // 32 raw bytes

        // X25519 key exchange
        $dh = sodium_crypto_scalarmult($ephemeralPrivate, $recipientPublicKey);
        $pkrm = $recipientPublicKey; // 32 raw bytes

        $sharedSecret = $this->extractAndExpand($dh, $enc . $pkrm);
        [$key, $baseNonce] = $this->keySchedule($sharedSecret);

        $payload = (string) json_encode($data);
        $ciphertext = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($payload, '', $baseNonce, $key);

        $bundle = [
            'enc'  => base64_encode($enc),
            'data' => base64_encode($ciphertext),
        ];
        return base64_encode((string) json_encode($bundle));
    }

    public function decode(string $encodedData, array $config = []): mixed
    {
        $this->ensureSodium();
        [$recipientPrivateKey, $recipientPublicKey] = $this->loadPrivateKey($config);

        try {
            $bundle = json_decode(base64_decode($encodedData, true) ?: '', true);
            if (!is_array($bundle)) {
                throw new RuntimeException('invalid bundle format');
            }

            $enc        = base64_decode($bundle['enc'], true);
            $ciphertext = base64_decode($bundle['data'], true);
            if ($enc === false || $ciphertext === false) {
                throw new RuntimeException('invalid base64 fields');
            }

            // X25519 key exchange
            $dh   = sodium_crypto_scalarmult($recipientPrivateKey, $enc);
            $pkrm = $recipientPublicKey;

            $sharedSecret = $this->extractAndExpand($dh, $enc . $pkrm);
            [$key, $baseNonce] = $this->keySchedule($sharedSecret);

            $payload = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext, '', $baseNonce, $key);
            if ($payload === false) {
                throw new RuntimeException('AEAD decryption failed');
            }

            $result = json_decode($payload, true);
            if ($result === null && json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException(json_last_error_msg());
            }

            return $result;
        } catch (\Throwable $e) {
            throw new RuntimeException('Failed to decode hpke data: ' . $e->getMessage(), 0, $e);
        }
    }

    // ========================================================================
    // HPKE KEM / Key Schedule helpers
    // ========================================================================

    private function extractAndExpand(string $dh, string $kemContext): string
    {
        $eaePrk = self::labeledExtract('', 'eae_prk', $dh, self::kemSuiteId());
        return self::labeledExpand($eaePrk, 'shared_secret', $kemContext, self::NSECRET, self::kemSuiteId());
    }

    /** @return array{0: string, 1: string} [key, baseNonce] */
    private function keySchedule(string $sharedSecret): array
    {
        $suiteId = self::hpkeSuiteId();
        $pskIdHash = self::labeledExtract('', 'psk_id_hash', '', $suiteId);
        $infoHash  = self::labeledExtract('', 'info_hash', '', $suiteId);
        $keyScheduleContext = "\x00" . $pskIdHash . $infoHash; // mode_base = 0x00

        $secret = self::labeledExtract($sharedSecret, 'secret', '', $suiteId);
        $key       = self::labeledExpand($secret, 'key', $keyScheduleContext, self::NK, $suiteId);
        $baseNonce = self::labeledExpand($secret, 'base_nonce', $keyScheduleContext, self::NN, $suiteId);

        return [$key, $baseNonce];
    }

    // ========================================================================
    // HKDF labeled extract / expand (RFC 9180 §4)
    // ========================================================================

    private static function labeledExtract(string $salt, string $label, string $ikm, string $suiteId): string
    {
        if ($salt === '') {
            $salt = str_repeat("\x00", 32);
        }
        return hash_hmac('sha256', "HPKE-v1" . $suiteId . $label . $ikm, $salt, true);
    }

    private static function labeledExpand(string $prk, string $label, string $info, int $length, string $suiteId): string
    {
        $labeledInfo = self::i2osp($length, 2) . "HPKE-v1" . $suiteId . $label . $info;

        $t = '';
        $okm = '';
        $counter = 1;
        while (strlen($okm) < $length) {
            $t = hash_hmac('sha256', $t . $labeledInfo . chr($counter), $prk, true);
            $okm .= $t;
            $counter++;
        }

        return substr($okm, 0, $length);
    }

    // ========================================================================
    // Suite ID builders
    // ========================================================================

    private static function kemSuiteId(): string
    {
        return "KEM" . self::i2osp(self::KEM_ID, 2);
    }

    private static function hpkeSuiteId(): string
    {
        return "HPKE" . self::i2osp(self::KEM_ID, 2) . self::i2osp(self::KDF_ID, 2) . self::i2osp(self::AEAD_ID, 2);
    }

    private static function i2osp(int $value, int $length): string
    {
        $hex = str_pad(dechex($value), $length * 2, '0', STR_PAD_LEFT);
        return (string) hex2bin($hex);
    }

    // ========================================================================
    // Key loading helpers
    // ========================================================================

    /**
     * Load the raw 32-byte X25519 public key from a PEM-encoded key.
     *
     * @return string 32-byte raw X25519 public key
     */
    private function loadPublicKey(array $config): string
    {
        $pem = $config['HPKEPublicKey'] ?? null;
        if (!$pem) {
            throw new RuntimeException(
                "HPKE encryption requires 'HPKEPublicKey' to be set via " .
                "PayloadShieldEnc::init(['HPKEPublicKey' => ...])"
            );
        }
        return $this->extractX25519PublicKeyFromPem((string) $pem);
    }

    /**
     * Load the raw 32-byte X25519 private key and its public key from PEM.
     *
     * @return array{0: string, 1: string} [privateKey, publicKey] as 32-byte raw strings
     */
    private function loadPrivateKey(array $config): array
    {
        $pem = $config['HPKEPrivateKey'] ?? null;
        if (!$pem) {
            throw new RuntimeException(
                "HPKE decryption requires 'HPKEPrivateKey' to be set via " .
                "PayloadShieldEnc::init(['HPKEPrivateKey' => ...])"
            );
        }
        return $this->extractX25519PrivateKeyFromPem((string) $pem);
    }

    /**
     * Extract the raw 32-byte X25519 public key from a PEM "PUBLIC KEY".
     *
     * X25519 public key DER = 30 2a 30 05 06 03 2b 65 6e 03 21 00 <32 bytes>
     * The raw key is the last 32 bytes of the DER payload.
     */
    private function extractX25519PublicKeyFromPem(string $pem): string
    {
        $der = $this->pemToDer($pem, 'PUBLIC KEY');
        // X25519 public key DER structure is 44 bytes; raw key is last 32
        if (strlen($der) < 44) {
            throw new RuntimeException('Invalid X25519 public key DER');
        }
        return substr($der, -32);
    }

    /**
     * Extract the raw 32-byte X25519 private key and its public key from a PEM "PRIVATE KEY".
     *
     * X25519 private key DER (PKCS#8) contains the 32-byte raw key inside an
     * OCTET STRING at a fixed offset. The raw private key is at offset 16 (after
     * the outer SEQUENCE + inner OID wrapper), wrapped in another OCTET STRING.
     *
     * @return array{0: string, 1: string} [privateKey, publicKey]
     */
    private function extractX25519PrivateKeyFromPem(string $pem): array
    {
        $der = $this->pemToDer($pem, 'PRIVATE KEY');
        // The raw 32-byte private key is the last 32 bytes of a 48-byte DER
        if (strlen($der) < 48) {
            throw new RuntimeException('Invalid X25519 private key DER');
        }
        $raw = substr($der, -32);

        // Derive the public key from the private key
        $publicKey = sodium_crypto_scalarmult_base($raw);

        return [$raw, $publicKey];
    }

    private function pemToDer(string $pem, string $type): string
    {
        $pem = trim($pem);
        $pattern = "/-----BEGIN {$type}-----(.+?)-----END {$type}-----/s";
        if (!preg_match($pattern, $pem, $matches)) {
            throw new RuntimeException("Failed to parse PEM {$type}");
        }
        $decoded = base64_decode(preg_replace('/\s+/', '', $matches[1]) ?? '', true);
        if ($decoded === false) {
            throw new RuntimeException("Failed to decode PEM {$type} base64");
        }
        return $decoded;
    }

    private function ensureSodium(): void
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException(
                'HPKE handler requires the sodium PHP extension. ' .
                'Install it via: pecl install sodium'
            );
        }
    }
}

# ComPHPPS

Framework-neutral pluggable encryption handlers for [PayloadShield](https://github.com/PayloadShield) — the PHP Composer equivalent of [ComPyPS](https://github.com/PayloadShield/ComPyPS).

[![PHP](https://img.shields.io/badge/PHP-%3E%3D8.1-blue)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)

## Installation

```bash
composer require payloadshield/comphpps
```

## Supported Encryption Handlers

| Handler Name        | Algorithm                                           | Key Config Required                     |
|---------------------|-----------------------------------------------------|-----------------------------------------|
| `base64`            | Base64 encoding (obfuscation only)                  | None                                    |
| `fernet`            | Fernet (AES-128-CBC + HMAC-SHA256)                  | `Key`                                   |
| `aes-gcm-256`       | AES-256-GCM                                         | `Key`                                   |
| `chacha20-poly1305` | ChaCha20-Poly1305                                   | `Key`                                   |
| `rsa-hybrid`        | RSA-OAEP-SHA256 + AES-256-GCM                      | `PublicKey` / `PrivateKey`              |
| `ecdh-aes-gcm`      | Ephemeral ECDH (P-256) + HKDF-SHA256 + AES-256-GCM | `ECPublicKey` / `ECPrivateKey`          |
| `ecies`             | ECIES (P-256, HKDF, AES-256-CTR, HMAC-SHA256)      | `ECPublicKey` / `ECPrivateKey`          |
| `hpke`              | RFC 9180 HPKE (X25519 + ChaCha20-Poly1305)          | `HPKEPublicKey` / `HPKEPrivateKey`      |

## Quick Start

### 1. Initialize the global config

Call `PayloadShieldEnc::init()` once at application startup (e.g. in a service provider, bootstrap file, or `index.php`):

```php
use PayloadShield\ComPHPPS\PayloadShieldEnc;

PayloadShieldEnc::init([
    'Key'        => 'your-32-byte-symmetric-key......',  // for fernet / aes-gcm-256 / chacha20-poly1305
    'PublicKey'   => file_get_contents('/path/to/rsa_public.pem'),   // for rsa-hybrid
    'PrivateKey'  => file_get_contents('/path/to/rsa_private.pem'),  // for rsa-hybrid
    'ECPublicKey' => file_get_contents('/path/to/ec_public.pem'),    // for ecdh-aes-gcm / ecies
    'ECPrivateKey' => file_get_contents('/path/to/ec_private.pem'),  // for ecdh-aes-gcm / ecies
    'HPKEPublicKey'  => file_get_contents('/path/to/x25519_pub.pem'),  // for hpke
    'HPKEPrivateKey' => file_get_contents('/path/to/x25519_priv.pem'), // for hpke
]);
```

> **Tip:** You only need to provide the keys for the handler(s) you intend to use. Key values can be either raw PEM strings or file paths — both are accepted.

### 2. Encrypt & decrypt via the static `Crypto` facade

```php
use PayloadShield\ComPHPPS\Crypto;

// Encrypt
$encoded = Crypto::encode('aes-gcm-256', ['user' => 'alice', 'role' => 'admin']);

// Decrypt
$decoded = Crypto::decode('aes-gcm-256', $encoded);
// => ['user' => 'alice', 'role' => 'admin']
```

## Usage Examples

### Base64 (obfuscation)

```php
$encoded = Crypto::encode('base64', ['hello' => 'world']);
$decoded = Crypto::decode('base64', $encoded);
```

### Fernet (symmetric)

```php
PayloadShieldEnc::init(['Key' => 'your-32-byte-symmetric-key......']);

$encoded = Crypto::encode('fernet', ['secret' => 'data']);
$decoded = Crypto::decode('fernet', $encoded);
```

### AES-GCM-256 (symmetric)

```php
PayloadShieldEnc::init(['Key' => 'your-32-byte-symmetric-key......']);

$encoded = Crypto::encode('aes-gcm-256', ['id' => 42]);
$decoded = Crypto::decode('aes-gcm-256', $encoded);
```

### ChaCha20-Poly1305 (symmetric)

```php
PayloadShieldEnc::init(['Key' => 'your-32-byte-symmetric-key......']);

$encoded = Crypto::encode('chacha20-poly1305', ['msg' => 'hi']);
$decoded = Crypto::decode('chacha20-poly1305', $encoded);
```

### RSA Hybrid (asymmetric)

```php
PayloadShieldEnc::init([
    'PublicKey'  => file_get_contents('rsa_public.pem'),
    'PrivateKey' => file_get_contents('rsa_private.pem'),
]);

$encoded = Crypto::encode('rsa-hybrid', ['sensitive' => 'payload']);
$decoded = Crypto::decode('rsa-hybrid', $encoded);
```

### ECDH + AES-GCM (asymmetric)

```php
PayloadShieldEnc::init([
    'ECPublicKey'  => file_get_contents('ec_public.pem'),
    'ECPrivateKey' => file_get_contents('ec_private.pem'),
]);

$encoded = Crypto::encode('ecdh-aes-gcm', ['data' => 'value']);
$decoded = Crypto::decode('ecdh-aes-gcm', $encoded);
```

### ECIES (asymmetric)

```php
PayloadShieldEnc::init([
    'ECPublicKey'  => file_get_contents('ec_public.pem'),
    'ECPrivateKey' => file_get_contents('ec_private.pem'),
]);

$encoded = Crypto::encode('ecies', ['field' => 'value']);
$decoded = Crypto::decode('ecies', $encoded);
```

### HPKE — RFC 9180 (asymmetric)

> Requires the `ext-sodium` PHP extension.

```php
PayloadShieldEnc::init([
    'HPKEPublicKey'  => file_get_contents('x25519_public.pem'),
    'HPKEPrivateKey' => file_get_contents('x25519_private.pem'),
]);

$encoded = Crypto::encode('hpke', ['message' => 'encrypted']);
$decoded = Crypto::decode('hpke', $encoded);
```

## Using Handlers Directly

If you prefer to use handler instances directly (e.g. for dependency injection):

```php
use PayloadShield\ComPHPPS\Crypto;
use PayloadShield\ComPHPPS\PayloadShieldEnc;

$handler = Crypto::getHandler('aes-gcm-256');
$config  = PayloadShieldEnc::getConfig();

$encoded = $handler->encode(['key' => 'value'], $config);
$decoded = $handler->decode($encoded, $config);
```

## Registering Custom Handlers

Implement `EncryptionHandlerInterface` and register it:

```php
use PayloadShield\ComPHPPS\Crypto;
use PayloadShield\ComPHPPS\EncryptionHandlerInterface;

class MyCustomHandler implements EncryptionHandlerInterface
{
    public function encode(mixed $data, array $config = []): string
    {
        // your encryption logic
    }

    public function decode(string $encodedData, array $config = []): mixed
    {
        // your decryption logic
    }
}

Crypto::registerHandler('my-custom', new MyCustomHandler());

$encoded = Crypto::encode('my-custom', $data);
```

## Available Static Methods

| Method | Description |
|--------|-------------|
| `PayloadShieldEnc::init(array $config)` | Initialize the global key configuration |
| `PayloadShieldEnc::getConfig()` | Get a copy of the current configuration |
| `Crypto::encode(string $handler, mixed $data)` | Encrypt/encode data using the named handler |
| `Crypto::decode(string $handler, string $data)` | Decrypt/decode data using the named handler |
| `Crypto::getHandler(string $name)` | Get a handler instance by name |
| `Crypto::registerHandler(string $name, $handler)` | Register a custom handler |
| `Crypto::getAvailableHandlers()` | List all registered handler names |

## Requirements

- PHP ≥ 8.1
- `ext-openssl` — required for all handlers except `base64`
- `ext-json` — required for payload serialization
- `ext-sodium` — required only for the `hpke` handler

## Python Interoperability

This package is the PHP equivalent of [ComPyPS](https://github.com/PayloadShield/ComPyPS). Both packages implement the same handler interfaces and encryption schemes, enabling cross-language encrypt/decrypt workflows:

```python
# Python — encrypt
from compyps import PayloadShieldEnc, get_handler

PayloadShieldEnc.init({"Key": "your-32-byte-symmetric-key......"})
encoded = get_handler("aes-gcm-256").encode({"user": "alice"}, PayloadShieldEnc.get_config())
```

```php
// PHP — decrypt the same payload
PayloadShieldEnc::init(['Key' => 'your-32-byte-symmetric-key......']);
$decoded = Crypto::decode('aes-gcm-256', $encoded);
// => ['user' => 'alice']
```

## License

[Apache License 2.0](LICENSE)

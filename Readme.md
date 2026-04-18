# node-cardcrypto

**node-cardcrypto** is a comprehensive Node.js wrapper for cryptographic operations, specifically tailored for smart card, EMV, and payment terminal domains. It provides an intuitive API that seamlessly handles both Hexadecimal Strings and Buffers, making it easy to perform various encryption, hashing, padding, and MAC operations.

## Overview

This library wraps essential cryptographic functions into a single, easy-to-use package. It is designed to simplify cryptography tasks commonly found in financial applications and APDU communications.

## Key Features

- **Symmetric Encryption**: Supports DES, Triple DES (3DES), AES, and SEED (South Korean block cipher algorithm).
- **Asymmetric Encryption**: RSA encryption support (Public/Private Key, CRT) via the `node-jsbnrsa` module.
- **Message Authentication Code (MAC)**: Implementations for DES MAC and various HMACs (HMAC-SHA1, HMAC-SHA256, HMAC-MD5) to ensure data integrity.
- **Hashing**: Common hashing algorithms including MD5, SHA1, and SHA256.
- **Padding Schemes**: Extensive support for padding data blocks, including ISO9797, 80 Padding, PKCS#5, and PKCS#7 padding.
- **Utilities**: Random byte generation and bitwise operations (e.g., XOR).

## API Reference

### DES (`node-cardcrypto.des`)
- **`ecb_encrypt(key, msg)`** / **`ecb_decrypt(key, msg)`**
  - `key` *(String | Buffer)*: 8 bytes (DES), 16 bytes (2-key 3DES), or 24 bytes (3-key 3DES).
  - `msg` *(String | Buffer)*: Data to process. Length must be a multiple of 8 bytes.
  - **Returns**: Hexadecimal string of the resulting data.
- **`cbc_encrypt(key, msg, iv)`** / **`cbc_decrypt(key, msg, iv)`**
  - `iv` *(String | Buffer)*: Optional. Initialization Vector (8 bytes). Defaults to `0x00...`.

### AES (`node-cardcrypto.aes`)
- **`ecb_encrypt(key, msg)`** / **`ecb_decrypt(key, msg)`**
  - `key` *(String | Buffer)*: 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256).
  - `msg` *(String | Buffer)*: Data to process. Length must be a multiple of 16 bytes.
- **`cbc_encrypt(key, msg, iv)`** / **`cbc_decrypt(key, msg, iv)`**
  - `iv` *(String | Buffer)*: Optional. Initialization Vector (16 bytes). Defaults to `0x00...`.
- **`ctr_encrypt(key, msg, iv)`** / **`ctr_decrypt(key, msg, iv)`**
  - `iv` *(String | Buffer)*: Optional. Initialization Vector (16 bytes).

### MAC (`node-cardcrypto.mac`)
- **`hmac(type, key, msg)`**
  - `type` *(String)*: Hashing algorithm (e.g., `'sha1'`, `'sha256'`, `'md5'`).
  - `key` *(String | Buffer)*: HMAC secret key.
  - `msg` *(String | Buffer)*: Message to authenticate.
- **`des_mac(key, msg, iv, len)`** (FIPS PUB 113 / CBC-MAC)
  - `key` *(String | Buffer)*: 16 bytes (2-key) or 24 bytes (3-key).
  - `len` *(Number)*: Optional. Output MAC length. Default is 4 bytes.
- **`des_mac_emv(key, data)`** (ISO/IEC 9797-1 MAC Algorithm 3 / Retail MAC)
  - `key` *(String | Buffer)*: 16 bytes (2-key).
  - `data` *(String | Buffer)*: Message to authenticate.

### Seed, Hash, and RSA
The library also exposes `seed`, `hash`, and `rsa` modules with comparable straightforward parameter structures (e.g., `seed.ecb_encrypt(key, msg)`, `hash.sha256(msg)`).

## Installation

You can install the package via npm:

```bash
npm install node-cardcrypto
```

## Examples

### DES ECB Encryption

```javascript
var assert = require('assert');
var des = require('node-cardcrypto').des;

// Hex string or Buffer can be used
var deskey1 = '7CA110454A1A6E57';
var plain = '01A1D6D039776742';

var answer = '690F5B0D9A26939B';

var result = des.ecb_encrypt(deskey1, plain);
assert(answer === result);
console.log('DES ECB Encrypt: ', result);
```

### Triple DES (3DES) ECB Encryption

```javascript
var assert = require('assert');
var des = require('node-cardcrypto').des;

var plain = '01A1D6D039776742';

var deskey1 = '7CA110454A1A6E57';
var deskey2 = '0131D9619DC1376E';

// Create a double-length key (16 bytes)
var deskey = deskey1 + deskey2;

var cipher = plain;
cipher = des.ecb_encrypt(deskey1, cipher);
cipher = des.ecb_decrypt(deskey2, cipher);
cipher = des.ecb_encrypt(deskey1, cipher);

var result = des.ecb_encrypt(deskey, plain);
assert(result === cipher);
console.log('3DES ECB Encrypt: ', result);
```

### Padding Example (PKCS#7)

```javascript
var padding = require('node-cardcrypto').padding;

var plain = '1234567890';
// Pad the string to a block size of 8 bytes
var padded = padding.pkcs7.pad(plain, 8); 

console.log('Padded Data: ', padded);
```
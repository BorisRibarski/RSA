# RSA (textbook) in Node.js (BigInt)

This is a **university / learning** implementation of RSA written in Node.js using native `BigInt`. It uses **no third-party cryptography libraries**.

## Security warning

This project implements **textbook RSA**: encryption is raw \(m^e \bmod n\) and decryption is \(c^d \bmod n\).

Textbook RSA is **not secure** for real-world use (no padding; deterministic; malleable). Use a vetted library and modern padding schemes (OAEP/PSS) for anything beyond coursework.

## Requirements

- Node.js 18+ (BigInt + `node:test`)

## Install

```bash
npm install
```

## Demo

```bash
npm run demo
```

## Tests

```bash
npm test
```

## Usage (module)

```js
import { generateKeyPair, encryptText, decryptText } from "./src/index.js";

const { publicKey, privateKey } = await generateKeyPair({ bitLength: 1024 });
const ciphertextB64 = encryptText("hello", publicKey);
const plaintext = decryptText(ciphertextB64, privateKey);
console.log({ ciphertextB64, plaintext });
```

## API

- `generateKeyPair({ bitLength, e }?) -> { publicKey, privateKey }`
  - `publicKey`: `{ n: bigint, e: bigint }`
  - `privateKey`: `{ n: bigint, d: bigint, p: bigint, q: bigint }`
- `encrypt(plaintextBytes, publicKey) -> Uint8Array`
- `decrypt(ciphertextBytes, privateKey) -> Uint8Array`
- `encryptText(text, publicKey, encoding='utf8') -> string` (base64)
- `decryptText(base64Ciphertext, privateKey, encoding='utf8') -> string`


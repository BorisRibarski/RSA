import test from "node:test";
import assert from "node:assert/strict";

import { modInv, modPow } from "../src/bigint/modarith.js";
import { generateKeyPair, encrypt, decrypt, encryptText, decryptText } from "../src/index.js";

test("modPow matches known small values", () => {
  assert.equal(modPow(2n, 10n, 1000n), 24n);
  assert.equal(modPow(3n, 0n, 7n), 1n);
  assert.equal(modPow(10n, 9n, 6n), 4n);
});

test("modInv works when gcd(a,m)=1", () => {
  const inv = modInv(3n, 11n);
  assert.equal((3n * inv) % 11n, 1n);
});

test("RSA round-trip bytes", async () => {
  const { publicKey, privateKey } = await generateKeyPair({ bitLength: 512 });
  const msg = Uint8Array.from(Buffer.from("hello world"));
  const ct = encrypt(msg, publicKey);
  const pt = decrypt(ct, privateKey);
  assert.equal(Buffer.from(pt).toString("utf8"), "hello world");
});

test("RSA round-trip text (base64)", async () => {
  const { publicKey, privateKey } = await generateKeyPair({ bitLength: 512 });
  const ctB64 = encryptText("Node.js RSA", publicKey);
  const pt = decryptText(ctB64, privateKey);
  assert.equal(pt, "Node.js RSA");
});


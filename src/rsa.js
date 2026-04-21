import { generateProbablePrime } from "./bigint/prime.js";
import { gcd, modInv, modPow } from "./bigint/modarith.js";
import {
  bigIntToBytes,
  bytesToBigInt,
  byteLengthOfBigInt,
  chunkPlaintextForTextbookRSA,
  unchunkPlaintextForTextbookRSA,
  concatBytes
} from "./encoding.js";

function assertKeyPublic(publicKey) {
  if (!publicKey || typeof publicKey !== "object") throw new TypeError("publicKey must be an object");
  const { n, e } = publicKey;
  if (typeof n !== "bigint" || typeof e !== "bigint") throw new TypeError("publicKey.n and publicKey.e must be bigint");
  if (n <= 0n || e <= 0n) throw new RangeError("publicKey.n and publicKey.e must be > 0");
  return { n, e };
}

function assertKeyPrivate(privateKey) {
  if (!privateKey || typeof privateKey !== "object") throw new TypeError("privateKey must be an object");
  const { n, d } = privateKey;
  if (typeof n !== "bigint" || typeof d !== "bigint") throw new TypeError("privateKey.n and privateKey.d must be bigint");
  if (n <= 0n || d <= 0n) throw new RangeError("privateKey.n and privateKey.d must be > 0");
  return { n, d };
}

export async function generateKeyPair({ bitLength = 1024, e = 65537n } = {}) {
  if (!Number.isInteger(bitLength) || bitLength < 64) {
    throw new RangeError("bitLength must be an integer >= 64");
  }
  if (typeof e !== "bigint" || e <= 1n) throw new RangeError("e must be a bigint > 1");

  const half = Math.floor(bitLength / 2);
  let p;
  let q;
  while (true) {
    p = await generateProbablePrime(half);
    do {
      q = await generateProbablePrime(bitLength - half);
    } while (q === p);

    const phi = (p - 1n) * (q - 1n);
    if (gcd(e, phi) !== 1n) continue;
    const n = p * q;
    const d = modInv(e, phi);

    return {
      publicKey: { n, e },
      privateKey: { n, d, p, q }
    };
  }
}

export function encrypt(plaintextBytes, publicKey) {
  const { n, e } = assertKeyPublic(publicKey);
  if (!(plaintextBytes instanceof Uint8Array)) throw new TypeError("plaintextBytes must be Uint8Array");

  const { k, blocks } = chunkPlaintextForTextbookRSA(plaintextBytes, n);
  const outBlocks = [];

  for (const plainBlock of blocks) {
    const m = bytesToBigInt(plainBlock);
    if (m >= n) throw new RangeError("plaintext block must be < n");
    const c = modPow(m, e, n);
    outBlocks.push(bigIntToBytes(c, k));
  }

  return concatBytes(outBlocks);
}

export function decrypt(ciphertextBytes, privateKey) {
  const { n, d } = assertKeyPrivate(privateKey);
  if (!(ciphertextBytes instanceof Uint8Array)) throw new TypeError("ciphertextBytes must be Uint8Array");

  const k = byteLengthOfBigInt(n);
  if (ciphertextBytes.length % k !== 0) throw new RangeError("ciphertext length must be a multiple of modulus byte length");

  const plainBlockSize = k - 1;
  const plainBlocks = [];

  for (let off = 0; off < ciphertextBytes.length; off += k) {
    const cBytes = ciphertextBytes.subarray(off, off + k);
    const c = bytesToBigInt(cBytes);
    if (c >= n) throw new RangeError("ciphertext block must be < n");
    const m = modPow(c, d, n);
    plainBlocks.push(bigIntToBytes(m, plainBlockSize));
  }

  return unchunkPlaintextForTextbookRSA(plainBlocks);
}

export function encryptText(text, publicKey, encoding = "utf8") {
  if (typeof text !== "string") throw new TypeError("text must be string");
  const bytes = Uint8Array.from(Buffer.from(text, encoding));
  const ciphertextBytes = encrypt(bytes, publicKey);
  return Buffer.from(ciphertextBytes).toString("base64");
}

export function decryptText(base64Ciphertext, privateKey, encoding = "utf8") {
  if (typeof base64Ciphertext !== "string") throw new TypeError("base64Ciphertext must be string");
  const ciphertextBytes = Uint8Array.from(Buffer.from(base64Ciphertext, "base64"));
  const plaintextBytes = decrypt(ciphertextBytes, privateKey);
  return Buffer.from(plaintextBytes).toString(encoding);
}


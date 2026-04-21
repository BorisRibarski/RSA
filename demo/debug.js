import { generateKeyPair } from "../src/index.js";
import { bytesToBigInt, bigIntToBytes, chunkPlaintextForTextbookRSA } from "../src/encoding.js";
import { modPow } from "../src/bigint/modarith.js";

function formatBigInt(x, { base = "hex", maxDigits = 64 } = {}) {
  if (typeof x !== "bigint") return String(x);
  const neg = x < 0n;
  const v = neg ? -x : x;
  const s =
    base === "dec"
      ? v.toString(10)
      : base === "bin"
        ? v.toString(2)
        : v.toString(16);

  const prefix = base === "dec" ? "" : base === "bin" ? "0b" : "0x";
  const sign = neg ? "-" : "";
  if (s.length <= maxDigits) return `${sign}${prefix}${s}`;
  return `${sign}${prefix}${s.slice(0, Math.floor(maxDigits / 2))}…${s.slice(-Math.floor(maxDigits / 2))} (${s.length} digits)`;
}

function bytesToHex(bytes, maxBytes = 32) {
  const shown = bytes.subarray(0, Math.min(bytes.length, maxBytes));
  const hex = Buffer.from(shown).toString("hex");
  return bytes.length > maxBytes ? `${hex}… (${bytes.length} bytes)` : `${hex} (${bytes.length} bytes)`;
}

async function debugForBitLength(bitLength, message) {
  console.log("\n============================================================");
  console.log(`Debug run for bitLength=${bitLength}`);
  console.log("============================================================");

  console.log("Generating keypair...");
  const { publicKey, privateKey } = await generateKeyPair({ bitLength });

  const { n, e } = publicKey;
  const { d, p, q } = privateKey;
  const phi = (p - 1n) * (q - 1n);

  console.log("\nKey material (BigInt):");
  console.log(`p   = ${formatBigInt(p)}`);
  console.log(`q   = ${formatBigInt(q)}`);
  console.log(`n   = p*q = ${formatBigInt(n)}`);
  console.log(`phi = (p-1)(q-1) = ${formatBigInt(phi)}`);
  console.log(`e   = ${formatBigInt(e, { base: "dec", maxDigits: 80 })}`);
  console.log(`d   = e^-1 mod phi = ${formatBigInt(d)}`);

  const msgBytes = Uint8Array.from(Buffer.from(message, "utf8"));
  console.log("\nMessage:");
  console.log(`text  = ${JSON.stringify(message)}`);
  console.log(`bytes = ${bytesToHex(msgBytes, 64)}`);

  const { k, plainBlockSize, blocks } = chunkPlaintextForTextbookRSA(msgBytes, n);
  console.log("\nBlock sizing:");
  console.log(`k (ciphertext block bytes) = ceil(bitlen(n)/8) = ${k}`);
  console.log(`plainBlockSize (bytes)     = k-1 = ${plainBlockSize}`);
  console.log(`max payload per block      = plainBlockSize-2 = ${plainBlockSize - 2}`);
  console.log(`number of blocks           = ${blocks.length}`);

  console.log("\nPer-block textbook RSA calculations:");
  for (let i = 0; i < blocks.length; i++) {
    const plainBlock = blocks[i];
    const m = bytesToBigInt(plainBlock);
    const c = modPow(m, e, n);
    const m2 = modPow(c, d, n);

    console.log(`\n[block ${i}]`);
    console.log(`plainBlock bytes = ${bytesToHex(plainBlock, 64)}`);
    console.log(`m  = bytesToBigInt(plainBlock) = ${formatBigInt(m)}`);
    console.log(`c  = m^e mod n                 = ${formatBigInt(c)}`);
    console.log(`m' = c^d mod n                 = ${formatBigInt(m2)}`);

    const m2Bytes = bigIntToBytes(m2, plainBlockSize);
    const len = (m2Bytes[0] << 8) | m2Bytes[1];
    const payload = m2Bytes.subarray(2, 2 + len);
    console.log(`decoded len = ${len}`);
    console.log(`decoded payload bytes = ${bytesToHex(payload, 64)}`);
    console.log(`decoded payload text  = ${JSON.stringify(Buffer.from(payload).toString("utf8"))}`);
  }
}

const message =
  "Debug RSA: show m^e mod n and c^d mod n across blocks. This message is long enough to force chunking.";

// Small/medium/big (keep big reasonable so it runs on student laptops)
await debugForBitLength(256, message);
await debugForBitLength(512, message);
await debugForBitLength(1024, message);


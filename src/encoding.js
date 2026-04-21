export function byteLengthOfBigInt(n) {
  if (typeof n !== "bigint") throw new TypeError("n must be bigint");
  if (n < 0n) throw new RangeError("n must be non-negative");
  if (n === 0n) return 1;
  return Math.ceil(n.toString(2).length / 8);
}

export function bytesToBigInt(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("bytes must be Uint8Array");
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}

export function bigIntToBytes(x, length) {
  if (typeof x !== "bigint") throw new TypeError("x must be bigint");
  if (!Number.isInteger(length) || length <= 0) throw new RangeError("length must be positive integer");
  if (x < 0n) throw new RangeError("x must be non-negative");

  const out = new Uint8Array(length);
  let v = x;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new RangeError("integer does not fit in length bytes");
  return out;
}

export function concatBytes(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export function chunkPlaintextForTextbookRSA(plaintextBytes, modulusN) {
  if (!(plaintextBytes instanceof Uint8Array)) throw new TypeError("plaintextBytes must be Uint8Array");
  if (typeof modulusN !== "bigint") throw new TypeError("modulusN must be bigint");

  const k = byteLengthOfBigInt(modulusN); // ciphertext block size
  const plainBlockSize = k - 1; // ensures m < 2^(8*(k-1)) <= n
  if (plainBlockSize < 3) throw new RangeError("modulus too small");

  const maxPayload = plainBlockSize - 2; // 2 bytes length prefix
  const blocks = [];
  for (let off = 0; off < plaintextBytes.length; off += maxPayload) {
    const chunk = plaintextBytes.subarray(off, Math.min(plaintextBytes.length, off + maxPayload));
    const block = new Uint8Array(plainBlockSize);
    block[0] = (chunk.length >>> 8) & 0xff;
    block[1] = chunk.length & 0xff;
    block.set(chunk, 2);
    blocks.push(block);
  }
  return { k, plainBlockSize, blocks };
}

export function unchunkPlaintextForTextbookRSA(plainBlocks) {
  const chunks = [];
  for (const block of plainBlocks) {
    if (!(block instanceof Uint8Array)) throw new TypeError("plain block must be Uint8Array");
    if (block.length < 2) throw new RangeError("plain block too small");
    const len = (block[0] << 8) | block[1];
    if (len > block.length - 2) throw new RangeError("invalid length prefix");
    chunks.push(block.subarray(2, 2 + len));
  }
  return concatBytes(chunks);
}


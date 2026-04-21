import { randomBytes } from "node:crypto";
import { gcd, modPow, mod } from "./modarith.js";

const SMALL_PRIMES = [
  3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n,
  59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n,
  127n, 131n, 137n, 139n, 149n, 151n, 157n, 163n, 167n, 173n, 179n, 181n,
  191n, 193n, 197n, 199n, 211n, 223n, 227n, 229n, 233n, 239n, 241n, 251n,
  257n, 263n, 269n, 271n, 277n, 281n, 283n, 293n, 307n, 311n, 313n, 317n,
  331n, 337n, 347n, 349n, 353n, 359n, 367n, 373n, 379n, 383n, 389n, 397n,
  401n, 409n, 419n, 421n, 431n, 433n, 439n, 443n, 449n, 457n, 461n, 463n,
  467n, 479n, 487n, 491n, 499n, 503n, 509n, 521n, 523n, 541n
];

export function randomBigInt(bitLength) {
  if (!Number.isInteger(bitLength) || bitLength <= 0) {
    throw new RangeError("bitLength must be a positive integer");
  }
  const byteLength = Math.ceil(bitLength / 8);
  const bytes = randomBytes(byteLength);

  const topBit = (bitLength - 1) % 8;
  bytes[0] |= 1 << topBit; // force bitLength bits
  bytes[bytes.length - 1] |= 1; // make it odd

  return bytesToBigInt(bytes);
}

export function randomBigIntBetweenInclusive(min, max) {
  if (typeof min !== "bigint" || typeof max !== "bigint") {
    throw new TypeError("min/max must be bigint");
  }
  if (min > max) throw new RangeError("min must be <= max");
  if (min === max) return min;

  const range = max - min + 1n;
  const bitLength = range.toString(2).length;
  const byteLength = Math.ceil(bitLength / 8);

  while (true) {
    const x = bytesToBigInt(randomBytes(byteLength));
    const candidate = x % range;
    return min + candidate;
  }
}

function bytesToBigInt(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}

export function isProbablyPrime(n, rounds = 40) {
  if (typeof n !== "bigint") throw new TypeError("n must be bigint");
  if (n < 2n) return false;
  if (n === 2n) return true;
  if ((n & 1n) === 0n) return false;

  for (const p of SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }

  // write n-1 = d * 2^s with d odd
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }

  for (let i = 0; i < rounds; i++) {
    const a = randomBigIntBetweenInclusive(2n, n - 2n);
    if (gcd(a, n) !== 1n) return false;

    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;

    let witness = true;
    for (let r = 1; r < s; r++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        witness = false;
        break;
      }
      if (x === 1n) return false;
    }
    if (witness) return false;
  }

  return true;
}

export async function generateProbablePrime(bitLength, { rounds = 40 } = {}) {
  if (!Number.isInteger(bitLength) || bitLength < 16) {
    throw new RangeError("bitLength must be an integer >= 16");
  }
  while (true) {
    const candidate = randomBigInt(bitLength);
    if (isProbablyPrime(candidate, rounds)) return candidate;
    // yield occasionally for very small event-loop friendliness
    await Promise.resolve();
  }
}


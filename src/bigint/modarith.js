export function assertBigInt(x, name = "value") {
  if (typeof x !== "bigint") throw new TypeError(`${name} must be a bigint`);
}

export function mod(a, m) {
  assertBigInt(a, "a");
  assertBigInt(m, "m");
  if (m <= 0n) throw new RangeError("m must be > 0");
  const r = a % m;
  return r < 0n ? r + m : r;
}

export function gcd(a, b) {
  assertBigInt(a, "a");
  assertBigInt(b, "b");
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a;
}

export function egcd(a, b) {
  assertBigInt(a, "a");
  assertBigInt(b, "b");

  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;

  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }

  return { g: oldR, x: oldS, y: oldT };
}

export function modInv(a, m) {
  assertBigInt(a, "a");
  assertBigInt(m, "m");
  if (m <= 0n) throw new RangeError("m must be > 0");
  const { g, x } = egcd(mod(a, m), m);
  if (g !== 1n) throw new RangeError("inverse does not exist");
  return mod(x, m);
}

export function modPow(base, exponent, modulus) {
  assertBigInt(base, "base");
  assertBigInt(exponent, "exponent");
  assertBigInt(modulus, "modulus");
  if (modulus <= 0n) throw new RangeError("modulus must be > 0");
  if (exponent < 0n) throw new RangeError("exponent must be >= 0");

  let b = mod(base, modulus);
  let e = exponent;
  let result = 1n;

  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    if (e > 0n) b = (b * b) % modulus;
  }

  return result;
}


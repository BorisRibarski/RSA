import { generateKeyPair, encryptText, decryptText } from "../src/index.js";

const message = "Hello from textbook RSA (BigInt)!";

console.log("Generating 1024-bit keypair (may take a moment)...");
const { publicKey, privateKey } = await generateKeyPair({ bitLength: 1024 });

const ciphertextB64 = encryptText(message, publicKey);
const roundTrip = decryptText(ciphertextB64, privateKey);

console.log({ message, ciphertextB64, roundTrip, ok: roundTrip === message });


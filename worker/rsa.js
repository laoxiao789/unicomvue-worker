const MODULUS_HEX =
  "dcf8264af5b040f4853e81950e73a1541aeef23bd5a94cd0743f39a014187de8" +
  "c8355aba2f0f5a2a67e7881782e3bf129718e748efd25176f7bd34f850a34efe" +
  "baa190804e229b0367471ecf16d091af288811c5286afb8db6e455a01026eaa" +
  "741d12adcb606aa19f2e02af6473a7c138f236a8c1531ccc7909440b673310c4b";

const MODULUS_BYTES = 128;
const MODULUS = BigInt(`0x${MODULUS_HEX}`);
const EXPONENT = 0x10001n;

function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function randomNonZeroBytes(length) {
  const out = new Uint8Array(length);
  let offset = 0;
  while (offset < length) {
    const buf = new Uint8Array(length - offset + 8);
    crypto.getRandomValues(buf);
    for (const byte of buf) {
      if (byte !== 0 && offset < length) {
        out[offset++] = byte;
      }
    }
  }
  return out;
}

function bytesToBigInt(bytes) {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return BigInt(`0x${hex || "0"}`);
}

function bigIntToBytes(value, size) {
  const hex = value.toString(16).padStart(size * 2, "0");
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function encryptCredential(value) {
  const data = new TextEncoder().encode(String(value));
  const psLen = MODULUS_BYTES - data.length - 3;
  if (psLen < 8) {
    throw new Error("待加密凭证过长");
  }

  const block = new Uint8Array(MODULUS_BYTES);
  block[0] = 0x00;
  block[1] = 0x02;
  block.set(randomNonZeroBytes(psLen), 2);
  block[2 + psLen] = 0x00;
  block.set(data, 3 + psLen);

  const m = bytesToBigInt(block);
  const c = modPow(m, EXPONENT, MODULUS);
  return bytesToBase64(bigIntToBytes(c, MODULUS_BYTES));
}

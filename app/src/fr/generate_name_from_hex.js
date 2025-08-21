import { WORDS } from "/src/fr/english-wordlist.js";

/**
 * Generate a mnemonic-style name from a 32-byte hex string.
 * @param {string} hexString - Must be 64 hex characters.
 * @returns {string} e.g. "avocado-sunset-513"
 */
export function generateNameFromHex(hexString) {
  if (typeof hexString !== "string") {
    throw new TypeError("hexString must be a string.");
  }

  const s = hexString.trim().toLowerCase();

  // Validate 32-byte hex (64 chars)
  if (s.length !== 64) {
    throw new Error("Input must be a 32-byte hex string (64 characters).");
  }
  if (!/^[0-9a-f]{64}$/.test(s)) {
    throw new Error("Input contains non-hex characters.");
  }

  // First 4 bytes (8 hex chars) -> 32-bit value
  const firstFourBytesHex = s.slice(0, 8);
  const value = Number.parseInt(firstFourBytesHex, 16); // safe for 32-bit

  // Convert to 32-bit binary, then slice into 11, 11, and 10 bits
  const bits = value.toString(2).padStart(32, "0");
  const first11  = parseInt(bits.slice(0, 11), 2);
  const second11 = parseInt(bits.slice(11, 22), 2);
  const tenBit   = parseInt(bits.slice(22, 32), 2);

  const firstWord = WORDS[first11];
  const secondWord = WORDS[second11];

  return `${firstWord}-${secondWord}-${tenBit}`;
}

// Attach to window so it’s available globally
window.generateNameFromHex = generateNameFromHex;

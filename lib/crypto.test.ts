import { describe, it, expect } from 'vitest';
import { encryptFile, decryptFile } from './crypto';

const CHUNK_SIZE = 5 * 1024 * 1024; // 5 MiB — must match crypto.ts
const PASSWORD = 'test-password';

const encode = (s: string) => new TextEncoder().encode(s);

// crypto.getRandomValues is capped at 65536 bytes per call
const randomBytes = (size: number): Uint8Array => {
  const buf = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65536) {
    crypto.getRandomValues(buf.subarray(offset, offset + Math.min(65536, size - offset)));
  }
  return buf;
};

const roundtrip = async (plaintext: Uint8Array, password = PASSWORD) => {
  const encrypted = await encryptFile(plaintext, password);
  const decrypted = await decryptFile(encrypted, password);
  return decrypted;
};

describe('encryptFile / decryptFile', () => {
  it('happy path: "hello world"', async () => {
    const plaintext = encode('hello world');
    const result = await roundtrip(plaintext);
    // stupid buffer from is needed so that it doesnt do a deep compare
    expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
  });

  it('happy path: exactly 1 byte', async () => {
    const plaintext = new Uint8Array([0x42]);
    const result = await roundtrip(plaintext);
    expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
  });

  it('happy path: exactly one full block (5 MiB)', async () => {
    const plaintext = randomBytes(CHUNK_SIZE);
    const result = await roundtrip(plaintext);
    expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
  });

  it('happy path: one full block + 1 byte (5 MiB + 1)', async () => {
    const plaintext = randomBytes(CHUNK_SIZE + 1);
    const result = await roundtrip(plaintext);
    expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
  });
});

// How the crypto works: Inspired by the [gocryptfs crypto](https://nuetzlich.net/gocryptfs/forward_mode_crypto/)
// Also see [its crypto audit](https://defuse.ca/audits/gocryptfs.htm)
//
// Effectively, we chunk every 5MiB and use AES256-GCM (GCM to find out if the crypto worked through auth tag).
// Now we furhtermore ensure against 2 attack vectors:
//
// 1. **Changing chunks between files:** The chunk size is known to the attacker. So if the attacker knows (or assumes)
//    that the lazy user always uses the same password, it could take two files and write chunks from file 1 to file 2,
//    as long as it keeps chunk boundaries. To prevent this, each file has a fileid (a header) that gets put into
//    each AES chunk as AAD, thus if chunks are transfered to a different file the file id doesnt match, thus wrong aad
//    breaks, thus it fails.
// 2. **Changing chunks within files:** This obviously doesn't secure against tampering within a single file. For this,
//    we also give each chunk a number (if we just increase by 1, we dont even have to store it) and add it to the aad.

const CHUNK_SIZE = 5 * 1024 * 1024; // 5 MiB
const FILE_ID_SIZE = 16; // 128-bit file ID
const IV_SIZE = 12;      // 96-bit IV for AES-GCM
const SALT_SIZE = 16;
const PBKDF2_ITERATIONS = 100000;

// Derive AES-GCM key from password using PBKDF2
export const deriveKey = async (password: string, salt: BufferSource): Promise<CryptoKey> => {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

// Build AAD for block i: fileId (16 bytes) || blockIndex (uint32, big-endian, 4 bytes)
const buildAAD = (fileId: Uint8Array, blockIndex: number): Uint8Array => {
  const aad = new Uint8Array(FILE_ID_SIZE + 4);
  aad.set(fileId, 0);
  new DataView(aad.buffer).setUint32(FILE_ID_SIZE, blockIndex, false /* big-endian */);
  return aad;
};

/**
 * Encrypted file layout:
 *   [16-byte salt][16-byte fileId][N blocks...]
 *
 * Each block:
 *   [12-byte IV][ciphertext + 16-byte GCM auth tag]
 */
export const encryptFile = async (data: Uint8Array, password: string): Promise<Uint8Array> => {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const fileId = crypto.getRandomValues(new Uint8Array(FILE_ID_SIZE));
  const key = await deriveKey(password, salt);

  const chunks: Uint8Array[] = [];
  if (data.length === 0) throw new Error('Cannot encrypt empty file.');
  const numBlocks = Math.ceil(data.length / CHUNK_SIZE);

  for (let i = 0; i < numBlocks; i++) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const plaintext = data.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
    const aad = buildAAD(fileId, i);

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      key,
      plaintext
    );

    const block = new Uint8Array(IV_SIZE + ciphertext.byteLength);
    block.set(iv, 0);
    block.set(new Uint8Array(ciphertext), IV_SIZE);
    chunks.push(block);
  }

  // Compute total size and assemble output
  const totalSize = SALT_SIZE + FILE_ID_SIZE + chunks.reduce((acc, c) => acc + c.length, 0);
  const result = new Uint8Array(totalSize);
  let offset = 0;

  result.set(salt, offset);   offset += SALT_SIZE;
  result.set(fileId, offset); offset += FILE_ID_SIZE;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
};

export const decryptFile = async (data: Uint8Array, password: string): Promise<Uint8Array> => {
  let offset = 0;

  const salt   = data.slice(offset, offset + SALT_SIZE);   offset += SALT_SIZE;
  const fileId = data.slice(offset, offset + FILE_ID_SIZE); offset += FILE_ID_SIZE;

  const key = await deriveKey(password, salt);

  // Each block is IV_SIZE + CHUNK_SIZE + 16 (auth tag), except the last block may be smaller.
  // We don't know chunk count upfront, so we decrypt block-by-block until EOF.
  // The encrypted chunk size = IV_SIZE + plaintext_size + 16 (GCM tag).
  // Maximum encrypted block size (for a full 5 MiB plaintext chunk):
  const MAX_BLOCK_ENC_SIZE = IV_SIZE + CHUNK_SIZE + 16;

  const plaintextChunks: Uint8Array[] = [];
  let blockIndex = 0;

  while (offset < data.length) {
    // Determine how many bytes remain; a block is at most MAX_BLOCK_ENC_SIZE
    const remaining = data.length - offset;
    const blockEncSize = Math.min(remaining, MAX_BLOCK_ENC_SIZE);

    const iv         = data.slice(offset, offset + IV_SIZE);
    const ciphertext = data.slice(offset + IV_SIZE, offset + blockEncSize);
    const aad        = buildAAD(fileId, blockIndex);

    let plaintext: ArrayBuffer;
    try {
      plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        ciphertext
      );
    } catch {
      if (blockIndex === 0) {
        throw new Error('Decryption failed on first block: wrong password or corrupted file.');
      }
      throw new Error(`Decryption failed on block ${blockIndex}: file may be corrupted.`);
    }

    plaintextChunks.push(new Uint8Array(plaintext));
    offset += blockEncSize;
    blockIndex++;
  }

  // Reassemble plaintext
  const totalSize = plaintextChunks.reduce((acc, c) => acc + c.length, 0);
  const result = new Uint8Array(totalSize);
  let writeOffset = 0;
  for (const chunk of plaintextChunks) {
    result.set(chunk, writeOffset);
    writeOffset += chunk.length;
  }

  return result;
};

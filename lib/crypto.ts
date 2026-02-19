// Derive AES-GCM key from password using PBKDF2
export const deriveKey = async (password: string, salt: BufferSource): Promise<CryptoKey> => {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  // Derive AES-GCM key using PBKDF2
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

export const encryptFile = async (data: Uint8Array, password: string): Promise<Uint8Array> => {
  // Generate random salt and IV
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Derive key from password
  const key = await deriveKey(password, salt);

  // Encrypt the data (create a new Uint8Array to ensure proper ArrayBuffer type)
  const dataToEncrypt = new Uint8Array(data);
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    dataToEncrypt
  );

  // Combine salt + iv + encrypted data
  const encryptedArray = new Uint8Array(encryptedData);
  const result = new Uint8Array(salt.length + iv.length + encryptedArray.length);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(encryptedArray, salt.length + iv.length);

  return result;
};

export const decryptFile = async (data: Uint8Array, password: string): Promise<Uint8Array> => {
  // Extract salt, IV, and encrypted data (create new arrays to ensure proper ArrayBuffer type)
  const salt = new Uint8Array(data.slice(0, 16));
  const iv = new Uint8Array(data.slice(16, 28));
  const encryptedData = new Uint8Array(data.slice(28));

  // Derive key from password
  const key = await deriveKey(password, salt);

  // Decrypt the data
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    encryptedData
  );

  return new Uint8Array(decryptedData);
};

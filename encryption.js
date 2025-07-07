/**
 * Cherami Client-Side Encryption
 * This code runs in the browser and handles all encryption
 * 
 * The server NEVER sees your plaintext message or decryption key
 */

// Generate a new AES-256-GCM key for each message
async function generateKey() {
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true, // extractable
    ["encrypt", "decrypt"]
  );
}

// Encrypt a message
async function encryptMessage(plaintext, password = null) {
  // Generate key and IV
  const key = await generateKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Convert plaintext to bytes
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  
  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    data
  );
  
  // Export the key
  const rawKey = await crypto.subtle.exportKey("raw", key);
  
  // If password provided, wrap the key
  let keyData;
  if (password) {
    keyData = await wrapKeyWithPassword(rawKey, password);
  } else {
    keyData = {
      protected: false,
      key: bufferToBase64(rawKey)
    };
  }
  
  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv),
    keyData: keyData
  };
}

// Wrap key with password using PBKDF2
async function wrapKeyWithPassword(keyBuffer, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Derive key from password
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  
  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  
  // Wrap the original key
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    keyBuffer
  );
  
  return {
    protected: true,
    wrapped_key: bufferToBase64(wrapped),
    salt: bufferToBase64(salt),
    iv: bufferToBase64(iv)
  };
}

// Decrypt a message
async function decryptMessage(ciphertext, iv, keyData, password = null) {
  let key;
  
  // Unwrap key if password protected
  if (keyData.protected) {
    if (!password) throw new Error("Password required");
    
    const unwrappedKey = await unwrapKeyWithPassword(
      base64ToBuffer(keyData.wrapped_key),
      password,
      base64ToBuffer(keyData.salt),
      base64ToBuffer(keyData.iv)
    );
    
    key = await crypto.subtle.importKey(
      "raw",
      unwrappedKey,
      "AES-GCM",
      true,
      ["decrypt"]
    );
  } else {
    key = await crypto.subtle.importKey(
      "raw",
      base64ToBuffer(keyData.key),
      "AES-GCM",
      true,
      ["decrypt"]
    );
  }
  
  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBuffer(iv)
    },
    key,
    base64ToBuffer(ciphertext)
  );
  
  // Convert to text
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

// Unwrap password-protected key
async function unwrapKeyWithPassword(wrappedKey, password, salt, iv) {
  // Derive key from password
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  
  const unwrappingKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );
  
  // Unwrap the key
  const unwrapped = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    unwrappingKey,
    wrappedKey
  );
  
  return unwrapped;
}

// Helper functions
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Example usage
async function example() {
  // Encrypt a message
  const message = "This is a secret message!";
  const encrypted = await encryptMessage(message, "optional-password");
  
  console.log("Encrypted:", encrypted);
  
  // The encrypted data goes to the server
  // The keyData goes in the URL fragment (never sent to server)
  
  // To decrypt:
  const decrypted = await decryptMessage(
    encrypted.ciphertext,
    encrypted.iv,
    encrypted.keyData,
    "optional-password"
  );
  
  console.log("Decrypted:", decrypted);
}

// What the server sees:
// - Encrypted ciphertext (unreadable without key)
// - IV (safe to share, needed for decryption)
// - Metadata (expiration, view count, etc.)

// What the server NEVER sees:
// - Your plaintext message
// - The encryption key
// - Your password
// - The URL fragment containing the key
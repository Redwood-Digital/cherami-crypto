// LinkVault Client-Side Encryption (AES-GCM)
async function encryptMessage(plaintext) {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(plaintext);


  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );


  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );


  const exportedKey = await crypto.subtle.exportKey("raw", key);


  return {
    iv: btoa(String.fromCharCode(...iv)),
    cipher: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    key: btoa(String.fromCharCode(...new Uint8Array(exportedKey)))
  };
}
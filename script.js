async function getKey(password) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

function base64ToArrayBuffer(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

async function encryptText() {
  const text = document.getElementById('plaintext').value;
  const password = document.getElementById('key').value;
  if (!text || !password) return alert("Enter text and private key");

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await getKey(password);

  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(text)
  );

  const result = arrayBufferToBase64(iv) + ":" + arrayBufferToBase64(encrypted);
  document.getElementById('result').value = result;
}

async function decryptText() {
  const encryptedText = document.getElementById('result').value;
  const password = document.getElementById('key').value;
  if (!encryptedText || !password) return alert("Enter encrypted text and private key");

  const [ivBase64, dataBase64] = encryptedText.split(":");
  const iv = base64ToArrayBuffer(ivBase64);
  const data = base64ToArrayBuffer(dataBase64);
  const key = await getKey(password);

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );
    document.getElementById('plaintext').value = new TextDecoder().decode(decrypted);
  } catch (e) {
    alert("Decryption failed: wrong key or corrupted data");
  }
}

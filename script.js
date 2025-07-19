// Convert ArrayBuffer to Base64
function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// Convert Base64 to ArrayBuffer
function base64ToBuffer(base64) {
  try {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  } catch {
    throw new Error('Invalid Base64 input');
  }
}

// Derive AES key from password using PBKDF2
async function deriveKeyFromPassword(password) {
  const enc = new TextEncoder();
  const salt = enc.encode('fixed-salt');
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-CTR', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt text using AES-CTR
async function encryptText() {
  const text = document.getElementById('textInput').value.trim();
  const password = document.getElementById('privateKey').value.trim();

  if (!text) return alert('Please enter a message to encrypt.');
  if (!password || password.length < 8) {
    return alert('Private key must be at least 8 characters.');
  }

  try {
    const key = await deriveKeyFromPassword(password);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encoded = new TextEncoder().encode(text);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: iv, length: 128 },
      key,
      encoded
    );
    const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.byteLength);

    document.getElementById('output').value = bufferToBase64(combined);
  } catch (err) {
    alert('Encryption failed: ' + err.message);
  }
}

// Decrypt text using AES-CTR
async function decryptText() {
  const encryptedText = document.getElementById('textInput').value.trim();
  const password = document.getElementById('privateKey').value.trim();

  if (!encryptedText) return alert('Please enter encrypted text.');
  if (!password || password.length < 8) {
    return alert('Private key must be at least 8 characters.');
  }

  try {
    const key = await deriveKeyFromPassword(password);
    const combined = base64ToBuffer(encryptedText);
    const iv = combined.slice(0, 16);
    const ciphertext = combined.slice(16);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CTR', counter: iv, length: 128 },
      key,
      ciphertext
    );
    document.getElementById('output').value = new TextDecoder().decode(decrypted);
  } catch (err) {
    alert('Decryption failed: ' + err.message);
  }
}

// Generate a random private key
function generatePrivateKey() {
  const randomArray = crypto.getRandomValues(new Uint8Array(16));
  const hex = Array.from(randomArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  document.getElementById('privateKey').value = hex;
  alert('Generated key copied to input field. Store it securely!');
}

// Copy private key to clipboard
function copyPrivateKey() {
  const privateKey = document.getElementById('privateKey').value.trim();
  if (!privateKey) return alert('No private key to copy.');
  navigator.clipboard.writeText(privateKey)
    .then(() => alert('Private key copied to clipboard!'))
    .catch(err => alert('Failed to copy: ' + err.message));
}

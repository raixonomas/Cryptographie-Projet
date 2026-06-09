let myKeyPair;
let mySignKeyPair;
let sharedKey;

async function generateIdentity() {
  myKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );

  mySignKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const pubECDH = await crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
  const pubSign = await crypto.subtle.exportKey("jwk", mySignKeyPair.publicKey);

  const fp = await getFingerprint(pubSign);

  log("🔑 Fingerprint:<br>" + fp);

  ws.send(JSON.stringify({
    type: "pubkey",
    id: myId,
    key: { ecdh: pubECDH, sign: pubSign }
  }));
}

async function deriveKey(peerJwk) {
  const peerKey = await crypto.subtle.importKey(
    "jwk",
    peerJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  return crypto.subtle.deriveKey(
    { name: "ECDH", public: peerKey },
    myKeyPair.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(msg) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(msg);

  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    sharedKey,
    enc
  );

  return {
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(cipher))
  };
}

async function decrypt(payload) {
  return new TextDecoder().decode(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(payload.iv) },
      sharedKey,
      new Uint8Array(payload.data)
    )
  );
}

async function sign(data) {
  const encoded = new TextEncoder().encode(data);

  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    mySignKeyPair.privateKey,
    encoded
  );

  return Array.from(new Uint8Array(sig));
}

async function verify(signature, data, peerSignPubKey) {
  const key = await crypto.subtle.importKey(
    "jwk",
    peerSignPubKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new Uint8Array(signature),
    new TextEncoder().encode(data)
  );
}

async function getFingerprint(publicJwk) {
  const key = await crypto.subtle.importKey(
    "jwk",
    publicJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );

  const raw = await crypto.subtle.exportKey("raw", key);
  const hash = await crypto.subtle.digest("SHA-256", raw);

  return Array.from(new Uint8Array(hash))
    .slice(0, 16)
    .map(x => x.toString(16).padStart(2, "0"))
    .join(":")
    .toUpperCase();
}
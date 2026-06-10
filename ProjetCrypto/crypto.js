let myIdentityKey, mySignedPreKey, myOneTimePreKeys = [];
let activeRatchetSessions = new Map();

async function getFingerprint(jwk) {
  const json = JSON.stringify(jwk);
  const buffer = new TextEncoder().encode(json);
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).toUpperCase().padStart(2, '0'))
    .join(':');
}

async function hkdf(secretBits, saltBits, infoString) {
  const enc = new TextEncoder();
  const infoBuffer = enc.encode(infoString);

  const saltBytes = saltBits.length === 0 ? new Uint8Array(32) : new Uint8Array(saltBits);
  const secretBytes = new Uint8Array(secretBits);

  const saltKey = await crypto.subtle.importKey(
    "raw",
    saltBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const prkBuffer = await crypto.subtle.sign({ name: "HMAC" }, saltKey, secretBytes);
  const prkKey = await crypto.subtle.importKey(
    "raw",
    prkBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const infoWithCounter = new Uint8Array(infoBuffer.length + 1);
  infoWithCounter.set(infoBuffer, 0);
  infoWithCounter.set([1], infoBuffer.length);

  const finalOutputBuffer = await crypto.subtle.sign({ name: "HMAC" }, prkKey, infoWithCounter);
  return finalOutputBuffer; 
}

async function computeDH(privateKeyObject, publicJwk) {
  const publicKeyObject = await crypto.subtle.importKey(
    "jwk",
    publicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKeyObject },
    privateKeyObject,
    256
  );
  return bits; 
}

async function generateIdentity() {
  myIdentityKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  mySignedPreKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  
  myOneTimePreKeys = [];
  for(let i = 0; i < 3; i++) {
    let opk = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    opk.kid = `opk_key_${i}`;
    myOneTimePreKeys.push(opk);
  }

  const ikJwk = await crypto.subtle.exportKey("jwk", myIdentityKey.publicKey);
  const spkJwk = await crypto.subtle.exportKey("jwk", mySignedPreKey.publicKey);
  
  const opkJwks = await Promise.all(myOneTimePreKeys.map(async (k, idx) => {
    const jwk = await crypto.subtle.exportKey("jwk", k.publicKey);
    jwk.kid = `opk_key_${idx}`; 
    return jwk;
  }));

  const fp = await getFingerprint(ikJwk);
  log(`🔑 Your Identity Fingerprint:<br><b>${fp}</b>`);

  ws.send(JSON.stringify({
    type: "publish_bundle",
    bundle: { ik: ikJwk, spk: spkJwk, opk: opkJwks }
  }));
}

async function initiateX3DHSession(peerId, bundle) {
  const ekA = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const selectedOpk = Array.isArray(bundle.opk) ? bundle.opk[0] : bundle.opk;

  const dh1 = await computeDH(myIdentityKey.privateKey, bundle.spk);
  const dh2 = await computeDH(ekA.privateKey, bundle.ik);
  const dh3 = await computeDH(ekA.privateKey, bundle.spk);

  let combinedSize = 96;
  if (selectedOpk) combinedSize += 32;
  
  const combinedSecret = new Uint8Array(combinedSize);
  combinedSecret.set(new Uint8Array(dh1), 0);
  combinedSecret.set(new Uint8Array(dh2), 32);
  combinedSecret.set(new Uint8Array(dh3), 64);

  if (selectedOpk) {
    const dh4 = await computeDH(ekA.privateKey, selectedOpk);
    combinedSecret.set(new Uint8Array(dh4), 96);
  }

  const masterKey = await hkdf(combinedSecret.buffer, new Uint8Array(32), "X3DH_Master_Secret_Salt");
  
  const ekAJwk = await crypto.subtle.exportKey("jwk", ekA.publicKey);
  const ikAJwk = await crypto.subtle.exportKey("jwk", myIdentityKey.publicKey);

  const session = new RatchetSession(masterKey, true, bundle.spk, ekA);
  activeRatchetSessions.set(peerId, session);

  return { ekA: ekAJwk, ikA: ikAJwk, usedOpk: selectedOpk };
}

async function receiveX3DHSession(peerId, x3dhHeader) {
  const selectedOpk = Array.isArray(x3dhHeader.usedOpk) ? x3dhHeader.usedOpk[0] : x3dhHeader.usedOpk;

  const dh1 = await computeDH(mySignedPreKey.privateKey, x3dhHeader.ikA);
  const dh2 = await computeDH(myIdentityKey.privateKey, x3dhHeader.ekA);
  const dh3 = await computeDH(mySignedPreKey.privateKey, x3dhHeader.ekA);

  let combinedSize = 96;
  if (selectedOpk) combinedSize += 32;

  const combinedSecret = new Uint8Array(combinedSize);
  combinedSecret.set(new Uint8Array(dh1), 0);
  combinedSecret.set(new Uint8Array(dh2), 32);
  combinedSecret.set(new Uint8Array(dh3), 64);

  if (selectedOpk) {
    const localOpkKeyPair = myOneTimePreKeys.find(k => k.kid === selectedOpk.kid) || myOneTimePreKeys[0];
    const dh4 = await computeDH(localOpkKeyPair.privateKey, x3dhHeader.ekA);
    combinedSecret.set(new Uint8Array(dh4), 96);
  }

  const masterKey = await hkdf(combinedSecret.buffer, new Uint8Array(32), "X3DH_Master_Secret_Salt");

  const session = new RatchetSession(masterKey, false, x3dhHeader.ekA, null);
  activeRatchetSessions.set(peerId, session);
}

class RatchetSession {
  constructor(masterKeyBuffer, isInitiator, remoteDhJwk, localDhKeyPair) {
    this.rootKey = masterKeyBuffer.slice(0, 16);
    const initialChainKey = masterKeyBuffer.slice(16, 32);
    
    this.isInitiator = isInitiator;
    this.remoteDhJwk = remoteDhJwk; 
    this.localDhKey = localDhKeyPair;

    this.isFirstMessage = !isInitiator;

    if (isInitiator) {
      this.sendingChainKey = initialChainKey;
      this.receivingChainKey = null;
    } else {
      this.sendingChainKey = null;
      this.receivingChainKey = initialChainKey;
    }
  }

  async stepSymmetric(chainKeyBuffer) {
    const derived = await hkdf(chainKeyBuffer, new Uint8Array(0), "Symmetric_Ratchet_Step");
    
    const nextChainKey = derived.slice(0, 16);
    const msgKeyBits = derived.slice(16, 32);
    return [nextChainKey, msgKeyBits];
  }

  async performAsymmetricRatchet(remoteDhJwk) {
    this.remoteDhJwk = remoteDhJwk;

    const dhBitsReceive = await computeDH(this.localDhKey.privateKey, this.remoteDhJwk);
    const rootOutputReceive = await hkdf(dhBitsReceive, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
    this.rootKey = rootOutputReceive.slice(0, 16);
    this.receivingChainKey = rootOutputReceive.slice(16, 32);

    this.localDhKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    
    const dhBitsSend = await computeDH(this.localDhKey.privateKey, this.remoteDhJwk);
    const rootOutputSend = await hkdf(dhBitsSend, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
    this.rootKey = rootOutputSend.slice(0, 16);
    this.sendingChainKey = rootOutputSend.slice(16, 32);
  }

  async encrypt(plaintext) {
    this.isFirstMessage = false;

    if (!this.localDhKey) {
      this.localDhKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      const dhBits = await computeDH(this.localDhKey.privateKey, this.remoteDhJwk);
      const rootOutput = await hkdf(dhBits, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
      this.rootKey = rootOutput.slice(0, 16);
      this.sendingChainKey = rootOutput.slice(16, 32);
    }

    const [nextChain, msgKeyBits] = await this.stepSymmetric(this.sendingChainKey);
    this.sendingChainKey = nextChain;

    const aesKey = await crypto.subtle.importKey("raw", msgKeyBits, { name: "AES-GCM" }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(plaintext));

    const localDhJwk = await crypto.subtle.exportKey("jwk", this.localDhKey.publicKey);

    return {
      dhHeader: localDhJwk,
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(encrypted))
    };
  }

  async decrypt(payload) {
    if (this.isFirstMessage) {
      this.isFirstMessage = false;
      this.remoteDhJwk = payload.dhHeader;
    } 
    else {
      const isNewKey = payload.dhHeader && (!this.remoteDhJwk || JSON.stringify(this.remoteDhJwk) !== JSON.stringify(payload.dhHeader));
      if (isNewKey) {
        await this.performAsymmetricRatchet(payload.dhHeader);
      }
    }

    const [nextChain, msgKeyBits] = await this.stepSymmetric(this.receivingChainKey);
    this.receivingChainKey = nextChain;

    const aesKey = await crypto.subtle.importKey("raw", msgKeyBits, { name: "AES-GCM" }, false, ["decrypt"]);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(payload.iv) },
      aesKey,
      new Uint8Array(payload.ciphertext)
    );

    return new TextDecoder().decode(decrypted);
  }
}
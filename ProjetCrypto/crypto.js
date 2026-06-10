// Global cryptographic state for the logged-in user
let myIdentityKey, mySignedPreKey, myOneTimePreKeys = [];
let activeRatchetSessions = new Map(); // peerId -> RatchetSession instance

/**
 * Helper: Simple SHA-256 Fingerprint generation
 */
async function getFingerprint(jwk) {
  const json = JSON.stringify(jwk);
  const buffer = new TextEncoder().encode(json);
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).toUpperCase().padStart(2, '0'))
    .join(':');
}

/**
 * Helper: Robust HKDF extraction layer built on top of SubtleCrypto HMAC
 */
async function hkdf(secretBits, saltBits, infoString) {
  const enc = new TextEncoder();
  const infoBuffer = enc.encode(infoString);

  const saltBytes = saltBits.length === 0 ? new Uint8Array(32) : new Uint8Array(saltBits);
  const secretBytes = new Uint8Array(secretBits);

  const saltKey = await crypto.subtle.importKey(
    "raw",
    saltBytes,
    { name: "HMAC", hash: "SHA-256" }, // ✅ Fixed escaped quotes syntax error
    false,
    ["sign"]
  );

  const prkBuffer = await crypto.subtle.sign({ name: "HMAC" }, saltKey, secretBytes);
  const prkKey = await crypto.subtle.importKey(
    "raw",
    prkBuffer,
    { name: "HMAC", hash: "SHA-256" }, // ✅ Fixed escaped quotes syntax error
    false,
    ["sign"]
  );

  const infoWithCounter = new Uint8Array(infoBuffer.length + 1);
  infoWithCounter.set(infoBuffer, 0);
  infoWithCounter.set([1], infoBuffer.length);

  const finalOutputBuffer = await crypto.subtle.sign({ name: "HMAC" }, prkKey, infoWithCounter);
  return finalOutputBuffer; 
}

/**
 * Helper: Computes a raw shared secret using ECDH deriveBits
 */
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

/**
 * Generates X3DH Public Key Bundle
 */
async function generateIdentity() {
  console.log("⚙️ [X3DH Setup] Starting key generation sequence...");
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

/**
 * Alice (Initiator) computes X3DH Master Secret
 */
async function initiateX3DHSession(peerId, bundle) {
  console.log(`📡 [X3DH Initiator] Starting X3DH Key Agreement with peer: ${peerId}`);
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

  // ✅ Fixed constructor argument positioning: remote public JWK goes third, local KeyPair goes fourth
  const session = new RatchetSession(masterKey, true, bundle.spk, ekA);
  activeRatchetSessions.set(peerId, session);

  return { ekA: ekAJwk, ikA: ikAJwk, usedOpk: selectedOpk };
}

/**
 * Bob (Receiver) replicates X3DH Master Secret
 */
async function receiveX3DHSession(peerId, x3dhHeader) {
  console.log(`📥 [X3DH Receiver] Processing inbound X3DH offer from: ${peerId}`);

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

    console.log(`🏁 [Ratchet Constructor] State isolated. Role: ${isInitiator ? 'Initiator' : 'Receiver'}`);
  }

  async stepSymmetric(chainKeyBuffer) {
    // Use one derivation label for both directions. Using different labels here
    // makes the sender and receiver derive different message keys from the same
    // chain state, which is exactly what triggers the "Bad Ratchet Synchronicity" error.
    const derived = await hkdf(chainKeyBuffer, new Uint8Array(0), "Symmetric_Ratchet_Step");
    
    const nextChainKey = derived.slice(0, 16);
    const msgKeyBits = derived.slice(16, 32);
    return [nextChainKey, msgKeyBits];
  }

  /**
   * Drives asymmetric ratchet forward when a new remote ephemeral key arrives
   */
  async performAsymmetricRatchet(remoteDhJwk) {
    console.log("🔄 [Asymmetric Ratchet Turn] Advancing structural key layer...");
    this.remoteDhJwk = remoteDhJwk;

    // 1. Terminate current receive chain using our existing local key pair against their new key
    const dhBitsReceive = await computeDH(this.localDhKey.privateKey, this.remoteDhJwk);
    const rootOutputReceive = await hkdf(dhBitsReceive, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
    this.rootKey = rootOutputReceive.slice(0, 16);
    this.receivingChainKey = rootOutputReceive.slice(16, 32);

    // 2. Generate a new local ephemeral key pair to step our send sequence forward
    this.localDhKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    
    // 3. Advance root key to build a clean sending chain base
    const dhBitsSend = await computeDH(this.localDhKey.privateKey, this.remoteDhJwk);
    const rootOutputSend = await hkdf(dhBitsSend, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
    this.rootKey = rootOutputSend.slice(0, 16);
    this.sendingChainKey = rootOutputSend.slice(16, 32);
  }

  async encrypt(plaintext) {
    console.log(`🔒 [Encrypt Action] Encrypting payload: "${plaintext}"`);

    // Once a session sends its first packet, it is no longer in the special
    // message-0 alignment phase. This is critical for Bob's session, because
    // Bob sends first and then receives Alice's reply later.
    this.isFirstMessage = false;

    // Fix: If Bob (or Alice later) does not have an active sending chain initialized, 
    // generate the local keypair and execute a DH step to securely advance the root sequence.
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
    console.log("🔓 [Decrypt Action] Processing inbound package...", payload);

    // 1. Check for Message 0 processing
    if (this.isFirstMessage) {
      console.log("🎯 [Message 0 Alignment] Running initial cryptographic lock step.");
      this.isFirstMessage = false;
      this.remoteDhJwk = payload.dhHeader; // Update pointer to Alice's active public key
    } 
    // 2. Standard asymmetric rotation step for all subsequent turns
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
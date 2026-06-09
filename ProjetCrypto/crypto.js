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

  const dh1 = await computeDH(myIdentityKey.privateKey, bundle.spk);
  const dh2 = await computeDH(ekA.privateKey, bundle.ik);
  const dh3 = await computeDH(ekA.privateKey, bundle.spk);

  let combinedSize = 96;
  if (bundle.opk) combinedSize += 32;
  
  const combinedSecret = new Uint8Array(combinedSize);
  combinedSecret.set(new Uint8Array(dh1), 0);
  combinedSecret.set(new Uint8Array(dh2), 32);
  combinedSecret.set(new Uint8Array(dh3), 64);

  if (bundle.opk) {
    const dh4 = await computeDH(ekA.privateKey, bundle.opk);
    combinedSecret.set(new Uint8Array(dh4), 96);
  }

  const masterKey = await hkdf(combinedSecret.buffer, new Uint8Array(32), "X3DH_Master_Secret_Salt");
  
  const ekAJwk = await crypto.subtle.exportKey("jwk", ekA.publicKey);
  const ikAJwk = await crypto.subtle.exportKey("jwk", myIdentityKey.publicKey);

  // Initialize session. Alice holds the local Ephemeral Key used for the agreement.
  const session = new RatchetSession(masterKey, true, ekA);
  activeRatchetSessions.set(peerId, session);

  return { ekA: ekAJwk, ikA: ikAJwk, usedOpk: bundle.opk };
}

/**
 * Bob (Receiver) replicates X3DH Master Secret
 */
async function receiveX3DHSession(peerId, x3dhHeader) {
  console.log(`📥 [X3DH Receiver] Processing inbound X3DH offer from: ${peerId}`);

  const dh1 = await computeDH(mySignedPreKey.privateKey, x3dhHeader.ikA);
  const dh2 = await computeDH(myIdentityKey.privateKey, x3dhHeader.ekA);
  const dh3 = await computeDH(mySignedPreKey.privateKey, x3dhHeader.ekA);

  let combinedSize = 96;
  if (x3dhHeader.usedOpk) combinedSize += 32;

  const combinedSecret = new Uint8Array(combinedSize);
  combinedSecret.set(new Uint8Array(dh1), 0);
  combinedSecret.set(new Uint8Array(dh2), 32);
  combinedSecret.set(new Uint8Array(dh3), 64);

  if (x3dhHeader.usedOpk) {
    let localOpkKeyPair = myOneTimePreKeys.find(k => k.kid === x3dhHeader.usedOpk.kid) || myOneTimePreKeys[0]; 
    const dh4 = await computeDH(localOpkKeyPair.privateKey, x3dhHeader.ekA);
    combinedSecret.set(new Uint8Array(dh4), 96);
  }

  const masterKey = await hkdf(combinedSecret.buffer, new Uint8Array(32), "X3DH_Master_Secret_Salt");

  // Bob tracks Alice's remote X3DH key header to evaluate changes later
  const session = new RatchetSession(masterKey, false, x3dhHeader.ekA);
  activeRatchetSessions.set(peerId, session);
}

/**
 * Double Ratchet Session State Machine
 */
class RatchetSession {
  constructor(masterKeyBuffer, isInitiator, dhKeyOrJwk) {
    // Drive Root Key and Initial Base Chain Key directly from Master Key
    this.rootKey = masterKeyBuffer.slice(0, 16);
    const initialChainKey = masterKeyBuffer.slice(16, 32);
    
    this.isInitiator = isInitiator;
    
    if (isInitiator) {
      // Alice uses her active X3DH keypair directly to anchor her first sending sequence
      this.localDhKey = dhKeyOrJwk; 
      this.remoteDhJwk = null;
      this.sendingChainKey = initialChainKey;
      this.receivingChainKey = null;
    } else {
      // Bob registers Alice's key as his baseline tracking reference
      this.localDhKey = null;
      this.remoteDhJwk = dhKeyOrJwk;
      this.sendingChainKey = null;
      this.receivingChainKey = initialChainKey;
    }

    console.log(`🏁 [Ratchet Session Created] Role: ${isInitiator ? 'Initiator' : 'Receiver'}`);
  }

  async stepSymmetric(chainKey, isSending) {
    const info = isSending ? "Symmetric_Send_Step" : "Symmetric_Recv_Step";
    const nextBits = await hkdf(chainKey, new Uint8Array(32), info);
    
    return [
      nextBits.slice(0, 16),  // Next Chain Key
      nextBits.slice(16, 32)  // Message Encryption Key
    ];
  }

  async performAsymmetricRatchet(newRemoteDhJwk) {
    console.log("🔄 [Asymmetric Ratchet Turn] Advancing DH Root Key layer...");
    this.remoteDhJwk = newRemoteDhJwk;
    
    // 1. Compute receiving chain updates using old local key against the new remote key
    const dhBitsRecv = await computeDH(this.localDhKey.privateKey, this.remoteDhJwk);
    const rootOutputRecv = await hkdf(dhBitsRecv, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
    this.rootKey = rootOutputRecv.slice(0, 16);
    this.receivingChainKey = rootOutputRecv.slice(16, 32);

    // 2. Generate a fresh keypair to spin up a new sending chain sequence
    this.localDhKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    
    const dhBitsSend = await computeDH(this.localDhKey.privateKey, this.remoteDhJwk);
    const rootOutputSend = await hkdf(dhBitsSend, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
    this.rootKey = rootOutputSend.slice(0, 16);
    this.sendingChainKey = rootOutputSend.slice(16, 32);
  }

  async encrypt(plaintext) {
    console.log(`🔒 [Encrypt Action] Encrypting payload: "${plaintext}"`);

    // If an initiator needs to respond after an incoming turn but has no active sending chain, handle the update step
    if (!this.sendingChainKey) {
      this.localDhKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      const dhBits = await computeDH(this.localDhKey.privateKey, this.remoteDhJwk);
      const rootOutput = await hkdf(dhBits, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
      this.rootKey = rootOutput.slice(0, 16);
      this.sendingChainKey = rootOutput.slice(16, 32);
    }

    const [nextChain, msgKeyBits] = await this.stepSymmetric(this.sendingChainKey, true);
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
    console.log("🔓 [Decrypt Action] Processing inbound package...");

    const isNewKey = payload.dhHeader && (!this.remoteDhJwk || JSON.stringify(this.remoteDhJwk) !== JSON.stringify(payload.dhHeader));
    
    // Check if the remote key has advanced
    if (isNewKey) {
      if (!this.isInitiator && !this.localDhKey) {
        // First message processing step for Bob (the Receiver)
        this.remoteDhJwk = payload.dhHeader;
        // Compute DH using Bob's local Signed Pre-Key to lock states with Alice's baseline key
        const dhBits = await computeDH(mySignedPreKey.privateKey, this.remoteDhJwk);
        const rootOutput = await hkdf(dhBits, new Uint8Array(this.rootKey), "DH_Ratchet_Step");
        this.rootKey = rootOutput.slice(0, 16);
        this.receivingChainKey = rootOutput.slice(16, 32);
        
        // Prepare Bob's next local ephemeral generation step ahead of responses
        this.localDhKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      } else {
        // Subsequent structural ratchet rotation step
        await this.performAsymmetricRatchet(payload.dhHeader);
      }
    }

    const [nextChain, msgKeyBits] = await this.stepSymmetric(this.receivingChainKey, false);
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
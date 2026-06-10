const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadCryptoRuntime() {
  const source = fs.readFileSync(path.join(__dirname, 'crypto.js'), 'utf8');
  const context = {
    console,
    crypto: require('node:crypto').webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    JSON,
    Promise,
    window: {},
    document: { getElementById: () => ({ value: '', innerHTML: '' }) },
  };

  vm.createContext(context);
  vm.runInContext(
    source + '\nthis.RatchetSession = RatchetSession; this.initiateX3DHSession = initiateX3DHSession; this.receiveX3DHSession = receiveX3DHSession; this.activeRatchetSessions = activeRatchetSessions;',
    context
  );

  return context;
}

async function generateIdentityState(runtime) {
  const identityKey = await runtime.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const signedPreKey = await runtime.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const oneTimePreKeys = [];
  for (let i = 0; i < 2; i += 1) {
    const key = await runtime.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    key.kid = `opk_key_${i}`;
    oneTimePreKeys.push(key);
  }

  runtime.__tempIdentityKey = identityKey;
  runtime.__tempSignedPreKey = signedPreKey;
  runtime.__tempOneTimePreKeys = oneTimePreKeys;

  vm.runInContext(
    'myIdentityKey = __tempIdentityKey; mySignedPreKey = __tempSignedPreKey; myOneTimePreKeys = __tempOneTimePreKeys;',
    runtime
  );

  const ik = await runtime.crypto.subtle.exportKey('jwk', identityKey.publicKey);
  const spk = await runtime.crypto.subtle.exportKey('jwk', signedPreKey.publicKey);
  const opk = await Promise.all(oneTimePreKeys.map(async (k) => {
    const jwk = await runtime.crypto.subtle.exportKey('jwk', k.publicKey);
    jwk.kid = k.kid;
    return jwk;
  }));

  return { ik, spk, opk };
}

test('Bob can send the first encrypted message and Alice can decrypt it', async () => {
  const aliceRuntime = loadCryptoRuntime();
  const bobRuntime = loadCryptoRuntime();

  const bobBundle = await generateIdentityState(bobRuntime);
  await generateIdentityState(aliceRuntime);

  const x3dhHeader = await aliceRuntime.initiateX3DHSession('bob', bobBundle);
  await bobRuntime.receiveX3DHSession('alice', x3dhHeader);

  const aliceSession = aliceRuntime.activeRatchetSessions.get('bob');
  const bobSession = bobRuntime.activeRatchetSessions.get('alice');

  assert.ok(aliceSession, 'Alice should have an active session after X3DH setup');
  assert.ok(bobSession, 'Bob should have an active session after X3DH setup');

  const payload = await bobSession.encrypt('first message from bob');
  const plaintext = await aliceSession.decrypt(payload);

  assert.equal(plaintext, 'first message from bob');
});

test('Alice can reply after Bob sends first and Bob can decrypt the reply', async () => {
  const aliceRuntime = loadCryptoRuntime();
  const bobRuntime = loadCryptoRuntime();

  const bobBundle = await generateIdentityState(bobRuntime);
  await generateIdentityState(aliceRuntime);

  const x3dhHeader = await aliceRuntime.initiateX3DHSession('bob', bobBundle);
  await bobRuntime.receiveX3DHSession('alice', x3dhHeader);

  const aliceSession = aliceRuntime.activeRatchetSessions.get('bob');
  const bobSession = bobRuntime.activeRatchetSessions.get('alice');

  const bobFirstPayload = await bobSession.encrypt('first message from bob');
  await aliceSession.decrypt(bobFirstPayload);

  const aliceReplyPayload = await aliceSession.encrypt('reply from alice');
  const bobPlaintext = await bobSession.decrypt(aliceReplyPayload);

  assert.equal(bobPlaintext, 'reply from alice');
});

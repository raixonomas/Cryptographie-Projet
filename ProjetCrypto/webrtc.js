let pc;
let dc;
let currentPeerId;

const config = {
  iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
};

async function startChat(user) {
  const fp = await getFingerprint(user.pubkey.sign);

  if (!trustedFingerprints.has(fp)) {
    const trust = confirm(`Verify fingerprint:\n\n${fp}`);
    if (!trust) return;

    trustedFingerprints.add(fp);
  }

  sharedKey = await deriveKey(user.pubkey.ecdh);
  currentPeerId = user.id;

  pc = new RTCPeerConnection(config);
  dc = pc.createDataChannel("chat");
  setupDC();

  pc.onicecandidate = e => {
    if (!e.candidate) {
      sendSignal(user.id, pc.localDescription);
    }
  };

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
}

function setupDC() {
  dc.onopen = () => log("🔐 Secure connection established");

  dc.onmessage = async (e) => {
    const msg = JSON.parse(e.data);
    const peer = getUser(currentPeerId);

    const ok = await verify(
      msg.signature,
      JSON.stringify(msg.encrypted),
      peer.pubkey.sign
    );

    if (!ok) return log("❌ Invalid signature");

    const text = await decrypt(msg.encrypted);

    log(peer.id + ": " + text);
  };
}

async function handleSignal(msg) {
  currentPeerId = msg.from;

  if (!pc) {
    pc = new RTCPeerConnection(config);

    pc.ondatachannel = e => {
      dc = e.channel;
      setupDC();
    };

    pc.onicecandidate = e => {
      if (!e.candidate) {
        sendSignal(msg.from, pc.localDescription);
      }
    };
  }

  await pc.setRemoteDescription(msg.data);

  if (msg.data.type === "offer") {
    const peer = getUser(msg.from);

    sharedKey = await deriveKey(peer.pubkey.ecdh);

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
  }
}

async function sendMessage() {
  const text = document.getElementById("msg").value;

  if (!sharedKey) return log("⚠️ Not connected");

  const encrypted = await encrypt(text);
  const signature = await sign(JSON.stringify(encrypted));

  dc.send(JSON.stringify({ encrypted, signature }));

  log("You: " + text);
  document.getElementById("msg").value = "";
}
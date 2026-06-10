let pc;
let dc;
let currentPeerId;

const peerConnections = new Map();
const dataChannels = new Map();

const config = { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] };

function getPeerConnection(peerId) {
  return peerConnections.get(peerId) || null;
}

function setPeerConnection(peerId, connection) {
  peerConnections.set(peerId, connection);
  pc = connection;
  return connection;
}

function getDataChannel(peerId) {
  return dataChannels.get(peerId) || null;
}

function setDataChannel(peerId, channel) {
  dataChannels.set(peerId, channel);
  dc = channel;
  return channel;
}

async function handleBundleResponse(msg) {
  currentPeerId = msg.targetId;
  ensureDiscussion(currentPeerId);
  selectDiscussion(currentPeerId);

  const fp = await getFingerprint(msg.ik);
  if (!trustedFingerprints.has(fp)) {
    const trust = await window.showConfirmDialog(
      `Verify identity for ${currentPeerId}`,
      `Verify identity key fingerprint for ${currentPeerId}:\n\n${fp}`
    );
    if (!trust) return;
    trustedFingerprints.add(fp);
  }

  const x3dhHeader = await initiateX3DHSession(currentPeerId, msg);

  pc = getPeerConnection(currentPeerId) || new RTCPeerConnection(config);
  setPeerConnection(currentPeerId, pc);
  
  dc = getDataChannel(currentPeerId) || pc.createDataChannel("chat");
  setDataChannel(currentPeerId, dc);
  setupDC(currentPeerId, dc);

  pc.onicecandidate = e => {
    if (!e.candidate) {
      sendSignal(currentPeerId, {
        sdp: {
          type: pc.localDescription.type,
          sdp: pc.localDescription.sdp
        },
        x3dh: x3dhHeader
      });
    }
  };

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
}

function setupDC(peerId = currentPeerId, channel = dc) {
  if (!channel) return;

  channel.onopen = () => {
    log("🔐 End-to-End Encrypted Double Ratchet Connection Active!");
  };

  channel.onmessage = async (e) => {
    const payload = JSON.parse(e.data);
    const session = activeRatchetSessions.get(peerId);

    if (!session) {
      log(`⚠️ Received a message but no active cryptographic session found for ${peerId}`);
      return;
    }

    try {
      const plainText = await session.decrypt(payload);
      appendMessage(peerId, peerId, plainText);
    } catch(err) {
      log("❌ Failed to decrypt inbound packet. Bad Ratchet Synchronicity.");
      console.error(err);
    }
  };

  channel.onerror = (err) => console.error("Data Channel Error:", err);
}

async function handleSignal(msg) {
  const signalingPeer = msg.from;
  currentPeerId = signalingPeer;
  ensureDiscussion(signalingPeer);
  selectDiscussion(signalingPeer);

  let peerConnection = getPeerConnection(signalingPeer);
  if (!peerConnection) {
    peerConnection = new RTCPeerConnection(config);
    setPeerConnection(signalingPeer, peerConnection);
  }

  if (!msg.data) return;

  let sdpInit = null;
  if (msg.data.sdp && typeof msg.data.sdp === "object") {
    sdpInit = msg.data.sdp;
  } else if (msg.data.type && msg.data.sdp) {
    sdpInit = msg.data;
  }

  if (msg.data.x3dh) {
    currentPeerId = signalingPeer;
    await receiveX3DHSession(signalingPeer, msg.data.x3dh);
  }

  if (!sdpInit || !sdpInit.type || !sdpInit.sdp) {
    return;
  }

  if (sdpInit.type === "answer" && peerConnection && peerConnection.signalingState === "stable") {
    console.warn("[WebRTC State Guard] Connection already stable. Ignoring duplicate remote answer.");
    return;
  }

  if (!peerConnection) {
    peerConnection = new RTCPeerConnection(config);
    setPeerConnection(signalingPeer, peerConnection);
  }

  if (!getDataChannel(signalingPeer)) {
    peerConnection.ondatachannel = e => {
      const channel = e.channel;
      setDataChannel(signalingPeer, channel);
      setupDC(signalingPeer, channel);
    };
  }

  peerConnection.onicecandidate = e => {
    if (!e.candidate) {
      sendSignal(signalingPeer, {
        type: peerConnection.localDescription.type,
        sdp: peerConnection.localDescription.sdp
      });
    }
  };

  try {
    await peerConnection.setRemoteDescription(new RTCSessionDescription({
      type: sdpInit.type,
      sdp: sdpInit.sdp
    }));
  } catch (err) {
    console.error("❌ Failed to set remote description:", err);
    return;
  }

  if (sdpInit.type === "offer") {
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);

    if (peerConnection.iceGatheringState === "complete") {
      sendSignal(signalingPeer, {
        type: peerConnection.localDescription.type,
        sdp: peerConnection.localDescription.sdp
      });
    }
  }
}

async function sendMessage() {
  const textInput = document.getElementById("msg");
  const text = textInput.value;
  if (!text.trim()) return;
  
  const peerId = currentPeerId || activeDiscussionId;
  const session = activeRatchetSessions.get(peerId);
  const channel = getDataChannel(peerId) || dc;

  if (!session || !channel || channel.readyState !== "open") {
    return log("⚠️ Secure channel uninitialized or connection closing.");
  }

  const payload = await session.encrypt(text);

  channel.send(JSON.stringify(payload));
  appendMessage(peerId, "You", text);
  textInput.value = "";
}
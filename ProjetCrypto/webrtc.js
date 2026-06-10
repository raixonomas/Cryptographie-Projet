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

/**
 * Initiator (Alice) requests the server bundle and starts WebRTC setup
 */
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

  // 1. Run X3DH to build local session state
  const x3dhHeader = await initiateX3DHSession(currentPeerId, msg);

  // 2. Setup standard WebRTC Peer Connection
  pc = getPeerConnection(currentPeerId) || new RTCPeerConnection(config);
  setPeerConnection(currentPeerId, pc);
  
  // 3. Immediately open the data channel
  dc = getDataChannel(currentPeerId) || pc.createDataChannel("chat");
  setDataChannel(currentPeerId, dc);
  setupDC(currentPeerId, dc);

  pc.onicecandidate = e => {
    if (!e.candidate) {
      console.log("🚀 [ICE Initiator] ICE gathering complete. Sending offer with X3DH header.");
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

/**
 * Attaches event listeners to the data channel cleanly
 */
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

    console.log("Decrypt payload :", payload, peerId, session);
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

/**
 * Standard inbound signal router with State Guardrails
 */
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

  console.log(`📡 [WebRTC Signaling] Signal received from: ${signalingPeer}. Current PC State: ${peerConnection ? peerConnection.signalingState : 'null'}`);

  if (!msg.data) return;

  // Extract the structured SDP block safely
  let sdpInit = null;
  if (msg.data.sdp && typeof msg.data.sdp === "object") {
    sdpInit = msg.data.sdp;
  } else if (msg.data.type && msg.data.sdp) {
    sdpInit = msg.data;
  }

  // Handle incoming X3DH bundle initialization
  if (msg.data.x3dh) {
    currentPeerId = signalingPeer;
    await receiveX3DHSession(signalingPeer, msg.data.x3dh);
  }

  if (!sdpInit || !sdpInit.type || !sdpInit.sdp) {
    return;
  }

  // 🔥 STATE GUARDRAIL: Avoid modifying remote answers if our signaling engine is stable
  if (sdpInit.type === "answer" && peerConnection && peerConnection.signalingState === "stable") {
    console.warn("⚠️ [WebRTC State Guard] Connection already stable. Ignoring duplicate remote answer.");
    return;
  }

  // IF we are the Receiver (Bob), initialize our PeerConnection context BEFORE applying descriptions
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
      console.log("🚀 [ICE Receiver] ICE gathering complete. Dispatching single answer back.");
      sendSignal(signalingPeer, {
        type: peerConnection.localDescription.type,
        sdp: peerConnection.localDescription.sdp
      });
    }
  };

  // Apply remote description safely
  try {
    console.log(`🔄 [WebRTC State] Applying remote description (${sdpInit.type})...`);
    await peerConnection.setRemoteDescription(new RTCSessionDescription({
      type: sdpInit.type,
      sdp: sdpInit.sdp
    }));
  } catch (err) {
    console.error("❌ Failed to set remote description:", err);
    return;
  }

  // Generate matching answer ONLY after setRemoteDescription successfully resolves
  if (sdpInit.type === "offer") {
    console.log("🔄 [WebRTC State] Compiling matching operational answer...");
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);

    if (peerConnection.iceGatheringState === "complete") {
      console.log("🚀 [ICE Instant Match] Sending completed answer profile.");
      sendSignal(signalingPeer, {
        type: peerConnection.localDescription.type,
        sdp: peerConnection.localDescription.sdp
      });
    }
  }
}

/**
 * Encrypts and transmits payloads over the DataChannel
 */
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
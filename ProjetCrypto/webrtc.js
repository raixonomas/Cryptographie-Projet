let pc;
let dc;
let currentPeerId;

const config = { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] };

/**
 * Initiator (Alice) requests the server bundle and starts WebRTC setup
 */
async function handleBundleResponse(msg) {
  currentPeerId = msg.targetId;

  const fp = await getFingerprint(msg.ik);
  if (!trustedFingerprints.has(fp)) {
    const trust = confirm(`Verify identity key fingerprint for ${currentPeerId}:\n\n${fp}`);
    if (!trust) return;
    trustedFingerprints.add(fp);
  }

  // 1. Run X3DH to build local session state
  const x3dhHeader = await initiateX3DHSession(currentPeerId, msg);

  // 2. Setup standard WebRTC Peer Connection
  pc = new RTCPeerConnection(config);
  
  // 3. Immediately open the data channel
  dc = pc.createDataChannel("chat");
  setupDC();

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
function setupDC() {
  if (!dc) return;

  dc.onopen = () => {
    log("🔐 End-to-End Encrypted Double Ratchet Connection Active!");
  };

  dc.onmessage = async (e) => {
    const payload = JSON.parse(e.data);
    const session = activeRatchetSessions.get(currentPeerId);

    if (!session) {
      log(`⚠️ Received a message but no active cryptographic session found for ${currentPeerId}`);
      return;
    }

    try {
      const plainText = await session.decrypt(payload);
      log(`<b>${currentPeerId}</b>: ${plainText}`);
    } catch(err) {
      log("❌ Failed to decrypt inbound packet. Bad Ratchet Synchronicity.");
      console.error(err);
    }
  };
  
  dc.onerror = (err) => console.error("Data Channel Error:", err);
}

/**
 * Standard inbound signal router with State Guardrails
 */
async function handleSignal(msg) {
  const signalingPeer = msg.from;
  console.log(`📡 [WebRTC Signaling] Signal received from: ${signalingPeer}. Current PC State: ${pc ? pc.signalingState : 'null'}`);

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
  if (sdpInit.type === "answer" && pc && pc.signalingState === "stable") {
    console.warn("⚠️ [WebRTC State Guard] Connection already stable. Ignoring duplicate remote answer.");
    return;
  }

  // IF we are the Receiver (Bob), initialize our PeerConnection context BEFORE applying descriptions
  if (!pc) {
    currentPeerId = signalingPeer;
    pc = new RTCPeerConnection(config);
    
    pc.ondatachannel = e => {
      dc = e.channel;
      setupDC();
    };

    pc.onicecandidate = e => {
      if (!e.candidate) {
        console.log("🚀 [ICE Receiver] ICE gathering complete. Dispatching single answer back.");
        sendSignal(signalingPeer, {
          type: pc.localDescription.type,
          sdp: pc.localDescription.sdp
        });
      }
    };
  }

  // Apply remote description safely
  try {
    console.log(`🔄 [WebRTC State] Applying remote description (${sdpInit.type})...`);
    await pc.setRemoteDescription(new RTCSessionDescription({
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
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    
    // If ICE gathering happened to complete instantaneously, send immediately.
    // Otherwise, we rely safely on pc.onicecandidate to prevent duplicate signaling packets.
    if (pc.iceGatheringState === "complete") {
      console.log("🚀 [ICE Instant Match] Sending completed answer profile.");
      sendSignal(signalingPeer, {
        type: pc.localDescription.type,
        sdp: pc.localDescription.sdp
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
  
  const session = activeRatchetSessions.get(currentPeerId);
  if (!session || !dc || dc.readyState !== "open") {
    return log("⚠️ Secure channel uninitialized or connection closing.");
  }

  const payload = await session.encrypt(text);
  
  dc.send(JSON.stringify(payload));
  log(`<b>You</b>: ${text}`);
  textInput.value = "";
}
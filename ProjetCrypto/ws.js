let ws;
let myId;

function connect() {
  myId = document.getElementById("name").value;
  ws = new WebSocket("ws://localhost:8080");

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "join", id: myId }));
    generateIdentity();
  };

  ws.onmessage = async (e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === "users") {
      updateUsers(msg.users);
    }

    if (msg.type === "bundle_response") {
      await handleBundleResponse(msg);
    }

    if (msg.type === "signal") {
      await handleSignal(msg);
    }

    if (msg.type === "connectionRequest") {
      const accepted = await window.showConfirmDialog(
        "Accept secure chat request?",
        `User ${msg.initiatorID} wants to establish an E2EE channel with you. Do you want to accept?`
      );

      ws.send(JSON.stringify({
        type: "connectionResponse",
        accepted,
        initiatorID: msg.initiatorID,
        targetID: myId
      }));

      if (accepted) {
        log(`✅ You accepted the connection request from ${msg.initiatorID}`);
      } else {
        log(`❌ You declined the connection request from ${msg.initiatorID}`);
      }
    }

    if (msg.type === "connectionAccepted") {
      log(`✅ ${msg.from} accepted the invitation. Starting the secure channel...`);
      requestUserBundle(msg.from);
    }

    if (msg.type === "connectionDeclined") {
      log(`❌ ${msg.from} declined the invitation.`);
    }
  };
}

function sendSignal(to, data) {
  ws.send(JSON.stringify({ type: "signal", to, data }));
}

function requestUserBundle(targetId) {
  ws.send(JSON.stringify({ type: "get_bundle", targetId }));
}

function requestConnection(targetId) {
  ws.send(JSON.stringify({ type: "connectionRequest", initiatorID: myId, targetID: targetId }));
}
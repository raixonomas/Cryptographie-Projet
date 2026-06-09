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
  };
}

function sendSignal(to, data) {
  ws.send(JSON.stringify({ type: "signal", to, data }));
}

function requestUserBundle(targetId) {
  ws.send(JSON.stringify({ type: "get_bundle", targetId }));
}
const WebSocket = require("ws");
const wss = new WebSocket.Server({ port: 8080 });

// id -> { ws, bundle: { ik, spk, opk: [] } }
const users = new Map(); 

function broadcastUsers() {
  const list = Array.from(users.entries()).map(([id, u]) => ({
    id,
    ready: !!u.bundle
  }));

  const msg = JSON.stringify({ type: "users", users: list });
  for (const u of users.values()) {
    u.ws.send(msg);
  }
}

wss.on("connection", (ws) => {
  let userId = null;

  ws.on("message", (raw) => {
    try {
      const data = JSON.parse(raw);

      if (data.type === "join") {
        userId = data.id;
        users.set(userId, { ws, bundle: null });
        broadcastUsers();
      }

      if (data.type === "publish_bundle") {
        if (users.has(userId)) {
          users.get(userId).bundle = data.bundle;
          broadcastUsers();
        }
      }

      if (data.type === "get_bundle") {
        const target = users.get(data.targetId);
        if (target && target.bundle) {
          ws.send(JSON.stringify({
            type: "bundle_response",
            targetId: data.targetId,
            ik: target.bundle.ik,
            spk: target.bundle.spk
          }));
        }
      }

      if (data.type === "signal") {
        const target = users.get(data.to);
        if (target) {
          target.ws.send(JSON.stringify({
            type: "signal",
            from: userId,
            data: data.data
          }));
        }
      }
    } catch (e) {
      console.error("Error processing message:", e);
    }
  });

  ws.on("close", () => {
    if (userId) users.delete(userId);
    broadcastUsers();
  });
});

console.log("🚀 Secure X3DH Server running on ws://localhost:8080");
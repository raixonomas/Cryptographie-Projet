const WebSocket = require("ws");

const wss = new WebSocket.Server({ port: 8080 });

const users = new Map(); 
// id -> { ws, pubkey }

function broadcastUsers() {
  const list = Array.from(users.entries()).map(([id, u]) => ({
    id,
    pubkey: u.pubkey || null,
    ready: u.pubkey?.ready === true   // 🔥 IMPORTANT
  }));

  const msg = JSON.stringify({ type: "users", users: list });

  for (const u of users.values()) {
    u.ws.send(msg);
  }
}

wss.on("connection", (ws) => {
  let userId = null;

  ws.on("message", (raw) => {
    const data = JSON.parse(raw);

    // JOIN
    if (data.type === "join") {
      userId = data.id;
      users.set(userId, { ws, pubkey: null });
      broadcastUsers();
    }

    // STORE PUBLIC KEY
    if (data.type === "pubkey") {
      if (!data.key?.ecdh || !data.key?.sign) return;

      if (!users.has(userId)) return;

      const user = users.get(userId);

      user.pubkey = {
        ecdh: data.key.ecdh,
        sign: data.key.sign,
        ready: true   // 🔥 ADD THIS
      };

      broadcastUsers();
    }

    // SIGNALING RELAY
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
  });

  ws.on("close", () => {
    if (userId) users.delete(userId);
    broadcastUsers();
  });
});

console.log("🚀 Server running on ws://localhost:8080");
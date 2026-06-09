const userStore = new Map();
const trustedFingerprints = new Set();

function updateUsers(users) {
  userStore.clear();

  for (const u of users) {
    if (u.ready && u.pubkey?.ecdh && u.pubkey?.sign) {
      userStore.set(u.id, u);
    }
  }

  renderUsers([...userStore.values()].filter(u => u.id !== myId));
}

function getUser(id) {
  return userStore.get(id);
}

async function renderUsers(users) {
  const div = document.getElementById("users");
  div.innerHTML = "";

  for (const u of users) {
    const btn = document.createElement("button");

    const ready = u?.pubkey?.ecdh && u?.pubkey?.sign;

    btn.disabled = !ready;
    btn.innerText = ready ? `Chat with ${u.id}` : `⏳ Waiting for ${u.id}`;

    if (u.pubkey?.sign) {
      const fp = await getFingerprint(u.pubkey.sign);
      btn.innerText = `Chat with ${u.id}\n${fp}`;
    }

    btn.onclick = () => {
      if (ready) startChat(u);
    };

    div.appendChild(btn);
  }
}
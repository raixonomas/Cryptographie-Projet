const userStore = new Map();
const trustedFingerprints = new Set();
window.trustedFingerprints = trustedFingerprints;

function updateUsers(users) {
  userStore.clear();
  for (const u of users) {
    if (u.ready) {
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
    btn.innerText = `Ask ${u.id} to start a secure chat`;

    btn.onclick = () => {
      requestConnection(u.id);
    };
    div.appendChild(btn);
  }
}
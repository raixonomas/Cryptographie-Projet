const discussions = new Map();
let activeDiscussionId = null;

function formatTime(date = new Date()) {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function ensureDiscussion(peerId) {
  if (!discussions.has(peerId)) {
    const li = createDiscussionItem(peerId, formatTime(), "Secure discussion ready");
    discussions.set(peerId, { peerId, messages: [], element: li });
  }

  return discussions.get(peerId);
}

function selectDiscussion(peerId) {
  ensureDiscussion(peerId);
  activeDiscussionId = peerId;
  currentPeerId = peerId;

  const activeItems = document.querySelectorAll(".discussion");
  activeItems.forEach((item) => item.classList.toggle("active", item.dataset.peerId === peerId));

  renderConversation(peerId);
}

function renderConversation(peerId) {
  const conversation = ensureDiscussion(peerId);
  const chatDiv = document.getElementById("chat");

  if (!chatDiv) return;

  chatDiv.innerHTML = "";
  conversation.messages.forEach((entry) => {
    chatDiv.innerHTML += `<div>${entry.sender === "You" ? "<b>You</b>" : `<b>${entry.sender}</b>`}: ${entry.text}</div>`;
  });
}

function appendMessage(peerId, sender, text) {
  const conversation = ensureDiscussion(peerId);
  conversation.messages.push({ sender, text, time: formatTime() });

  if (conversation.element) {
    conversation.element.querySelector(".disc-nom").textContent = peerId;
    conversation.element.querySelector(".disc-heure").textContent = conversation.messages[conversation.messages.length - 1].time;
    conversation.element.querySelector(".disc-preview").textContent = text;
  }

  if (activeDiscussionId === peerId) {
    renderConversation(peerId);
  }
}

function createDiscussionItem(name, date, message) {
  const liste = document.getElementById("disc-list");

  const li = document.createElement("li");
  li.classList.add("discussion");
  li.dataset.peerId = name;
  li.onclick = () => selectDiscussion(name);

  li.innerHTML = `
    <div class="disc-details">
      <div class="disc-ligne-haute">
        <span class="disc-nom"></span>
        <span class="disc-heure"></span>
      </div>
      <div class="disc-ligne-basse">
        <p class="disc-preview"></p>
      </div>
    </div>
  `;

  li.querySelector(".disc-nom").textContent = name;
  li.querySelector(".disc-heure").textContent = date;
  li.querySelector(".disc-preview").textContent = message;

  liste.appendChild(li);
  return li;
}

function log(msg) {
  const chatDiv = document.getElementById("chat");
  if (chatDiv) {
    chatDiv.innerHTML += `<div>${msg}</div>`;
  }
}

function showConfirmDialog(title, message) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("dialog-overlay");
    const titleEl = document.getElementById("dialog-title");
    const messageEl = document.getElementById("dialog-message");
    const acceptBtn = document.getElementById("dialog-accept");
    const declineBtn = document.getElementById("dialog-decline");

    if (!overlay || !titleEl || !messageEl || !acceptBtn || !declineBtn) {
      return resolve(false);
    }

    titleEl.textContent = title;
    messageEl.innerHTML = String(message).replace(/\n/g, "<br>");
    overlay.classList.add("show");
    overlay.setAttribute("aria-hidden", "false");

    const cleanup = () => {
      overlay.classList.remove("show");
      overlay.setAttribute("aria-hidden", "true");
      acceptBtn.onclick = null;
      declineBtn.onclick = null;
      document.removeEventListener("keydown", onKeyDown);
    };

    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        cleanup();
        resolve(false);
      }
      if (event.key === "Enter") {
        cleanup();
        resolve(true);
      }
    };

    acceptBtn.onclick = () => {
      cleanup();
      resolve(true);
    };

    declineBtn.onclick = () => {
      cleanup();
      resolve(false);
    };

    document.addEventListener("keydown", onKeyDown);
  });
}

function bindChatInput() {
  const messageInput = document.getElementById("msg");
  if (!messageInput) return;

  messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      sendMessage();
    }
  });
}

window.addEventListener("DOMContentLoaded", bindChatInput);
window.log = log;
window.showConfirmDialog = showConfirmDialog;
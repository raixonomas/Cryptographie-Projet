var button = document.getElementById("testbtn");

button.onclick = () => {
      createDiscussionItem("Rocketax", "12:58", "Hey you, you're finally awake.");
    };


function createDiscussionItem(name, date, message) {
  const liste = document.getElementById("disc-list");

  const li = document.createElement("li");
  li.classList.add("discussion");

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

window.log = log;
window.showConfirmDialog = showConfirmDialog;
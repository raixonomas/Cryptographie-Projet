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
window.log = log;
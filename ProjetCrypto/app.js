function log(msg) {
  const chatDiv = document.getElementById("chat");
  if (chatDiv) {
    chatDiv.innerHTML += `<div>${msg}</div>`;
  }
}
window.log = log;
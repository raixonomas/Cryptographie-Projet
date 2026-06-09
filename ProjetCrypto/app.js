function log(msg) {
  document.getElementById("chat").innerHTML += `<div>${msg}</div>`;
}

window.log = log;
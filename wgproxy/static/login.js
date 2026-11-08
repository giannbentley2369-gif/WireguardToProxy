import { api } from "./common.js";

const form = document.getElementById("login-form");
const errorBox = document.getElementById("login-error");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  const username = document.getElementById("login-username");
  try {
    await api("POST", "/api/auth/login", {
      username: username ? username.value : "",
      password: document.getElementById("login-password").value,
    });
    const next = form.dataset.next || "/";
    window.location.href = next.startsWith("/") && !next.startsWith("//") ? next : "/";
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
  }
});

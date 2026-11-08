import { api, escapeHtml, setupLogout, toast, watchStatus } from "./common.js";

const $ = (id) => document.getElementById(id);
const form = $("settings-form");
let loaded = null;

function fill(settings) {
  for (const input of form.elements) {
    if (!input.name || !(input.name in settings)) continue;
    if (input.type === "checkbox") input.checked = Boolean(settings[input.name]);
    else input.value = settings[input.name] ?? "";
  }
  $("ui-password-status").textContent = settings.ui_password_set
    ? "A password protects the WebUI. HTTP Basic auth with the same password works for scripts."
    : "No password set: anyone who can reach 127.0.0.1 on this machine can use the WebUI. Set one if the machine has other users.";
  $("ui-password-disable").hidden = !settings.ui_password_set;
}

function collectChanges() {
  const changes = {};
  for (const input of form.elements) {
    if (!input.name || !(input.name in loaded)) continue;
    let value;
    if (input.type === "checkbox") value = input.checked;
    else if (input.type === "number") value = input.value === "" ? null : Number(input.value);
    else value = input.value.trim();
    if (value !== loaded[input.name]) changes[input.name] = value;
  }
  return changes;
}

async function load() {
  loaded = await api("GET", "/api/settings");
  fill(loaded);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const changes = collectChanges();
  if (!Object.keys(changes).length) {
    toast("Nothing changed");
    return;
  }
  try {
    const result = await api("PUT", "/api/settings", changes);
    loaded = { ...loaded, ...result.settings };
    fill(loaded);
    toast(`Saved: ${result.changed.join(", ") || "no effective change"}`, "ok");
  } catch (error) {
    toast(error.message, "error", 9000);
  }
});

for (const button of document.querySelectorAll("[data-reveal]")) {
  button.addEventListener("click", () => {
    const input = form.elements[button.dataset.reveal];
    input.type = input.type === "password" ? "text" : "password";
    button.textContent = input.type === "password" ? "Show" : "Hide";
  });
}

$("upstream-direct").addEventListener("click", () => {
  form.elements.upstream_host.value = "";
  toast("Upstream host cleared: save to switch to direct mode");
});

$("upstream-test").addEventListener("click", async () => {
  const pending = collectChanges();
  if (Object.keys(pending).some((key) => key.startsWith("upstream_"))) {
    toast("Save the upstream settings first; the test uses the saved values", "warn");
  }
  const list = $("upstream-result");
  list.hidden = false;
  list.innerHTML = '<li class="muted">Testing…</li>';
  try {
    const result = await api("POST", "/api/upstream/test");
    list.innerHTML = result.steps
      .map(
        (step) =>
          `<li class="${step.ok ? "step-ok" : "step-bad"}"><strong>${step.ok ? "✓" : "✗"} ${escapeHtml(step.name)}</strong> ${escapeHtml(step.detail)}</li>`,
      )
      .join("");
  } catch (error) {
    list.innerHTML = `<li class="step-bad">${escapeHtml(error.message)}</li>`;
  }
});

$("regenerate-password").addEventListener("click", async () => {
  if (!window.confirm("Generate a new proxy password? Every app using the proxies must be updated, and all tunnels restart.")) return;
  try {
    const result = await api("POST", "/api/settings/proxy-password/regenerate");
    loaded.proxy_password = result.password;
    form.elements.proxy_password.value = result.password;
    toast("New proxy password generated", "ok");
  } catch (error) {
    toast(error.message, "error");
  }
});

$("ui-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("ui-password").value;
  if (password.length < 8) {
    toast("Use at least 8 characters", "warn");
    return;
  }
  if (password !== $("ui-password-repeat").value) {
    toast("The passwords do not match", "warn");
    return;
  }
  try {
    await api("POST", "/api/settings/ui-password", { password });
    $("ui-password").value = "";
    $("ui-password-repeat").value = "";
    toast("WebUI password set", "ok");
    await load();
  } catch (error) {
    toast(error.message, "error");
  }
});

$("ui-password-disable").addEventListener("click", async () => {
  if (!window.confirm("Remove the WebUI password?")) return;
  try {
    await api("POST", "/api/settings/ui-password", { password: "" });
    toast("WebUI password removed", "ok");
    await load();
  } catch (error) {
    toast(error.message, "error");
  }
});

// -- per-proxy port overrides --------------------------------------------------------------

let proxies = [];

async function loadPorts() {
  proxies = await api("GET", "/api/proxies");
  $("port-rows").innerHTML =
    proxies
      .map(
        (proxy) => `<tr data-id="${proxy.id}">
          <td>${escapeHtml(proxy.name)}</td>
          <td class="num"><code>${proxy.port}</code></td>
          <td><input type="number" class="port-input" min="1024" max="65535" value="${proxy.port}" aria-label="New port for ${escapeHtml(proxy.name)}"></td>
          <td class="muted">${escapeHtml(proxy.notice || "")}</td>
        </tr>`,
      )
      .join("") || '<tr><td colspan="4" class="muted">No proxies yet.</td></tr>';
}

$("ports-save").addEventListener("click", async () => {
  const changes = [];
  for (const row of $("port-rows").querySelectorAll("tr[data-id]")) {
    const proxy = proxies.find((item) => item.id === Number(row.dataset.id));
    const port = Number(row.querySelector(".port-input").value);
    if (proxy && port && port !== proxy.port) changes.push({ proxy, port });
  }
  if (!changes.length) {
    toast("No port changes");
    return;
  }
  const errors = [];
  for (const { proxy, port } of changes) {
    try {
      await api("PATCH", `/api/proxies/${proxy.id}`, { port });
    } catch (error) {
      errors.push(`${proxy.name}: ${error.message}`);
    }
  }
  if (errors.length) toast(errors.join(" · "), "error", 10000);
  else toast(`${changes.length} port(s) updated`, "ok");
  await loadPorts();
});

load().catch((error) => toast(error.message, "error"));
loadPorts().catch((error) => toast(error.message, "error"));
watchStatus();
setupLogout();

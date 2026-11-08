import { api, copyText, escapeHtml, fmtAgo, fmtTime, setupLogout, statusBadge, toast, watchStatus } from "./common.js";

const $ = (id) => document.getElementById(id);
const tbody = $("proxy-rows");
const filterText = $("filter-text");
const filterStatus = $("filter-status");
const filterCountry = $("filter-country");

const state = {
  proxies: [],
  status: null,
  selected: new Set(),
  sort: { key: "name", dir: 1 },
  loaded: false,
  revealPassword: false,
  testRunning: false,
  editId: null,
};

const NOT_RUNNING = new Set(["error", "failed", "backoff", "stopped", "pending", "starting"]);
const STATUS_ORDER = { ok: 0, unknown: 1, pending: 2, starting: 3, dead: 4, backoff: 5, failed: 6, error: 7, stopped: 8, disabled: 9 };

function credentials() {
  return state.status ? state.status.credentials : { username: "USER", password: "PASS" };
}

function proxyUrl(proxy, scheme = "socks5") {
  const { username, password } = credentials();
  return `${scheme}://${encodeURIComponent(username)}:${encodeURIComponent(password)}@127.0.0.1:${proxy.port}`;
}

function matchesFilters(proxy) {
  const text = filterText.value.trim().toLowerCase();
  if (text) {
    const haystack = [proxy.name, proxy.endpoint, proxy.exit_ip, proxy.country, proxy.country_code, proxy.city, proxy.port]
      .join(" ")
      .toLowerCase();
    if (!haystack.includes(text)) return false;
  }
  const wanted = filterStatus.value;
  if (wanted === "problem" ? !NOT_RUNNING.has(proxy.status) : wanted && proxy.status !== wanted) return false;
  if (filterCountry.value && (proxy.country_code || "") !== filterCountry.value) return false;
  return true;
}

function sortValue(proxy, key) {
  switch (key) {
    case "port":
      return proxy.port;
    case "latency_ms":
      return proxy.latency_ms ?? Number.MAX_SAFE_INTEGER;
    case "status":
      return STATUS_ORDER[proxy.status] ?? 99;
    case "country":
      return (proxy.country || "").toLowerCase() || "\uffff";
    case "exit_ip":
      return proxy.exit_ip || "\uffff";
    case "checked_at":
      return proxy.checked_at || "";
    default:
      return proxy.name.toLowerCase();
  }
}

function visibleProxies() {
  const { key, dir } = state.sort;
  return state.proxies.filter(matchesFilters).sort((a, b) => {
    const va = sortValue(a, key);
    const vb = sortValue(b, key);
    if (va < vb) return -dir;
    if (va > vb) return dir;
    return a.name.localeCompare(b.name);
  });
}

function countryCell(proxy) {
  if (!proxy.country_code) return '<span class="muted">—</span>';
  const city = proxy.city ? `<div class="sub">${escapeHtml(proxy.city)}</div>` : "";
  return `<strong>${escapeHtml(proxy.country_code)}</strong> ${escapeHtml(proxy.country || "")}${city}`;
}

function rowHtml(proxy) {
  const checked = state.selected.has(proxy.id) ? "checked" : "";
  const notice = proxy.notice ? ` <span class="notice" title="${escapeHtml(proxy.notice)}">moved</span>` : "";
  const latency = proxy.latency_ms != null ? `${proxy.latency_ms} ms` : '<span class="muted">—</span>';
  const checkedAt = proxy.checked_at
    ? `<span title="${escapeHtml(fmtTime(proxy.checked_at))}">${fmtAgo(proxy.checked_at)}</span>`
    : '<span class="muted">never</span>';
  return `<tr data-id="${proxy.id}" class="${proxy.enabled ? "" : "is-disabled"}">
    <td class="col-check"><input type="checkbox" class="row-check" ${checked} aria-label="Select ${escapeHtml(proxy.name)}"></td>
    <td><div class="name">${escapeHtml(proxy.name)}</div><div class="sub">${escapeHtml(proxy.endpoint)}</div></td>
    <td class="num"><code>${proxy.port}</code>${notice}</td>
    <td><label class="switch" title="${proxy.enabled ? "Disable" : "Enable"}"><input type="checkbox" class="row-toggle" ${proxy.enabled ? "checked" : ""} aria-label="Enabled"><span></span></label></td>
    <td>${statusBadge(proxy)}</td>
    <td>${proxy.exit_ip ? `<code>${escapeHtml(proxy.exit_ip)}</code>` : '<span class="muted">—</span>'}</td>
    <td>${countryCell(proxy)}</td>
    <td class="num">${latency}</td>
    <td>${checkedAt}</td>
    <td class="col-actions">
      <button type="button" class="btn tiny" data-action="test" ${proxy.enabled ? "" : "disabled"}>Test</button>
      <button type="button" class="btn tiny" data-action="copy" title="Copy socks5:// URL">Copy URL</button>
      <button type="button" class="btn tiny" data-action="edit">Edit</button>
      <a class="btn tiny" href="/api/proxies/${proxy.id}/conf" download title="Download the original .conf">.conf</a>
      <button type="button" class="btn tiny danger" data-action="delete">Delete</button>
    </td>
  </tr>`;
}

function render() {
  const rows = visibleProxies();
  tbody.innerHTML = rows.map(rowHtml).join("");
  $("empty-state").hidden = !state.loaded || state.proxies.length > 0;
  const selectAll = $("select-all");
  const visibleSelected = rows.filter((proxy) => state.selected.has(proxy.id)).length;
  selectAll.checked = rows.length > 0 && visibleSelected === rows.length;
  selectAll.indeterminate = visibleSelected > 0 && visibleSelected < rows.length;
  for (const th of document.querySelectorAll("th[data-sort]")) {
    th.classList.toggle("sorted", th.dataset.sort === state.sort.key);
    th.classList.toggle("desc", th.dataset.sort === state.sort.key && state.sort.dir < 0);
  }
  $("bulkbar").hidden = state.selected.size === 0;
  $("bulk-count").textContent = `${state.selected.size} selected`;
  renderCountryOptions();
  renderSummary(rows.length);
}

function renderCountryOptions() {
  const countries = new Map();
  for (const proxy of state.proxies) {
    if (proxy.country_code) countries.set(proxy.country_code, proxy.country || proxy.country_code);
  }
  const sorted = [...countries.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  for (const select of [filterCountry, $("export-country")]) {
    const current = select.value;
    const first = select.options[0].outerHTML;
    select.innerHTML =
      first +
      sorted
        .map(([code, name]) => `<option value="${escapeHtml(code)}">${escapeHtml(name)} (${escapeHtml(code)})</option>`)
        .join("");
    select.value = countries.has(current) ? current : "";
  }
}

function renderSummary(visible) {
  const counts = state.status ? state.status.counts : null;
  if (!counts) return;
  const shown = visible === state.proxies.length ? "" : ` · ${visible} shown`;
  $("summary").textContent = `${counts.total} proxies · ${counts.enabled} enabled · ${counts.ok} OK · ${counts.dead} dead · ${counts.errors} with errors${shown}`;
}

function renderCredentials() {
  const { username, password } = credentials();
  $("cred-user").textContent = username;
  $("cred-pass").textContent = state.revealPassword ? password : "•".repeat(Math.min(password.length, 16));
  $("cred-reveal").textContent = state.revealPassword ? "Hide" : "Show";
  const port = state.proxies.length ? state.proxies[0].port : "PORT";
  const shownPassword = state.revealPassword ? encodeURIComponent(password) : "PASS";
  $("cred-example").textContent = `socks5://${encodeURIComponent(username)}:${shownPassword}@127.0.0.1:${port}`;
}

function renderProgress() {
  const job = state.status ? state.status.test : null;
  const box = $("test-progress");
  const running = Boolean(job && job.running);
  box.hidden = !running;
  $("btn-test-all").disabled = running;
  if (running) {
    const text =
      job.phase === "geo"
        ? `Looking up countries for ${job.ok} working proxies…`
        : `Testing ${job.done}/${job.total} · ${job.ok} OK · ${job.failed} failed`;
    $("test-progress-text").textContent = text;
    $("test-progress-bar").max = Math.max(job.total, 1);
    $("test-progress-bar").value = job.done;
  }
  if (state.testRunning && !running && job) {
    toast(job.error ? `Test run ended: ${job.error}` : `Test finished: ${job.ok} OK, ${job.failed} failed`, job.failed || job.error ? "warn" : "ok");
  }
  state.testRunning = running;
}

async function loadProxies() {
  state.proxies = await api("GET", "/api/proxies");
  const ids = new Set(state.proxies.map((proxy) => proxy.id));
  for (const id of state.selected) if (!ids.has(id)) state.selected.delete(id);
  state.loaded = true;
  render();
}

const poller = watchStatus(
  async (status) => {
    state.status = status;
    renderProgress();
    await loadProxies();
    renderCredentials();
  },
  { fastWhile: (status) => Boolean(status.test && status.test.running) },
);

function findProxy(id) {
  return state.proxies.find((proxy) => proxy.id === id);
}

async function run(action, successMessage) {
  try {
    const result = await action();
    if (successMessage) toast(typeof successMessage === "function" ? successMessage(result) : successMessage, "ok");
    return result;
  } catch (error) {
    toast(error.message, "error", 7000);
    return undefined;
  } finally {
    poller.refresh();
  }
}

// -- table interactions --------------------------------------------------------------------

tbody.addEventListener("change", async (event) => {
  const row = event.target.closest("tr[data-id]");
  if (!row) return;
  const id = Number(row.dataset.id);
  if (event.target.classList.contains("row-check")) {
    if (event.target.checked) state.selected.add(id);
    else state.selected.delete(id);
    render();
  } else if (event.target.classList.contains("row-toggle")) {
    const enabled = event.target.checked;
    await run(() => api("PATCH", `/api/proxies/${id}`, { enabled }), `${findProxy(id)?.name ?? "Proxy"} ${enabled ? "enabled" : "disabled"}`);
  }
});

tbody.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const id = Number(button.closest("tr[data-id]").dataset.id);
  const proxy = findProxy(id);
  if (!proxy) return;
  switch (button.dataset.action) {
    case "test":
      button.disabled = true;
      button.textContent = "…";
      await run(
        () => api("POST", `/api/proxies/${id}/test`),
        (result) => (result.check_status === "ok" ? `${result.name}: ${result.exit_ip} (${result.latency_ms} ms)` : `${result.name}: ${result.check_error || "failed"}`),
      );
      break;
    case "copy":
      await copyText(proxyUrl(proxy));
      break;
    case "edit":
      openEdit(id);
      break;
    case "delete":
      if (window.confirm(`Delete ${proxy.name}? Its port ${proxy.port} is released.`)) {
        await run(() => api("DELETE", `/api/proxies/${id}`), `${proxy.name} deleted`);
      }
      break;
    default:
      break;
  }
});

$("select-all").addEventListener("change", (event) => {
  for (const proxy of visibleProxies()) {
    if (event.target.checked) state.selected.add(proxy.id);
    else state.selected.delete(proxy.id);
  }
  render();
});

for (const th of document.querySelectorAll("th[data-sort]")) {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 };
    render();
  });
}

for (const input of [filterText, filterStatus, filterCountry]) input.addEventListener("input", render);

$("cred-reveal").addEventListener("click", () => {
  state.revealPassword = !state.revealPassword;
  renderCredentials();
});
for (const button of document.querySelectorAll("[data-copy]")) {
  button.addEventListener("click", () => {
    const { username, password } = credentials();
    copyText(button.dataset.copy === "user" ? username : password);
  });
}

// -- bulk actions and tests ------------------------------------------------------------------

for (const button of document.querySelectorAll("[data-bulk]")) {
  button.addEventListener("click", async () => {
    const ids = [...state.selected];
    const action = button.dataset.bulk;
    if (!ids.length) return;
    if (action === "delete" && !window.confirm(`Delete ${ids.length} proxies? Their ports are released.`)) return;
    const result = await run(() => api("POST", "/api/proxies/bulk", { action, ids }), (data) => `${action}: ${data.affected} proxies`);
    if (result && action === "delete") state.selected.clear();
  });
}
$("bulk-clear").addEventListener("click", () => {
  state.selected.clear();
  render();
});

$("btn-test-all").addEventListener("click", async () => {
  await run(() => api("POST", "/api/tests", {}), (job) => `Testing ${job.total} enabled proxies…`);
});

// -- export dialog ---------------------------------------------------------------------------

const exportDialog = $("export-dialog");
const exportForm = $("export-form");

function exportParams(download) {
  const data = new FormData(exportForm);
  const params = new URLSearchParams({
    scheme: data.get("scheme") || "socks5",
    enabled_only: exportForm.elements.enabled_only.checked ? "true" : "false",
    status: exportForm.elements.status_ok.checked ? "ok" : "any",
    download: download ? "true" : "false",
  });
  if (data.get("country")) params.set("country", data.get("country"));
  if (exportForm.elements.selected_only.checked && state.selected.size) params.set("ids", [...state.selected].join(","));
  return params;
}

async function refreshExportPreview() {
  try {
    const text = await api("GET", `/api/export?${exportParams(false)}`, undefined, { text: true });
    const lines = text.split("\n").filter(Boolean);
    $("export-count").textContent = `${lines.length} proxies match`;
    $("export-preview").textContent = lines.slice(0, 5).join("\n") + (lines.length > 5 ? "\n…" : "");
    return text;
  } catch (error) {
    $("export-count").textContent = error.message;
    return "";
  }
}

$("btn-export").addEventListener("click", () => {
  $("export-selected-count").textContent = String(state.selected.size);
  exportForm.elements.selected_only.checked = state.selected.size > 0;
  exportForm.elements.selected_only.disabled = state.selected.size === 0;
  exportDialog.showModal();
  refreshExportPreview();
});
exportForm.addEventListener("change", refreshExportPreview);
$("export-download").addEventListener("click", () => {
  window.location.href = `/api/export?${exportParams(true)}`;
});
$("export-copy").addEventListener("click", async () => {
  const text = await refreshExportPreview();
  if (text) await copyText(text);
});

// -- edit dialog -----------------------------------------------------------------------------

const editDialog = $("edit-dialog");
const editForm = $("edit-form");

function detailRows(proxy) {
  const rows = [
    ["Endpoint", proxy.endpoint],
    ["Engine shard", proxy.shard ?? "—"],
  ];
  const config = proxy.config || {};
  if (config.addresses) rows.push(["Addresses", config.addresses.join(", ")]);
  if (config.dns) rows.push(["DNS in .conf", config.dns.length ? config.dns.join(", ") : "none (fallback used)"]);
  if (config.mtu) rows.push(["MTU in .conf", config.mtu]);
  if (config.ip_versions) rows.push(["IP versions", config.ip_versions.map((v) => `IPv${v}`).join(" + ")]);
  for (const peer of config.peers || []) {
    rows.push(["Peer", `${peer.endpoint} · AllowedIPs ${peer.allowed_ips.join(", ")}${peer.has_preshared_key ? " · PSK" : ""}`]);
  }
  for (const warning of config.warnings || []) rows.push(["Parser note", warning]);
  if (proxy.check_error) rows.push(["Last test error", proxy.check_error]);
  return rows.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`).join("");
}

async function openEdit(id) {
  try {
    const proxy = await api("GET", `/api/proxies/${id}`);
    state.editId = id;
    editForm.elements.name.value = proxy.name;
    editForm.elements.port.value = proxy.port;
    $("edit-error").hidden = !proxy.engine_error;
    $("edit-error").textContent = proxy.engine_error || "";
    $("edit-notice").hidden = !proxy.notice;
    $("edit-notice").textContent = proxy.notice || "";
    $("edit-retry").hidden = !proxy.engine_error;
    $("edit-details").innerHTML = detailRows(proxy);
    editDialog.showModal();
  } catch (error) {
    toast(error.message, "error");
  }
}

$("edit-save").addEventListener("click", async () => {
  const proxy = findProxy(state.editId);
  if (!proxy || !editForm.reportValidity()) return;
  const changes = {};
  const name = editForm.elements.name.value.trim();
  const port = Number(editForm.elements.port.value);
  if (name !== proxy.name) changes.name = name;
  if (port !== proxy.port) changes.port = port;
  if (!Object.keys(changes).length) {
    editDialog.close();
    return;
  }
  const result = await run(() => api("PATCH", `/api/proxies/${proxy.id}`, changes), "Saved; the engine is reloading this proxy");
  if (result) editDialog.close();
});

$("edit-retry").addEventListener("click", async () => {
  const result = await run(() => api("POST", "/api/proxies/bulk", { action: "retry", ids: [state.editId] }), "Retrying");
  if (result) editDialog.close();
});

setupLogout();

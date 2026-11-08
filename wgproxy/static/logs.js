import { api, escapeHtml, setupLogout, toast, watchStatus } from "./common.js";

const $ = (id) => document.getElementById(id);
const view = $("log-view");
const MAX_BUFFER = 5000;
const MAX_LINES = 3000;
const LEVEL_RANK = { TRACE: 0, DEBUG: 1, INFO: 2, WARN: 3, ERROR: 4, FATAL: 5, PANIC: 5 };
const buffer = [];
const sources = new Set();
let paused = false;

function matches(entry) {
  const source = $("log-source").value;
  if (source && entry.source !== source) return false;
  const level = $("log-level").value;
  if (level && (LEVEL_RANK[entry.level] ?? 2) < LEVEL_RANK[level]) return false;
  const text = $("log-filter").value.trim().toLowerCase();
  return !text || entry.text.toLowerCase().includes(text);
}

function lineElement(entry) {
  const line = document.createElement("div");
  line.className = `log-line level-${entry.level.toLowerCase()}`;
  const time = new Date(entry.ts * 1000).toLocaleTimeString();
  line.innerHTML = `<span class="log-time">${time}</span><span class="log-source">${escapeHtml(entry.source)}</span><span class="log-text">${escapeHtml(entry.text)}</span>`;
  return line;
}

function nearBottom() {
  return view.scrollTop + view.clientHeight >= view.scrollHeight - 40;
}

function scrollIfWanted(wasNearBottom) {
  if ($("log-autoscroll").checked && wasNearBottom) view.scrollTop = view.scrollHeight;
}

function rerender() {
  const wasNear = true;
  view.replaceChildren(...buffer.filter(matches).slice(-MAX_LINES).map(lineElement));
  scrollIfWanted(wasNear);
}

function addSource(source) {
  if (sources.has(source)) return;
  sources.add(source);
  const select = $("log-source");
  const current = select.value;
  const options = [...sources].sort().map((item) => `<option value="${escapeHtml(item)}">${escapeHtml(item)}</option>`);
  select.innerHTML = `<option value="">All sources</option>${options.join("")}`;
  select.value = current;
}

function append(entry) {
  buffer.push(entry);
  if (buffer.length > MAX_BUFFER) buffer.splice(0, buffer.length - MAX_BUFFER);
  addSource(entry.source);
  if (paused || !matches(entry)) return;
  const wasNear = nearBottom();
  view.appendChild(lineElement(entry));
  while (view.childElementCount > MAX_LINES) view.firstElementChild.remove();
  scrollIfWanted(wasNear);
}

const connection = $("log-connection");
const events = new EventSource("/api/logs/stream");
events.onopen = () => {
  connection.textContent = "live";
  connection.className = "pill pill-ok";
};
events.onerror = () => {
  connection.textContent = "reconnecting…";
  connection.className = "pill pill-warn";
};
events.onmessage = (event) => append(JSON.parse(event.data));

for (const id of ["log-source", "log-level", "log-filter"]) $(id).addEventListener("input", rerender);
$("log-pause").addEventListener("click", () => {
  paused = !paused;
  $("log-pause").textContent = paused ? "Resume" : "Pause";
  if (!paused) rerender();
});
$("log-clear").addEventListener("click", () => {
  buffer.length = 0;
  view.replaceChildren();
});
$("log-download").addEventListener("click", () => {
  const text = buffer
    .map((entry) => `${new Date(entry.ts * 1000).toISOString()} [${entry.source}] ${entry.text}`)
    .join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([`${text}\n`], { type: "text/plain" }));
  link.download = "wgproxy-logs.txt";
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});

function renderEngine(engine) {
  $("engine-message").textContent = [engine.message, engine.version ? `sing-box ${engine.version}` : ""]
    .filter(Boolean)
    .join(" · ");
  $("shard-rows").innerHTML =
    engine.shards
      .map((shard) => {
        const ports = shard.ports.length ? `${shard.ports[0]}${shard.ports.length > 1 ? `–${shard.ports[shard.ports.length - 1]}` : ""}` : "—";
        const retry = shard.retry_in != null ? ` (retry in ${Math.ceil(shard.retry_in)}s)` : "";
        return `<tr>
          <td>${shard.index}</td>
          <td><span class="badge badge-${shard.state === "running" ? "ok" : shard.state === "starting" ? "starting" : shard.state === "stopped" ? "disabled" : "dead"}">${escapeHtml(shard.state)}</span>${escapeHtml(retry)}</td>
          <td class="num">${shard.pid ?? "—"}</td>
          <td class="num" title="${escapeHtml(shard.names.join(", "))}">${shard.tunnels}</td>
          <td>${escapeHtml(ports)}</td>
          <td class="error-text">${escapeHtml(shard.last_error || "")}</td>
        </tr>`;
      })
      .join("") || '<tr><td colspan="6" class="muted">No engine processes (no enabled proxies).</td></tr>';
}

const poller = watchStatus((status) => renderEngine(status.engine));

$("restart-engine").addEventListener("click", async () => {
  if (!window.confirm("Restart every engine process? Tunnels reconnect batch by batch.")) return;
  try {
    await api("POST", "/api/engine/restart");
    toast("Engine restart scheduled", "ok");
  } catch (error) {
    toast(error.message, "error");
  }
  poller.refresh();
});

setupLogout();

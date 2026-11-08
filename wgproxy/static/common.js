// Shared helpers for every page. Plain ES modules, no framework and no build step.

const CSRF_HEADERS = { "X-Requested-With": "wgproxy" };

export async function api(method, url, body, { text = false } = {}) {
  const options = { method, headers: { ...CSRF_HEADERS }, credentials: "same-origin" };
  if (body instanceof FormData) {
    options.body = body;
  } else if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(url, options);
  if (response.status === 401 && !url.startsWith("/api/auth/")) {
    window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
    throw new Error("Authentication required");
  }
  const isJson = (response.headers.get("content-type") || "").includes("application/json");
  const data = text || !isJson ? await response.text() : await response.json();
  if (!response.ok) throw new Error(describeError(data, response));
  return data;
}

function describeError(data, response) {
  if (data && typeof data === "object" && "detail" in data) {
    const { detail } = data;
    if (Array.isArray(detail)) {
      return detail
        .map((item) => {
          const where = (item.loc || []).filter((part) => part !== "body").join(".");
          return where ? `${where}: ${item.msg}` : item.msg;
        })
        .join("; ");
    }
    return String(detail);
  }
  if (typeof data === "string" && data.trim()) return data.trim().slice(0, 300);
  return `${response.status} ${response.statusText}`;
}

export function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch],
  );
}

export function toast(message, kind = "info", timeout = 4500) {
  const box = document.getElementById("toasts");
  if (!box) return;
  const item = document.createElement("div");
  item.className = `toast toast-${kind}`;
  item.textContent = message;
  item.addEventListener("click", () => item.remove());
  box.appendChild(item);
  setTimeout(() => item.remove(), timeout);
}

export function fmtAgo(iso) {
  const date = iso ? new Date(iso) : null;
  if (!date || Number.isNaN(date.getTime())) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 45) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} d ago`;
}

export function fmtTime(iso) {
  const date = iso ? new Date(iso) : null;
  return date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : "";
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.className = "offscreen";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  toast("Copied to clipboard", "ok", 2000);
}

const STATUS_INFO = {
  ok: ["OK", "Last test succeeded: handshake done and the internet is reachable"],
  dead: ["Dead", "Last test failed"],
  unknown: ["Unknown", "Running, not tested yet"],
  disabled: ["Disabled", "Disabled: no listener, no tunnel"],
  error: ["Error", "Excluded by the engine"],
  pending: ["Pending", "Waiting for its engine process (staggered start)"],
  starting: ["Starting", "Engine process starting"],
  backoff: ["Restarting", "Engine process failed; retrying with back-off"],
  failed: ["Failed", "Engine process failed"],
  stopped: ["Stopped", "Engine process stopped"],
};

export function statusBadge(proxy) {
  const [label, hint] = STATUS_INFO[proxy.status] || [proxy.status, ""];
  let title = hint;
  if (proxy.status === "dead" && proxy.check_error) title = `Last test failed: ${proxy.check_error}`;
  if (proxy.status === "error" && proxy.engine_error) title = proxy.engine_error;
  return `<span class="badge badge-${escapeHtml(proxy.status)}" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`;
}

const ENGINE_LABELS = {
  running: "running",
  starting: "starting",
  degraded: "degraded",
  waiting_upstream: "waiting for upstream",
  idle: "idle",
  error: "error",
  stopping: "stopping",
  stopped: "stopped",
};
const ENGINE_KIND = {
  running: "ok",
  starting: "info",
  degraded: "warn",
  waiting_upstream: "warn",
  error: "bad",
};

function renderHeader(status) {
  const engine = document.getElementById("pill-engine");
  if (engine) {
    const e = status.engine;
    const count = e.total_shards ? ` ${e.running_shards}/${e.total_shards}` : "";
    engine.textContent = `Engine: ${ENGINE_LABELS[e.state] || e.state}${count}`;
    engine.className = `pill pill-${ENGINE_KIND[e.state] || "idle"}`;
    engine.title = [e.message, e.version ? `sing-box ${e.version}` : ""].filter(Boolean).join(" · ");
  }
  const upstream = document.getElementById("pill-upstream");
  if (upstream) {
    const u = status.upstream;
    if (!u.configured) {
      upstream.textContent = "Upstream: direct mode";
      upstream.className = "pill pill-idle";
      upstream.title = "No upstream proxy: tunnels use direct userspace UDP";
    } else {
      const ok = u.state === "reachable";
      upstream.textContent = `Upstream ${u.address || ""} ${ok ? "✓" : u.state === "unreachable" ? "✗" : "…"}`;
      upstream.className = `pill pill-${ok ? "ok" : u.state === "unreachable" ? "bad" : "idle"}`;
      upstream.title = u.error || "Upstream SOCKS5 proxy accepts connections";
    }
  }
  const banner = document.getElementById("banner");
  if (banner) {
    const messages = [];
    const { engine: e, upstream: u } = status;
    if (u.configured && u.state === "unreachable") {
      messages.push(`Upstream proxy ${u.address} is unreachable (${u.error || "connection failed"}); tunnels cannot connect until it is back.`);
    }
    if (["waiting_upstream", "error", "degraded"].includes(e.state) && e.message) messages.push(e.message);
    if (!e.version && !["starting", "stopping", "stopped"].includes(e.state)) {
      messages.push("The sing-box binary could not be executed; see Engine & logs.");
    }
    banner.textContent = messages.join(" ");
    banner.hidden = messages.length === 0;
  }
  const version = document.getElementById("engine-version");
  if (version && status.engine.version) version.textContent = `sing-box ${status.engine.version}`;
}

// Polls /api/status (header pills, banner) and hands the result to the page.
export function watchStatus(onUpdate, { fastWhile } = {}) {
  let timer = null;
  let generation = 0;
  async function tick(current) {
    let status = null;
    try {
      status = await api("GET", "/api/status");
      renderHeader(status);
      if (onUpdate) await onUpdate(status);
    } catch (error) {
      console.warn("status refresh failed", error);
    }
    if (current !== generation) return;
    const fast = status && fastWhile && fastWhile(status);
    timer = setTimeout(() => tick(current), fast ? 1500 : 5000);
  }
  function refresh() {
    generation += 1;
    clearTimeout(timer);
    tick(generation);
  }
  refresh();
  return { refresh };
}

export function setupLogout() {
  const button = document.getElementById("logout");
  if (!button) return;
  button.addEventListener("click", async () => {
    await api("POST", "/api/auth/logout");
    window.location.href = "/login";
  });
}

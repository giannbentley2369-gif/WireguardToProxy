import { api, escapeHtml, setupLogout, toast, watchStatus } from "./common.js";

const $ = (id) => document.getElementById(id);
const fileInput = $("file-input");
const dropZone = $("drop-zone");
let pendingFiles = [];

function setFiles(files) {
  const all = Array.from(files);
  pendingFiles = all.filter((file) => /\.(conf|zip)$/i.test(file.name));
  const skipped = all.length - pendingFiles.length;
  if (skipped) toast(`${skipped} file(s) ignored: only .conf and .zip are accepted`, "warn");
  $("file-list").innerHTML = pendingFiles
    .map((file) => `<li>${escapeHtml(file.name)} <span class="muted">${(file.size / 1024).toFixed(1)} KiB</span></li>`)
    .join("");
  $("upload-submit").disabled = pendingFiles.length === 0;
}

dropZone.addEventListener("click", () => fileInput.click());
dropZone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.click();
  }
});
dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropZone.classList.add("over");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("over"));
dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("over");
  setFiles(event.dataTransfer.files);
});
fileInput.addEventListener("change", () => setFiles(fileInput.files));

function showResults(results) {
  const added = results.filter((item) => item.status === "added").length;
  const failed = results.length - added;
  $("results-card").hidden = false;
  $("results-summary").textContent = `${added} added, ${failed} rejected.`;
  $("results-rows").innerHTML = results
    .map((item) => {
      const ok = item.status === "added";
      const notes = ok ? item.warnings.join(" · ") : item.error;
      return `<tr>
        <td><span class="badge badge-${ok ? "ok" : "dead"}">${ok ? "Added" : "Error"}</span></td>
        <td>${escapeHtml(item.source)}</td>
        <td>${escapeHtml(item.name || "—")}</td>
        <td class="num">${item.port ?? "—"}</td>
        <td class="${ok ? "muted" : "error-text"}">${escapeHtml(notes || "")}</td>
      </tr>`;
    })
    .join("");
  toast(`${added} config(s) added${failed ? `, ${failed} rejected` : ""}`, failed ? "warn" : "ok");
  $("results-card").scrollIntoView({ behavior: "smooth", block: "start" });
}

$("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!pendingFiles.length) return;
  const data = new FormData();
  for (const file of pendingFiles) data.append("files", file, file.name);
  data.append("enable", $("upload-enable").checked ? "true" : "false");
  const button = $("upload-submit");
  button.disabled = true;
  button.textContent = "Importing…";
  try {
    const response = await api("POST", "/api/proxies/import", data);
    showResults(response.results);
    setFiles([]);
    fileInput.value = "";
  } catch (error) {
    toast(error.message, "error", 8000);
  } finally {
    button.textContent = "Import files";
    button.disabled = pendingFiles.length === 0;
  }
});

$("paste-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const response = await api("POST", "/api/proxies/paste", {
      name: $("paste-name").value,
      text: $("paste-text").value,
      enable: $("paste-enable").checked,
    });
    showResults(response.results);
    if (response.results.every((item) => item.status === "added")) {
      $("paste-text").value = "";
      $("paste-name").value = "";
    }
  } catch (error) {
    toast(error.message, "error", 8000);
  }
});

watchStatus();
setupLogout();

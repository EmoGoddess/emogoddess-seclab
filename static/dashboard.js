// ---- internal dev notes (TODO: strip before launch) ----
// data layer: sqlite users(id,username,password,role,display_name,secret)
// report svc key (b64): cmVwb3J0X2tleV9lZ190Y2c=  ->  /api/v1/report?key=
// internal profile svc (no auth yet): /api/v2/internal?user=<id>
// ---------------------------------------------------------

async function loadCatalogue() {
  try { const r = await fetch("/api/cards"); if (r.ok) { const c = await r.json(); console.log(`catalogue: ${c.length}`); } }
  catch (e) { console.warn(e); }
}

function chatAppend(who, text) {
  const log = document.getElementById("eg-chat-log");
  const row = document.createElement("div");
  row.className = "eg-msg " + who;
  row.textContent = text;
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
}

function initChat() {
  const toggle = document.getElementById("eg-chat-toggle");
  const panel = document.getElementById("eg-chat-panel");
  const form = document.getElementById("eg-chat-form");
  const input = document.getElementById("eg-chat-input");
  if (!toggle) return;
  let greeted = false;
  toggle.addEventListener("click", () => {
    panel.hidden = !panel.hidden;
    if (!panel.hidden && !greeted) {
      chatAppend("bot", "Hi! I'm EGAI. Type help to see what I can do.");
      greeted = true;
    }
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = input.value.trim();
    if (!msg) return;
    chatAppend("user", msg);
    input.value = "";
    try {
      const r = await fetch("/api/assistant", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg }),
      });
      const d = await r.json();
      chatAppend("bot", d.reply || "(no reply)");
    } catch (err) { chatAppend("bot", "assistant offline"); }
  });
}

function initDevTools() {
  const urlInput = document.getElementById("eg-art-url");
  const fetchBtn = document.getElementById("eg-art-fetch");
  const artOut = document.getElementById("eg-art-result");
  const tokenBtn = document.getElementById("eg-gen-token");
  const tokenOut = document.getElementById("eg-token-result");
  if (!fetchBtn) return;

  fetchBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (!url) return;
    artOut.textContent = "Fetching...";
    try {
      const r = await fetch("/api/fetch-art?url=" + encodeURIComponent(url));
      const body = await r.text();
      try { artOut.textContent = JSON.stringify(JSON.parse(body), null, 2); }
      catch (_) { artOut.textContent = body; }
    } catch (e) { artOut.textContent = "Request failed."; }
  });

  tokenBtn.addEventListener("click", async () => {
    tokenOut.textContent = "Generating...";
    try {
      const r = await fetch("/api/v1/token");
      tokenOut.textContent = JSON.stringify(await r.json(), null, 2);
    } catch (e) { tokenOut.textContent = "Request failed."; }
  });

  const fileName = document.getElementById("eg-file-name");
  const fileBtn = document.getElementById("eg-file-load");
  const fileOut = document.getElementById("eg-file-result");
  fileBtn.addEventListener("click", async () => {
    const name = fileName.value.trim();
    if (!name) return;
    fileOut.textContent = "Loading...";
    try {
      const r = await fetch("/api/card-art?file=" + encodeURIComponent(name));
      fileOut.textContent = r.ok ? await r.text() : `(${r.status}) not available`;
    } catch (e) { fileOut.textContent = "Request failed."; }
  });
}

function initMarketSearch() {
  const input = document.getElementById("eg-market-search");
  const btn = document.getElementById("eg-market-search-btn");
  const out = document.getElementById("eg-search-results");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const q = input.value.trim();
    if (!q) { out.textContent = ""; return; }
    out.textContent = "Searching...";
    try {
      const r = await fetch("/api/search?q=" + encodeURIComponent(q));
      const data = await r.json();
      out.textContent = Array.isArray(data)
        ? (data.length ? data.map(c => `${c.card_id ?? ""}: ${c.name ?? ""} (${c.rarity ?? ""})`).join(" | ")
                       : "No cards matched.")
        : JSON.stringify(data);
    } catch (e) { out.textContent = "Search failed."; }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  loadCatalogue(); initChat(); initDevTools(); initMarketSearch();
});

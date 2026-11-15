let token = localStorage.getItem("vg_token") || "";
let role = localStorage.getItem("vg_role") || "";
let name = localStorage.getItem("vg_name") || "";

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));

async function api(url, opt = {}) {
  const headers = { "Content-Type": "application/json", ...(opt.headers || {}) };
  if (token) headers.Authorization = "Bearer " + token;
  const response = await fetch(url, { ...opt, headers });
  const data = await response.json().catch(() => ({ detail: "Invalid response" }));
  if (!response.ok) throw Error(data.detail || "Request failed");
  return data;
}

function toast(message) {
  $("toast").textContent = message;
  $("toast").classList.add("show");
  setTimeout(() => $("toast").classList.remove("show"), 3000);
}

function showApp() {
  $("loginView").classList.add("hidden");
  $("appView").classList.remove("hidden");
  $("userLabel").textContent = name + " · " + role;
  document.querySelectorAll(".nav").forEach(button => {
    button.classList.toggle("hidden", role !== "admin" && button.dataset.page !== "documents");
  });

  // The old admin-generated demo controls are intentionally disabled.
  ["honeyDemo", "burstDemo", "demoMsg"].forEach(id => {
    if ($(id)) $(id).classList.add("hidden");
  });

  if (role === "admin") {
    page("overview");
    refreshAll();
  } else {
    page("documents");
  }
}

function loginView() {
  $("appView").classList.add("hidden");
  $("loginView").classList.remove("hidden");
}

function page(pageName) {
  document.querySelectorAll(".page").forEach(section => section.classList.add("hidden"));
  $(pageName + "Page").classList.remove("hidden");
  document.querySelectorAll(".nav").forEach(button => {
    button.classList.toggle("active", button.dataset.page === pageName);
  });
  $("pageTitle").textContent = ({
    overview: "Overview",
    contractors: "Contractors",
    documents: "Documents",
    monitoring: "Security monitoring"
  })[pageName];

  if (pageName === "overview") overview();
  if (pageName === "contractors") users();
  if (pageName === "documents") docs();
  if (pageName === "monitoring") {
    incidents();
    logs();
  }
}

document.querySelectorAll(".nav").forEach(button => {
  button.onclick = () => page(button.dataset.page);
});

$("loginForm").onsubmit = async event => {
  event.preventDefault();
  $("loginError").textContent = "";
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("username").value,
        password: $("password").value
      })
    });
    token = data.access_token;
    role = data.role;
    name = data.full_name;
    localStorage.setItem("vg_token", token);
    localStorage.setItem("vg_role", role);
    localStorage.setItem("vg_name", name);
    showApp();
  } catch (error) {
    $("loginError").textContent = error.message;
  }
};

$("logout").onclick = async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } catch {}
  token = "";
  role = "";
  name = "";
  localStorage.removeItem("vg_token");
  localStorage.removeItem("vg_role");
  localStorage.removeItem("vg_name");
  loginView();
};

async function overview() {
  try {
    const data = await api("/api/admin/overview");
    $("sUsers").textContent = data.contractors;
    $("sActive").textContent = data.active_contractors;
    $("sLogs").textContent = data.access_events;
    $("sInc").textContent = data.open_incidents;

    const rows = await api("/api/admin/incidents");
    $("recent").innerHTML = rows.slice(0, 6).map(item => `
      <tr>
        <td>${esc(new Date(item.created_at).toLocaleString())}</td>
        <td>${esc(item.username)}</td>
        <td>${esc(item.kind)}</td>
        <td><span class="tag ${esc(item.severity)}">${esc(item.severity)}</span></td>
        <td>${esc(item.status)}</td>
      </tr>
    `).join("") || '<tr><td colspan="5">No incidents yet.</td></tr>';
  } catch (error) {
    toast(error.message);
  }
}

async function users() {
  try {
    const rows = await api("/api/admin/users");
    $("users").innerHTML = rows.map(item => `
      <tr>
        <td>${esc(item.full_name)}</td>
        <td>${esc(item.username)}</td>
        <td><span class="tag ${esc(item.status)}">${esc(item.status)}</span></td>
        <td>${item.status === "active"
          ? `<button class="ghost" onclick="userAction(${item.id},'suspend')">Suspend</button>`
          : `<button class="secondary" onclick="userAction(${item.id},'restore')">Restore</button>`}
        </td>
      </tr>
    `).join("") || '<tr><td colspan="4">No contractors.</td></tr>';
  } catch (error) {
    toast(error.message);
  }
}

window.userAction = async (id, action) => {
  try {
    await api(`/api/admin/users/${id}/${action}`, { method: "POST" });
    await users();
    await overview();
    toast(action === "restore" ? "Contractor account restored" : "Contractor account suspended");
  } catch (error) {
    toast(error.message);
  }
};

$("addToggle").onclick = () => $("addBox").classList.toggle("hidden");

$("addForm").onsubmit = async event => {
  event.preventDefault();
  const ids = [...document.querySelectorAll('#addForm input[type=checkbox]:checked')]
    .map(input => input.value);
  try {
    await api("/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        username: $("newUser").value,
        full_name: $("newName").value,
        password: $("newPass").value,
        document_ids: ids
      })
    });
    $("addMsg").textContent = "Contractor created.";
    event.target.reset();
    users();
  } catch (error) {
    $("addMsg").textContent = error.message;
  }
};

async function docs() {
  try {
    const rows = await api("/api/documents");
    let html = rows.map(item => `
      <tr>
        <td><b>${esc(item.name)}</b><br>${esc(item.id)}</td>
        <td>${esc(item.category)}</td>
        <td>${esc(item.description)}</td>
        <td><button class="secondary" onclick="downloadDoc('${esc(item.id)}')">Download</button></td>
      </tr>
    `).join("");

    // A planted lure is presented as a plausible related archive reference.
    // It is not part of /api/documents and does not appear in the normal catalogue.
    if (role === "contractor") {
      const lure = await api("/api/vendor/decoy-link");
      html += `
        <tr class="related-reference">
          <td><b>${esc(lure.label)}</b><br><span class="tag">Related reference</span></td>
          <td>Archive</td>
          <td>${esc(lure.description)}</td>
          <td><button class="secondary" onclick="openDecoy('${esc(lure.document_id)}')">Open reference</button></td>
        </tr>
      `;
    }

    $("docs").innerHTML = html || '<tr><td colspan="4">No permitted documents.</td></tr>';
  } catch (error) {
    toast(error.message);
  }
}

window.downloadDoc = async id => {
  try {
    const data = await api(`/api/documents/${encodeURIComponent(id)}/download`, {
      method: "POST"
    });
    const blob = new Blob([data.content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = data.filename.replace(/\.pdf$/i, ".txt");
    link.click();
    URL.revokeObjectURL(url);
    toast("Synthetic document download recorded");
    if (role === "admin") logs();
  } catch (error) {
    toast(error.message);
  }
};

window.openDecoy = async id => {
  try {
    await api(`/api/documents/${encodeURIComponent(id)}/download`, { method: "POST" });
  } catch (error) {
    // The backend records the event and revokes this vendor's session.
    if (error.message.toLowerCase().includes("decoy resource accessed")) {
      toast("Critical alert recorded. Vendor account suspended.");
      token = "";
      role = "";
      name = "";
      localStorage.removeItem("vg_token");
      localStorage.removeItem("vg_role");
      localStorage.removeItem("vg_name");
      setTimeout(loginView, 900);
    } else {
      toast(error.message);
    }
  }
};

async function incidents() {
  try {
    const rows = await api("/api/admin/incidents");
    $("incidents").innerHTML = rows.map(item => `
      <tr>
        <td>${esc(new Date(item.created_at).toLocaleString())}</td>
        <td>${esc(item.username)}</td>
        <td>${esc(item.kind)}</td>
        <td><span class="tag ${esc(item.severity)}">${esc(item.severity)}</span></td>
        <td>${esc(item.description)}</td>
        <td>${esc(item.status)}</td>
        <td>${item.status === "open"
          ? `<button class="ghost" onclick="resolveIt(${item.id})">Resolve</button>`
          : ""}
        </td>
      </tr>
    `).join("") || '<tr><td colspan="7">No incidents.</td></tr>';
  } catch (error) {
    toast(error.message);
  }
}

window.resolveIt = async id => {
  try {
    await api(`/api/admin/incidents/${id}/resolve`, { method: "POST" });
    incidents();
    overview();
  } catch (error) {
    toast(error.message);
  }
};

async function logs() {
  try {
    const rows = await api("/api/admin/logs");
    $("logs").innerHTML = rows.map(item => `
      <tr>
        <td>${esc(new Date(item.created_at).toLocaleString())}</td>
        <td>${esc(item.username)}</td>
        <td>${esc(item.action)}</td>
        <td>${esc(item.document_id || "—")}</td>
        <td>${esc(item.result)}</td>
        <td>${esc(item.detail)}</td>
      </tr>
    `).join("") || '<tr><td colspan="6">No events.</td></tr>';
  } catch (error) {
    toast(error.message);
  }
}

async function refreshAll() {
  await overview();
  await users();
  await docs();
  await incidents();
  await logs();
}

$("refresh").onclick = refreshAll;
$("monRefresh").onclick = () => {
  incidents();
  logs();
  overview();
};

// Revalidate any remembered session before showing the application.
if (token) {
  api("/api/me")
    .then(user => {
      role = user.role;
      name = user.full_name;
      showApp();
    })
    .catch(() => {
      token = "";
      role = "";
      name = "";
      localStorage.removeItem("vg_token");
      localStorage.removeItem("vg_role");
      localStorage.removeItem("vg_name");
      loginView();
    });
} else {
  loginView();
}

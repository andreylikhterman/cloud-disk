const API_BASE = window.location.origin;
let authToken = localStorage.getItem("authToken");
let currentUsername = localStorage.getItem("username");

document.addEventListener("DOMContentLoaded", () => {
  if (authToken) {
    showApp();
  } else {
    showAuth();
  }
  setupEventListeners();
  setView(currentView);
});

function setupEventListeners() {
  document.getElementById("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    await login(
      document.getElementById("loginUsername").value,
      document.getElementById("loginPassword").value,
    );
  });

  const uploadZone = document.getElementById("uploadZone");
  const fileInput = document.getElementById("fileInput");

  uploadZone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", (e) => handleFiles(e.target.files));

  uploadZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    uploadZone.classList.add("dragover");
  });

  uploadZone.addEventListener("dragleave", () => {
    uploadZone.classList.remove("dragover");
  });

  uploadZone.addEventListener("drop", (e) => {
    e.preventDefault();
    uploadZone.classList.remove("dragover");
    handleFiles(e.dataTransfer.files);
  });

  document.getElementById("logoutBtn").addEventListener("click", logout);

  document.getElementById("searchInput").addEventListener("input", searchFiles);
  document.getElementById("sortSelect").addEventListener("change", sortFiles);
  document.getElementById("refreshBtn").addEventListener("click", loadFiles);

  document.querySelectorAll(".view-btn").forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset.view));
  });

  document.addEventListener("click", (e) => {
    const target = e.target;
    if (target.dataset.action === "download") {
      downloadFile(target.dataset.filename);
    } else if (target.dataset.action === "delete") {
      deleteFile(target.dataset.filename);
    } else if (target.dataset.action === "rename") {
      promptRename(target.dataset.filename);
    } else if (target.dataset.action === "share") {
      shareFile(target.dataset.filename);
    }
  });

  document
    .getElementById("cancelRenameBtn")
    .addEventListener("click", closeRenameModal);
  document.getElementById("confirmRenameBtn").addEventListener("click", () => {
    const oldName = document.getElementById("renameModal").dataset.filename;
    const newName = document.getElementById("newFilename").value;
    if (newName && newName !== oldName) {
      renameFile(oldName, newName);
    } else {
      closeRenameModal();
    }
  });

  document
    .getElementById("closeShareBtn")
    .addEventListener("click", closeShareModal);
  document
    .getElementById("copyShareBtn")
    .addEventListener("click", copyShareLink);
  document
    .getElementById("shareLinkInput")
    .addEventListener("click", (e) => e.target.select());
}

async function login(username, password) {
  try {
    const res = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (data.success) {
      authToken = data.data.token;
      currentUsername = data.data.username;
      localStorage.setItem("authToken", authToken);
      localStorage.setItem("username", currentUsername);
      showApp();
    } else {
      showAlert(data.message, "error");
    }
  } catch (e) {
    showAlert("Unable to connect to server", "error");
  }
}

function logout() {
  console.log("Logging out...");
  authToken = null;
  currentUsername = null;
  localStorage.removeItem("authToken");
  localStorage.removeItem("username");
  showAuth();
}
window.logout = logout;

function showAuth() {
  document.body.classList.add("auth-mode");
  document.getElementById("authSection").classList.remove("hidden");
  document.getElementById("appSection").classList.add("hidden");
}

function showApp() {
  document.body.classList.remove("auth-mode");
  document.getElementById("authSection").classList.add("hidden");
  document.getElementById("appSection").classList.remove("hidden");
  document.getElementById("currentUser").textContent = currentUsername;
  loadFiles();
  loadQuota();
}

async function handleFiles(files) {
  for (let file of files) {
    await uploadFile(file);
  }
  document.getElementById("fileInput").value = "";
}

async function uploadFile(file) {
  const maxSize = 256 * 1024 * 1024;
  if (file.size > maxSize) {
    showAlert("✗ File is too large (max 256 MB)", "error");
    return;
  }

  try {
    const quotaRes = await fetch(`${API_BASE}/quota`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });

    if (quotaRes.ok) {
      const quotaData = await quotaRes.json();
      if (quotaData.success && quotaData.data && quotaData.data.storage) {
        const available = quotaData.data.storage.quota - quotaData.data.storage.used;
        if (file.size > available) {
          showAlert("✗ Quota exceeded. Please delete some files first.", "error");
          loadQuota();
          return;
        }
      }
    }
  } catch (e) {
    console.error("Failed to check quota:", e);
  }

  const md5Hash = await calculateMD5(file);

  const formData = new FormData();
  formData.append("file", file);
  formData.append("md5", md5Hash);

  const progressEl = document.getElementById("uploadProgress");
  const fileNameEl = document.getElementById("uploadFileName");
  const percentEl = document.getElementById("uploadPercent");
  const progressBar = document.getElementById("uploadProgressBar");

  fileNameEl.textContent = file.name;
  percentEl.textContent = "0%";
  progressBar.style.width = "0%";
  progressEl.classList.remove("hidden");

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const percent = Math.round((e.loaded / e.total) * 100);
        percentEl.textContent = `${percent}%`;
        progressBar.style.width = `${percent}%`;
      }
    };

    xhr.onload = () => {
      progressEl.classList.add("hidden");

      if (xhr.status === 401) {
        logout();
        resolve();
        return;
      }

      if (xhr.status === 413 || xhr.status === 400) {
        showAlert("✗ File is too large (max 256 MB)", "error");
        resolve();
        return;
      }

      if (xhr.status === 403) {
        showAlert("✗ Quota exceeded. Please delete some files first.", "error");
        loadQuota();
        resolve();
        return;
      }

      try {
        const contentType = xhr.getResponseHeader("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
          const data = JSON.parse(xhr.responseText);
          if (data.success) {
            showAlert("✓ File uploaded successfully", "success");
            loadFiles();
            loadQuota();
          } else {
            showAlert(`✗ ${data.message}`, "error");
          }
        } else {
          if (xhr.responseText.includes("413 Request Entity Too Large")) {
            showAlert("✗ File is too large (max 256 MB)", "error");
          } else {
            showAlert(`✗ Upload failed: ${xhr.status} ${xhr.statusText}`, "error");
          }
        }
      } catch (e) {
        showAlert(`✗ Upload failed: ${xhr.status}`, "error");
      }
      resolve();
    };

    xhr.onerror = () => {
      progressEl.classList.add("hidden");
      showAlert("✗ Upload failed: Network error", "error");
      resolve();
    };

    xhr.open("POST", `${API_BASE}/upload`);
    xhr.setRequestHeader("Authorization", `Bearer ${authToken}`);
    xhr.send(formData);
  });
}

function calculateMD5(file) {
  return new Promise((resolve, reject) => {
    const chunkSize = 2097152;
    const chunks = Math.ceil(file.size / chunkSize);
    let currentChunk = 0;
    const spark = new SparkMD5.ArrayBuffer();
    const fileReader = new FileReader();

    fileReader.onload = function (e) {
      spark.append(e.target.result);
      currentChunk++;

      if (currentChunk < chunks) {
        loadNext();
      } else {
        resolve(spark.end());
      }
    };

    fileReader.onerror = function () {
      reject(new Error("Failed to read file for MD5 calculation"));
    };

    function loadNext() {
      const start = currentChunk * chunkSize;
      const end = Math.min(start + chunkSize, file.size);
      fileReader.readAsArrayBuffer(file.slice(start, end));
    }

    loadNext();
  });
}

let allFiles = [];

async function loadFiles() {
  try {
    const res = await fetch(`${API_BASE}/files`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    const data = await res.json();

    if (data.success) {
      allFiles = data.data || [];
      applyFilters();
    } else {
      if (res.status === 401) logout();
    }
  } catch (e) {
    showAlert("Unable to load files from server", "error");
  }
}
window.loadFiles = loadFiles;

function searchFiles() {
  applyFilters();
}
window.searchFiles = searchFiles;

function sortFiles() {
  applyFilters();
}
window.sortFiles = sortFiles;

function applyFilters() {
  const searchTerm = document.getElementById("searchInput").value.toLowerCase();
  const sortType = document.getElementById("sortSelect").value;

  let filtered = allFiles.filter((file) =>
    file.name.toLowerCase().includes(searchTerm),
  );

  filtered.sort((a, b) => {
    switch (sortType) {
      case "name":
        return a.name.localeCompare(b.name);
      case "size":
        return b.size - a.size;
      case "date":
        return new Date(b.modTime) - new Date(a.modTime);
      default:
        return 0;
    }
  });

  renderFiles(filtered);
}

let currentView = localStorage.getItem("viewMode") || "list";

function setView(view) {
  console.log("Setting view:", view);
  currentView = view;
  localStorage.setItem("viewMode", view);

  const list = document.getElementById("fileList");
  if (view === "grid") {
    list.classList.add("grid");
  } else {
    list.classList.remove("grid");
  }

  document.querySelectorAll(".view-btn").forEach((btn) => {
    if (btn.dataset.view === view) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });
}
window.setView = setView;

async function deleteFile(filename) {
  console.log("Deleting file:", filename);
  try {
    const res = await fetch(
      `${API_BASE}/delete/${encodeURIComponent(filename)}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${authToken}` },
      },
    );
    const data = await res.json();

    if (data.success) {
      loadFiles();
      loadQuota();
    } else {
      showAlert(data.message, "error");
    }
  } catch (e) {
    showAlert("Failed to delete file", "error");
  }
}
window.deleteFile = deleteFile;

async function downloadFile(filename) {
  console.log("Downloading file:", filename);
  try {
    const res = await fetch(
      `${API_BASE}/download/${encodeURIComponent(filename)}`,
      {
        headers: { Authorization: `Bearer ${authToken}` },
      },
    );

    if (res.ok) {
      const serverMD5 = res.headers.get("Content-MD5");
      const blob = await res.blob();

      if (serverMD5) {
        const file = new File([blob], filename);
        const clientMD5 = await calculateMD5(file);

        if (clientMD5 !== serverMD5) {
          showAlert("✗ File integrity check failed: MD5 mismatch", "error");
          console.error(
            `MD5 mismatch: server=${serverMD5}, client=${clientMD5}`,
          );
          return;
        }
        console.log(`MD5 verified: ${clientMD5}`);
      }

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } else {
      showAlert("Failed to download file", "error");
    }
  } catch (e) {
    showAlert("Failed to download file", "error");
  }
}
window.downloadFile = downloadFile;

function renderFiles(files) {
  const list = document.getElementById("fileList");
  if (files.length === 0) {
    list.innerHTML = '<div class="empty-state">No files yet</div>';
    return;
  }

  list.innerHTML = files
    .map(
      (file) => `
        <div class="file-item">
            <div class="file-icon-wrapper">${getFileIcon(file.name)}</div>
            <div class="file-info">
                <div class="file-name">${file.name}</div>
                <div class="file-meta">${formatSize(file.size)} • ${new Date(file.modTime).toLocaleDateString()}</div>
            </div>
            <div class="file-actions flex gap-2">
                <button data-action="share" data-filename="${file.name}" class="btn btn-sm btn-info">Share</button>
                <button data-action="rename" data-filename="${file.name}" class="btn btn-sm btn-warning">Edit</button>
                <button data-action="download" data-filename="${file.name}" class="btn btn-sm btn-success">Download</button>
                <button data-action="delete" data-filename="${file.name}" class="btn btn-sm btn-danger">Delete</button>
            </div>
        </div>
    `,
    )
    .join("");
}

function getFileIcon(filename) {
  return `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M14 2H6C4.89543 2 4 2.89543 4 4V20C4 21.1046 4.89543 22 6 22H18C19.1046 22 20 21.1046 20 20V8L14 2Z" stroke="#888888" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M14 2V8H20" stroke="#888888" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
}

function formatSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function showAlert(msg, type) {
  const container = document.getElementById("alertContainer");

  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  const alert = document.createElement("div");
  alert.className = `alert alert-${type}`;
  alert.textContent = msg;
  container.appendChild(alert);
  setTimeout(() => alert.remove(), type === "info" ? 3000 : 5000);
}

let renameFilename = "";

function promptRename(filename) {
  const modal = document.getElementById("renameModal");
  const input = document.getElementById("newFilename");
  modal.dataset.filename = filename;
  input.value = filename;
  modal.classList.remove("hidden");
  input.focus();
}

function closeRenameModal() {
  document.getElementById("renameModal").classList.add("hidden");
}

async function renameFile(oldName, newName) {
  try {
    const res = await fetch(`${API_BASE}/rename`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ oldName, newName }),
    });
    const data = await res.json();

    if (data.success) {
      showAlert("File renamed successfully", "success");
      closeRenameModal();
      loadFiles();
    } else {
      showAlert(data.message, "error");
    }
  } catch (e) {
    showAlert("Failed to rename file", "error");
  }
}

async function shareFile(filename) {
  try {
    const res = await fetch(`${API_BASE}/share`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ filename }),
    });
    const data = await res.json();

    if (data.success) {
      const shareUrl = `${API_BASE}/s/${data.data.token}`;
      openShareModal(shareUrl);
    } else {
      showAlert(data.message, "error");
    }
  } catch (e) {
    showAlert("Failed to generate share link", "error");
  }
}

function openShareModal(url) {
  const modal = document.getElementById("shareModal");
  const input = document.getElementById("shareLinkInput");
  input.value = url;
  modal.classList.remove("hidden");
}

function closeShareModal() {
  document.getElementById("shareModal").classList.add("hidden");
}

function copyShareLink() {
  const input = document.getElementById("shareLinkInput");
  input.select();
  document.execCommand("copy");
  showAlert("✓ Link copied to clipboard", "success");
}

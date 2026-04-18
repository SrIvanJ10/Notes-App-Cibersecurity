// ---------------------------------------------------------------------------
// Auth guard
// ---------------------------------------------------------------------------
const token = localStorage.getItem("token");
const username = localStorage.getItem("username");

if (!token) {
  window.location.href = "/index.html";
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let notes = [];
let currentNoteId = null;   // null = new unsaved note, number = existing note
let isNewNote = false;

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
document.getElementById("username-display").textContent = username || "Usuario";
loadNotes();

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------
async function api(method, path, body = null) {
  const options = {
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  };
  if (body !== null) options.body = JSON.stringify(body);

  const res = await fetch(path, options);

  // Token expired or invalid — send back to login
  if (res.status === 401) {
    logout();
    return null;
  }

  return res;
}

// ---------------------------------------------------------------------------
// Load & render notes list
// ---------------------------------------------------------------------------
async function loadNotes() {
  const res = await api("GET", "/api/notes");
  if (!res) return;

  notes = await res.json();
  renderList();
}

function renderList() {
  const listEl = document.getElementById("notes-list");

  if (notes.length === 0) {
    listEl.innerHTML =
      '<p class="notes-empty-hint">Sin notas todavia.<br>Crea la primera con el boton de arriba.</p>';
    return;
  }

  listEl.innerHTML = notes
    .map(
      (note) => `
      <div class="note-item ${note.id === currentNoteId ? "active" : ""}"
           onclick="openNote(${note.id})">
        <div class="note-item-title">${note.title}</div>
        <div class="note-item-preview">${note.content || "Sin contenido"}</div>
        <div class="note-item-date">${formatDate(note.updated_at)}</div>
      </div>`
    )
    .join("");
}

// ---------------------------------------------------------------------------
// Open existing note
// ---------------------------------------------------------------------------
function openNote(noteId) {
  const note = notes.find((n) => n.id === noteId);
  if (!note) return;

  currentNoteId = noteId;
  isNewNote = false;

  document.getElementById("note-title").value = note.title;
  document.getElementById("note-content").value = note.content || "";
  document.getElementById("save-status").textContent = "";
  document.getElementById("btn-delete").classList.remove("hidden");

  showEditor();
  renderList();
}

// ---------------------------------------------------------------------------
// New note
// ---------------------------------------------------------------------------
function newNote() {
  currentNoteId = null;
  isNewNote = true;

  document.getElementById("note-title").value = "";
  document.getElementById("note-content").value = "";
  document.getElementById("save-status").textContent = "";
  document.getElementById("btn-delete").classList.add("hidden");

  // Remove active highlight from list
  document.querySelectorAll(".note-item").forEach((el) => el.classList.remove("active"));

  showEditor();
  document.getElementById("note-title").focus();
}

// ---------------------------------------------------------------------------
// Save note (create or update)
// ---------------------------------------------------------------------------
async function saveNote() {
  const title = document.getElementById("note-title").value.trim();
  const content = document.getElementById("note-content").value;
  const statusEl = document.getElementById("save-status");

  if (!title) {
    setStatus(statusEl, "El titulo es obligatorio", "error");
    return;
  }

  try {
    let res;
    if (isNewNote) {
      res = await api("POST", "/api/notes", { title, content });
    } else {
      res = await api("PUT", `/api/notes/${currentNoteId}`, { title, content });
    }

    if (!res) return;

    const saved = await res.json();

    if (!res.ok) {
      setStatus(statusEl, saved.error || "Error al guardar", "error");
      return;
    }

    // Update local state
    const idx = notes.findIndex((n) => n.id === saved.id);
    if (idx >= 0) {
      notes[idx] = saved;
    } else {
      notes.unshift(saved);
    }

    currentNoteId = saved.id;
    isNewNote = false;
    document.getElementById("btn-delete").classList.remove("hidden");

    renderList();
    setStatus(statusEl, "Guardado correctamente", "ok");
  } catch {
    setStatus(statusEl, "Error de conexion", "error");
  }
}

// ---------------------------------------------------------------------------
// Delete note
// ---------------------------------------------------------------------------
async function deleteNote() {
  if (!currentNoteId) return;

  if (!confirm("¿Seguro que quieres eliminar esta nota? Esta accion no se puede deshacer.")) {
    return;
  }

  try {
    const res = await api("DELETE", `/api/notes/${currentNoteId}`);
    if (!res) return;

    if (res.ok) {
      notes = notes.filter((n) => n.id !== currentNoteId);
      currentNoteId = null;
      renderList();

      if (notes.length > 0) {
        openNote(notes[0].id);
      } else {
        showEmptyState();
      }
    }
  } catch {
    alert("Error al eliminar la nota.");
  }
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------
function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("username");
  window.location.href = "/index.html";
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------
function showEditor() {
  document.getElementById("empty-state").classList.add("hidden");
  document.getElementById("note-editor").classList.remove("hidden");
}

function showEmptyState() {
  document.getElementById("note-editor").classList.add("hidden");
  document.getElementById("empty-state").classList.remove("hidden");
  currentNoteId = null;
  isNewNote = false;
}

function setStatus(el, msg, type) {
  el.textContent = msg;
  el.style.color = type === "error" ? "#e53e3e" : "#38a169";
  if (type === "ok") {
    setTimeout(() => { el.textContent = ""; }, 2500);
  }
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.appendChild(document.createTextNode(text || ""));
  return div.innerHTML;
}

function formatDate(dateStr) {
  // SQLite stores UTC timestamps without timezone info
  const date = new Date(dateStr + "Z");
  return date.toLocaleString("es-ES", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}
// Redirect to dashboard if already authenticated
// (el username en localStorage es solo una pista visual; la sesión real la valida el servidor)
if (localStorage.getItem("username")) {
  window.location.href = "/dashboard.html";
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
function switchTab(tab) {
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  const tabLogin = document.getElementById("tab-login");
  const tabRegister = document.getElementById("tab-register");

  if (tab === "login") {
    loginForm.classList.remove("hidden");
    registerForm.classList.add("hidden");
    tabLogin.classList.add("active");
    tabRegister.classList.remove("active");
  } else {
    loginForm.classList.add("hidden");
    registerForm.classList.remove("hidden");
    tabLogin.classList.remove("active");
    tabRegister.classList.add("active");
  }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------
async function login() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const errorEl = document.getElementById("login-error");

  errorEl.classList.add("hidden");

  if (!username || !password) {
    showError(errorEl, "Por favor completa todos los campos");
    return;
  }

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError(errorEl, data.error || "Error al iniciar sesion");
      return;
    }

    // El token viene en una cookie HttpOnly
    // Solo guardamos el username en localStorage para mostrarlo en la interfaz.
    localStorage.setItem("username", data.username);
    window.location.href = "/dashboard.html";
  } catch {
    showError(errorEl, "Error de conexion. Intenta de nuevo.");
  }
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------
async function register() {
  const username = document.getElementById("reg-username").value.trim();
  const password = document.getElementById("reg-password").value;
  const confirm = document.getElementById("reg-confirm").value;
  const errorEl = document.getElementById("register-error");
  const successEl = document.getElementById("register-success");

  errorEl.classList.add("hidden");
  successEl.classList.add("hidden");

  if (!username || !password || !confirm) {
    showError(errorEl, "Por favor completa todos los campos");
    return;
  }

  if (password !== confirm) {
    showError(errorEl, "Las contrasenas no coinciden");
    return;
  }

  try {
    const res = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError(errorEl, data.error || "Error al registrarse");
      return;
    }

    successEl.textContent = "Cuenta creada. Ahora puedes iniciar sesion.";
    successEl.classList.remove("hidden");

    // Switch to login tab after a short delay
    setTimeout(() => switchTab("login"), 1800);
  } catch {
    showError(errorEl, "Error de conexion. Intenta de nuevo.");
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove("hidden");
}

// Allow Enter key to submit the visible form
document.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const loginForm = document.getElementById("login-form");
  if (!loginForm.classList.contains("hidden")) {
    login();
  } else {
    register();
  }
});
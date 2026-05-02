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

    // Contraseña correcta: el servidor pide el segundo factor
    showTotpVerify();
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

    // Mostrar el secreto TOTP para que el usuario lo añada a su app
    document.getElementById("totp-secret-display").textContent = data.totp_secret;
    document.getElementById("totp-uri-display").textContent = data.totp_uri;
    hideAllForms();
    document.getElementById("totp-setup").classList.remove("hidden");
  } catch {
    showError(errorEl, "Error de conexion. Intenta de nuevo.");
  }
}

// ---------------------------------------------------------------------------
// TOTP verify
// ---------------------------------------------------------------------------
async function verifyTotp() {
  const code = document.getElementById("totp-code").value.trim();
  const errorEl = document.getElementById("totp-error");
  errorEl.classList.add("hidden");

  if (!code) {
    showError(errorEl, "Introduce el codigo de tu app de autenticacion");
    return;
  }

  try {
    const res = await fetch("/api/auth/totp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError(errorEl, data.error || "Codigo incorrecto");
      return;
    }

    // Token de sesión recibido en cookie HttpOnly, guardamos solo el username
    localStorage.setItem("username", data.username);
    window.location.href = "/dashboard.html";
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

function hideAllForms() {
  ["login-form", "register-form", "totp-setup", "totp-verify-form"].forEach(id => {
    document.getElementById(id).classList.add("hidden");
  });
  document.getElementById("auth-tabs") && document.getElementById("auth-tabs").classList.add("hidden");
}

function showTotpVerify() {
  hideAllForms();
  document.getElementById("totp-verify-form").classList.remove("hidden");
  document.getElementById("totp-code").focus();
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
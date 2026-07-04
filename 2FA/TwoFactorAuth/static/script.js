// --- Element references -----------------------------------------------
const tabButtons = document.querySelectorAll(".tab-btn");
const panels = {
  register: document.getElementById("panel-register"),
  "login-step1": document.getElementById("panel-login-step1"),
};

const regUsername = document.getElementById("reg-username");
const regEmail = document.getElementById("reg-email");
const regPassword = document.getElementById("reg-password");
const registerBtn = document.getElementById("register-btn");
const registerStatus = document.getElementById("register-status");

const loginUsername = document.getElementById("login-username");
const loginPassword = document.getElementById("login-password");
const loginStep1Btn = document.getElementById("login-step1-btn");
const loginStep1Status = document.getElementById("login-step1-status");

const panelLoginStep2 = document.getElementById("panel-login-step2");
const panelSuccess = document.getElementById("panel-success");
const demoOtpHint = document.getElementById("demo-otp-hint");
const otpCode = document.getElementById("otp-code");
const loginStep2Btn = document.getElementById("login-step2-btn");
const loginStep2Status = document.getElementById("login-step2-status");
const backBtn = document.getElementById("back-btn");
const logoutBtn = document.getElementById("logout-btn");

let pendingUsername = null;

// --- Helpers -------------------------------------------------------------

function setStatus(el, message, kind) {
  el.textContent = message || "";
  el.className = "status" + (kind ? ` ${kind}` : "");
}

function showOnly(view) {
  panels.register.classList.add("hidden");
  panels["login-step1"].classList.add("hidden");
  panelLoginStep2.classList.add("hidden");
  panelSuccess.classList.add("hidden");
  view.classList.remove("hidden");
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  return { ok: response.ok && data.ok, data };
}

// --- Tab switching ---------------------------------------------------------

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    tabButtons.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    showOnly(tab === "register" ? panels.register : panels["login-step1"]);
  });
});

// --- Registration ---------------------------------------------------------

registerBtn.addEventListener("click", async () => {
  setStatus(registerStatus, "Registering...", "");
  const { ok, data } = await postJSON("/api/register", {
    username: regUsername.value,
    email: regEmail.value,
    password: regPassword.value,
  });

  if (!ok) {
    setStatus(registerStatus, data.error || "Registration failed.", "error");
    return;
  }

  setStatus(registerStatus, data.message, "success");
  regUsername.value = "";
  regEmail.value = "";
  regPassword.value = "";

  // Conveniently switch to the login tab.
  document.querySelector('.tab-btn[data-tab="login"]').click();
});

// --- Login step 1: password -------------------------------------------

loginStep1Btn.addEventListener("click", async () => {
  setStatus(loginStep1Status, "Checking password...", "");
  const username = loginUsername.value;
  const { ok, data } = await postJSON("/api/login/step1", {
    username,
    password: loginPassword.value,
  });

  if (!ok) {
    setStatus(loginStep1Status, data.error || "Login failed.", "error");
    return;
  }

  pendingUsername = username;
  setStatus(loginStep1Status, "", "");
  loginPassword.value = "";

  demoOtpHint.innerHTML = data.demo_otp
    ? `<strong>Demo mode:</strong> your one-time code is <strong>${data.demo_otp}</strong> (a real app would email this instead of showing it).`
    : "";

  otpCode.value = "";
  setStatus(loginStep2Status, "", "");
  showOnly(panelLoginStep2);
  otpCode.focus();
});

// --- Login step 2: OTP --------------------------------------------------

loginStep2Btn.addEventListener("click", async () => {
  if (!pendingUsername) {
    setStatus(loginStep2Status, "Please start the login again.", "error");
    return;
  }

  setStatus(loginStep2Status, "Verifying code...", "");
  const { ok, data } = await postJSON("/api/login/step2", {
    username: pendingUsername,
    otp: otpCode.value,
  });

  if (!ok) {
    setStatus(loginStep2Status, data.error || "Verification failed.", "error");
    return;
  }

  showOnly(panelSuccess);
});

otpCode.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    loginStep2Btn.click();
  }
});

backBtn.addEventListener("click", () => {
  pendingUsername = null;
  setStatus(loginStep2Status, "", "");
  showOnly(panels["login-step1"]);
});

// --- Logout / reset --------------------------------------------------------

logoutBtn.addEventListener("click", () => {
  pendingUsername = null;
  loginUsername.value = "";
  setStatus(loginStep1Status, "", "");
  document.querySelector('.tab-btn[data-tab="login"]').click();
});

// Start on the Register tab.
showOnly(panels.register);

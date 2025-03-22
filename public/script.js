// Variables globales
let userId;
let socket;

// Elementos DOM
const DOM = {
  authContainer: document.getElementById('authContainer'),
  chatContainer: document.getElementById('chatContainer'),
  username: document.getElementById('username'),
  password: document.getElementById('password'),
  messages: document.getElementById('messages'),
  messageForm: document.getElementById('messageForm'),
  messageInput: document.getElementById('messageInput'),
  passwordModal: document.getElementById('passwordModal'),
  currentPassword: document.getElementById('currentPassword'),
  newPassword: document.getElementById('newPassword'),
  passwordError: document.getElementById('passwordError')
};

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  // Autenticación
  document.getElementById('registerBtn').addEventListener('click', register);
  document.getElementById('loginBtn').addEventListener('click', login);
  document.getElementById('logoutBtn').addEventListener('click', logout);
  
  // Chat
  DOM.messageForm.addEventListener('submit', handleMessageSubmit);
  
  // Modal contraseña
  document.getElementById('changePassBtn').addEventListener('click', showPasswordModal);
  document.getElementById('closeModal').addEventListener('click', hidePasswordModal);
  document.getElementById('confirmChangePass').addEventListener('click', changePassword);

  checkAuth();
});

// ================= FUNCIONES PRINCIPALES =================

async function checkAuth() {
  try {
    const response = await fetch('/check-auth');
    if (response.ok) {
      const data = await response.json();
      userId = data.userId;
      toggleUI(true);
      initializeChat();
    }
  } catch (error) {
    console.error('Error checking auth:', error);
  }
}

async function register() {
  try {
    const username = DOM.username.value.trim();
    const password = DOM.password.value;

    const response = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();
    if (response.ok) {
      alert('✅ Registro exitoso');
    } else {
      alert(`❌ Error: ${data.error || 'Desconocido'}`);
    }
  } catch (error) {
    alert('🚨 Error de red: ' + error.message);
  }
}

async function login() {
  try {
    const username = DOM.username.value.trim();
    const password = DOM.password.value;

    const response = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });

    if (response.ok) {
      await checkAuth();
    } else {
      const data = await response.json();
      alert(`🔐 Error: ${data.error || 'Credenciales incorrectas'}`);
    }
  } catch (error) {
    alert('🚨 Error de red: ' + error.message);
  }
}

function initializeChat() {
  socket = io("https://chatus-production.up.railway.app", {
    withCredentials: true,
    transports: ['websocket']
  });

  socket.on('chat message', (data) => {
    const li = document.createElement('li');
    li.className = data.uid === userId ? 'own-message' : 'other-message';
    li.innerHTML = `
      <div class="message-container">
        <strong>${data.user}:</strong>
        <div class="message-content">${data.text}</div>
      </div>
    `;
    DOM.messages.appendChild(li);
    DOM.messages.scrollTop = DOM.messages.scrollHeight;
  });
}

function handleMessageSubmit(e) {
  e.preventDefault();
  const message = DOM.messageInput.value.trim();
  if (message && socket) {
    socket.emit('chat message', message);
    DOM.messageInput.value = '';
  }
}

async function logout() {
  await fetch('/logout', { method: 'POST' });
  toggleUI(false);
  window.location.reload();
}

// ================= FUNCIONES MODAL =================
function showPasswordModal() {
  DOM.passwordModal.style.display = 'block';
}

function hidePasswordModal() {
  DOM.passwordModal.style.display = 'none';
  DOM.passwordError.textContent = '';
}

async function changePassword() {
  const current = DOM.currentPassword.value;
  const newPass = DOM.newPassword.value;

  if (!current || !newPass) {
    DOM.passwordError.textContent = 'Ambos campos son requeridos';
    return;
  }

  try {
    const response = await fetch('/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: current, newPassword: newPass })
    });

    if (response.ok) {
      alert('✅ Contraseña cambiada');
      hidePasswordModal();
    } else {
      const error = await response.json();
      DOM.passwordError.textContent = error.error;
    }
  } catch (error) {
    DOM.passwordError.textContent = 'Error de conexión';
  }
}

// ================= HELPERS =================
function toggleUI(isLoggedIn) {
  DOM.authContainer.style.display = isLoggedIn ? 'none' : 'block';
  DOM.chatContainer.style.display = isLoggedIn ? 'block' : 'none';
}
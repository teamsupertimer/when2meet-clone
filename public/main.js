// Common client‑side utilities for the When2Meet clone

// Make an API request. Returns parsed JSON or throws on error.
async function apiFetch(path, options = {}) {
  const res = await fetch(path, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    credentials: 'include',
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || 'Request failed');
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

// Fetch current user information. Returns user or null.
async function getCurrentUser() {
  try {
    const res = await apiFetch('/api/me', { method: 'GET' });
    return res.user;
  } catch (e) {
    console.error(e);
    return null;
  }
}

// Render navigation bar. Expects there to be a <nav> element inside header.
async function renderNav() {
  const nav = document.querySelector('header nav');
  if (!nav) return;
  const user = await getCurrentUser();
  nav.innerHTML = '';
  if (user) {
    // Logged in view
    const greeting = document.createElement('span');
    greeting.textContent = `안녕하세요, ${user.username}`;
    greeting.style.marginRight = '1rem';
    nav.appendChild(greeting);
    const createLink = document.createElement('a');
    createLink.href = '/create.html';
    createLink.textContent = '새 이벤트 생성';
    nav.appendChild(createLink);
    const logoutLink = document.createElement('a');
    logoutLink.href = '#';
    logoutLink.textContent = '로그아웃';
    logoutLink.addEventListener('click', async e => {
      e.preventDefault();
      await apiFetch('/api/logout', { method: 'POST' });
      location.href = '/';
    });
    nav.appendChild(logoutLink);
  } else {
    // Logged out view
    const loginLink = document.createElement('a');
    loginLink.href = '/login.html';
    loginLink.textContent = '로그인';
    nav.appendChild(loginLink);
    const registerLink = document.createElement('a');
    registerLink.href = '/register.html';
    registerLink.textContent = '회원가입';
    nav.appendChild(registerLink);
  }
}

// Utility to format date/time
function formatDateTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString();
}
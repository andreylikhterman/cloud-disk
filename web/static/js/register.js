const API_BASE = window.location.origin;

document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;
    await register(username, password);
});

async function register(username, password) {
    try {
        const res = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();

        if (data.success) {
            showAlert('Account created successfully! Redirecting to login...', 'success');
            setTimeout(() => {
                window.location.href = '/';
            }, 1500);
        } else {
            showAlert(data.message || 'Registration failed', 'error');
        }
    } catch (e) {
        showAlert('Connection error', 'error');
    }
}

function showAlert(msg, type) {
    if (type !== 'error') return;
    const container = document.getElementById('alertContainer');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = msg;
    container.appendChild(alert);
    setTimeout(() => alert.remove(), 5000);
}

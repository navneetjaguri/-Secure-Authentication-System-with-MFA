const API_BASE = '/api';
let currentUserId = null;

// Utility functions
function showMessage(message, type = 'info') {
    const messageDiv = document.getElementById('message');
    if (messageDiv) {
        messageDiv.textContent = message;
        messageDiv.className = `message ${type}`;
        messageDiv.style.display = 'block';
    }
}

function setLoading(buttonId, isLoading) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.disabled = isLoading;
        if (isLoading) {
            button.classList.add('loading');
        } else {
            button.classList.remove('loading');
        }
    }
}

function getToken() {
    return localStorage.getItem('auth_token');
}

function setToken(token) {
    localStorage.setItem('auth_token', token);
}

function removeToken() {
    localStorage.removeItem('auth_token');
}

function checkAuth() {
    const token = getToken();
    if (!token) {
        if (window.location.pathname.includes('dashboard')) {
            window.location.href = 'login.html';
        }
        return false;
    }
    return true;
}

// API calls
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
        },
    };

    const token = getToken();
    if (token) {
        options.headers.Authorization = `Bearer ${token}`;
    }

    if (data) {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'An error occurred');
        }
        
        return result;
    } catch (error) {
        throw new Error(error.message);
    }
}

// Auth handlers
async function handleSignup(e) {
    e.preventDefault();
    setLoading('signupBtn', true);

    const formData = new FormData(e.target);
    const data = {
        username: formData.get('username'),
        email: formData.get('email'),
        password: formData.get('password')
    };

    const confirmPassword = formData.get('confirmPassword');
    
    if (data.password !== confirmPassword) {
        showMessage('Passwords do not match', 'error');
        setLoading('signupBtn', false);
        return;
    }

    try {
        await apiCall('/signup', 'POST', data);
        showMessage('Account created successfully! Please login.', 'success');
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 2000);
    } catch (error) {
        showMessage(error.message, 'error');
    } finally {
        setLoading('signupBtn', false);
    }
}

async function handleLogin(e) {
    e.preventDefault();
    setLoading('loginBtn', true);

    const formData = new FormData(e.target);
    const data = {
        username: formData.get('username'),
        password: formData.get('password')
    };

    try {
        const result = await apiCall('/login', 'POST', data);

        if (result.mfa_required) {
            currentUserId = result.user_id;
            // Show MFA section
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('mfaSection').style.display = 'block';
            showMessage('Enter your MFA code', 'info');
        } else {
            setToken(result.token);
            showMessage('Login successful!', 'success');
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1000);
        }
    } catch (error) {
        showMessage(error.message, 'error');
    } finally {
        setLoading('loginBtn', false);
    }
}

async function handleMFAVerification(e) {
    e.preventDefault();
    setLoading('verifyBtn', true);

    // Get user ID from URL params or localStorage
    const urlParams = new URLSearchParams(window.location.search);
    const userId = urlParams.get('user_id') || currentUserId;

    if (!userId) {
        showMessage('Session expired. Please login again.', 'error');
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 2000);
        return;
    }

    // Collect code from boxes
    const codeBoxes = document.querySelectorAll('.code-box');
    const totpCode = Array.from(codeBoxes).map(box => box.value).join('');

    if (totpCode.length !== 6) {
        showMessage('Please enter all 6 digits', 'error');
        setLoading('verifyBtn', false);
        return;
    }

    const data = {
        user_id: parseInt(userId),
        totp_code: totpCode
    };

    try {
        const result = await apiCall('/verify-mfa', 'POST', data);
        setToken(result.token);
        showMessage('MFA verification successful!', 'success');
        setTimeout(() => {
            window.location.href = 'dashboard.html';
        }, 1000);
    } catch (error) {
        showMessage(error.message, 'error');
    } finally {
        setLoading('verifyBtn', false);
    }
}

async function handleForgotPassword(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const data = {
        email: formData.get('email')
    };

    try {
        await apiCall('/forgot-password', 'POST', data);
        showMessage('If the email exists, a reset link has been sent.', 'success');
    } catch (error) {
        showMessage(error.message, 'error');
    }
}

async function handlePasswordReset(e, token) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const password = formData.get('newPassword');
    const confirmPassword = formData.get('confirmNewPassword');

    if (password !== confirmPassword) {
        showMessage('Passwords do not match', 'error');
        return;
    }

    const data = {
        token: token,
        password: password
    };

    try {
        await apiCall('/reset-password', 'POST', data);
        showMessage('Password reset successful! You can now login.', 'success');
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 2000);
    } catch (error) {
        showMessage(error.message, 'error');
    }
}

async function loadDashboard() {
    try {
        const userInfo = await apiCall('/dashboard');
        
        const userInfoDiv = document.getElementById('userInfo');
        userInfoDiv.innerHTML = `
            <h3>Welcome, ${userInfo.username}!</h3>
            <p><strong>Email:</strong> ${userInfo.email}</p>
            <p><strong>Member since:</strong> ${new Date(userInfo.created_at).toLocaleDateString()}</p>
        `;

        const mfaStatusDiv = document.getElementById('mfaStatus');
        if (userInfo.mfa_enabled) {
            mfaStatusDiv.innerHTML = '<p class="status-enabled">✅ MFA is enabled</p>';
        } else {
            mfaStatusDiv.innerHTML = `
                <p class="status-disabled">❌ MFA is not enabled</p>
                <button onclick="setupMFA()" class="btn btn-primary">Setup MFA</button>
            `;
        }
    } catch (error) {
        showMessage(error.message, 'error');
        if (error.message.includes('Token')) {
            logout();
        }
    }
}

async function setupMFA() {
    try {
        const result = await apiCall('/setup-mfa', 'POST');
        
        const qrCodeDiv = document.getElementById('qrCode');
        qrCodeDiv.innerHTML = `<img src="${result.qr_code}" alt="QR Code">`;
        
        const secretSpan = document.getElementById('mfaSecret');
        secretSpan.textContent = result.secret;
        
        document.getElementById('mfaSetup').style.display = 'block';
    } catch (error) {
        showMessage(error.message, 'error');
    }
}

async function handleEnableMFA(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const data = {
        totp_code: formData.get('verifyCode')
    };

    try {
        await apiCall('/enable-mfa', 'POST', data);
        showMessage('MFA enabled successfully!', 'success');
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    } catch (error) {
        showMessage(error.message, 'error');
    }
}

function logout() {
    removeToken();
    window.location.href = 'login.html';
}

// Check URL params for MFA redirect
window.addEventListener('load', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const userId = urlParams.get('user_id');
    if (userId && window.location.pathname.includes('mfa')) {
        currentUserId = userId;
    }
});

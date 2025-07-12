// CyberNox Admin Login JavaScript
const API_BASE = 'http://127.0.0.1:5000/api/v1';

// Auto-fill demo credentials
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('username').value = 'admin';
    document.getElementById('password').value = 'cybernox123';
    
    // Check if user is already logged in
    const token = localStorage.getItem('cybernox_token');
    if (token) {
        console.log('Token found, verifying validity...');
        
        // Verify token is still valid by accessing dashboard
        fetch('/api/v1/dashboard', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'text/html'
            }
        }).then(response => {
            if (response.ok) {
                console.log('Token is valid, redirecting to dashboard...');
                // Token is valid, redirect to dashboard
                return response.text();
            } else {
                console.log('Token is invalid, clearing and staying on login page...');
                // Token invalid, remove it
                localStorage.removeItem('cybernox_token');
                localStorage.removeItem('cybernox_remember');
                throw new Error('Token validation failed');
            }
        }).then(html => {
            // Replace current page with dashboard
            document.open();
            document.write(html);
            document.close();
            window.history.pushState({}, 'CyberNox Dashboard', '/api/v1/dashboard');
        }).catch(error => {
            console.log('Staying on login page:', error.message);
            // Stay on login page - user needs to login
        });
    } else {
        console.log('No token found, user needs to login');
    }
});

document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    
    // Show loading state
    showLoading(true);
    clearAlert();
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok && data.token) {
            // Store token
            localStorage.setItem('cybernox_token', data.token);
            
            if (rememberMe) {
                localStorage.setItem('cybernox_remember', 'true');
            }
            
            // Show success message
            showAlert('success', '<i class="fas fa-check-circle"></i> Login successful! Redirecting to dashboard...');
            
            // Log login activity
            logActivity('admin_login', { username, timestamp: new Date().toISOString() });
            
            // Redirect after delay
            setTimeout(() => {
                redirectToDashboard();
            }, 1500);
            
        } else {
            showAlert('danger', '<i class="fas fa-exclamation-triangle"></i> ' + (data.error || 'Login failed'));
            logActivity('failed_login', { username, timestamp: new Date().toISOString() });
        }
        
    } catch (error) {
        console.error('Login error:', error);
        showAlert('danger', '<i class="fas fa-exclamation-triangle"></i> Connection error. Make sure the API server is running on port 5000.');
    } finally {
        showLoading(false);
    }
});

function showLoading(show) {
    const spinner = document.getElementById('loadingSpinner');
    const text = document.getElementById('loginText');
    const button = document.querySelector('.btn-login');
    
    if (show) {
        spinner.style.display = 'inline-block';
        text.innerHTML = 'Authenticating...';
        button.disabled = true;
    } else {
        spinner.style.display = 'none';
        text.innerHTML = '<i class="fas fa-sign-in-alt"></i> Access Dashboard';
        button.disabled = false;
    }
}

function showAlert(type, message) {
    const alertDiv = document.getElementById('loginAlert');
    alertDiv.innerHTML = `
        <div class="alert alert-${type} alert-custom" role="alert">
            ${message}
        </div>
    `;
    
    // Auto-hide success alerts
    if (type === 'success') {
        setTimeout(() => {
            alertDiv.innerHTML = '';
        }, 3000);
    }
}

function clearAlert() {
    document.getElementById('loginAlert').innerHTML = '';
}

function redirectToDashboard() {
    // Get the stored token
    const token = localStorage.getItem('cybernox_token');
    
    if (!token) {
        showAlert('danger', '<i class="fas fa-exclamation-triangle"></i> No authentication token found. Please login again.');
        return;
    }
    
    // Use fetch to access the dashboard with the token
    fetch('/api/v1/dashboard', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'text/html'
        }
    })
    .then(response => {
        if (response.ok) {
            return response.text();
        } else if (response.status === 401) {
            // Token expired or invalid
            localStorage.removeItem('cybernox_token');
            showAlert('danger', '<i class="fas fa-exclamation-triangle"></i> Session expired. Please login again.');
            throw new Error('Authentication failed');
        } else {
            throw new Error('Dashboard access failed');
        }
    })
    .then(html => {
        // Replace current page with dashboard HTML
        document.open();
        document.write(html);
        document.close();
        
        // Update URL without page reload
        window.history.pushState({}, 'CyberNox Dashboard', '/api/v1/dashboard');
    })
    .catch(error => {
        console.error('Dashboard redirect error:', error);
        showAlert('danger', '<i class="fas fa-exclamation-triangle"></i> Failed to access dashboard. Please try again.');
    });
}

function logActivity(action, data) {
    // Store activity log in localStorage for demo
    const activities = JSON.parse(localStorage.getItem('cybernox_activities') || '[]');
    activities.push({
        action,
        data,
        timestamp: new Date().toISOString(),
        ip: 'localhost' // In real app, get actual IP
    });
    
    // Keep only last 100 activities
    if (activities.length > 100) {
        activities.splice(0, activities.length - 100);
    }
    
    localStorage.setItem('cybernox_activities', JSON.stringify(activities));
}

// Password visibility toggle
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('fa-eye') || e.target.classList.contains('fa-eye-slash')) {
        const passwordField = document.getElementById('password');
        const icon = e.target;
        
        if (passwordField.type === 'password') {
            passwordField.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            passwordField.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }
});

// Add password visibility toggle icon
document.querySelector('.input-group:last-of-type').innerHTML += `
    <i class="fas fa-eye position-absolute" style="right: 20px; top: 50%; transform: translateY(-50%); cursor: pointer; z-index: 3;"></i>
`;

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Alt + D for demo credentials
    if (e.altKey && e.key === 'd') {
        e.preventDefault();
        document.getElementById('username').value = 'admin';
        document.getElementById('password').value = 'cybernox123';
        showAlert('info', '<i class="fas fa-info-circle"></i> Demo credentials loaded');
    }
});

// Check API server status on load
fetch(`${API_BASE}/status`)
    .then(response => {
        if (response.ok) {
            console.log('✅ API server is running');
        } else {
            showAlert('warning', '<i class="fas fa-exclamation-triangle"></i> API server may not be running. Please start it with: python api_server.py');
        }
    })
    .catch(error => {
        showAlert('warning', '<i class="fas fa-exclamation-triangle"></i> Cannot connect to API server. Please start it with: python api_server.py');
    });

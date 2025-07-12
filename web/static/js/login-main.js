/**
 * Login Page Application
 * Handles login functionality with modular architecture
 */

// Initialize login page when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('Login page loaded');
    
    // Check if user is already authenticated
    checkExistingAuth();
    
    // Setup login form
    setupLoginForm();
});

/**
 * Check if user is already authenticated
 */
async function checkExistingAuth() {
    const token = localStorage.getItem('cybernox_token');
    if (token) {
        console.log('Existing token found, validating...');
        
        try {
            const response = await fetch('http://127.0.0.1:5000/api/v1/status', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (response.ok) {
                console.log('Valid token found, redirecting to dashboard...');
                redirectToDashboard();
                return;
            } else {
                console.log('Invalid token, clearing...');
                localStorage.removeItem('cybernox_token');
                localStorage.removeItem('cybernox_remember');
            }
        } catch (error) {
            console.log('Token validation failed:', error);
            localStorage.removeItem('cybernox_token');
            localStorage.removeItem('cybernox_remember');
        }
    }
    
    console.log('No valid token, staying on login page');
}

/**
 * Setup login form event listeners
 */
function setupLoginForm() {
    const loginForm = document.getElementById('loginForm');
    const loginBtn = document.getElementById('loginBtn');
    const errorAlert = document.getElementById('errorAlert');
    
    if (!loginForm) {
        console.error('Login form not found');
        return;
    }
    
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const rememberMe = document.getElementById('rememberMe').checked;
        
        if (!username || !password) {
            showError('Please enter both username and password');
            return;
        }
        
        // Show loading state
        showLoading(true);
        hideError();
        
        try {
            const response = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    password: password,
                    remember_me: rememberMe
                })
            });
            
            const data = await response.json();
            
            if (response.ok && data.token) {
                console.log('Login successful');
                
                // Store token
                localStorage.setItem('cybernox_token', data.token);
                if (rememberMe) {
                    localStorage.setItem('cybernox_remember', 'true');
                }
                
                // Show success message briefly
                showSuccess('Login successful! Redirecting...');
                
                // Redirect to dashboard
                setTimeout(() => {
                    redirectToDashboard();
                }, 1000);
                
            } else {
                console.log('Login failed:', data.error);
                showError(data.error || 'Login failed. Please try again.');
            }
            
        } catch (error) {
            console.error('Login request failed:', error);
            showError('Network error. Please check your connection and try again.');
        } finally {
            showLoading(false);
        }
    });
}

/**
 * Show error message
 */
function showError(message) {
    const errorAlert = document.getElementById('errorAlert');
    if (errorAlert) {
        errorAlert.textContent = message;
        errorAlert.style.display = 'block';
    }
}

/**
 * Hide error message
 */
function hideError() {
    const errorAlert = document.getElementById('errorAlert');
    if (errorAlert) {
        errorAlert.style.display = 'none';
    }
}

/**
 * Show success message
 */
function showSuccess(message) {
    const errorAlert = document.getElementById('errorAlert');
    if (errorAlert) {
        errorAlert.textContent = message;
        errorAlert.className = 'alert alert-success';
        errorAlert.style.display = 'block';
    }
}

/**
 * Show/hide loading state
 */
function showLoading(isLoading) {
    const loginBtn = document.getElementById('loginBtn');
    const loginBtnText = document.getElementById('loginBtnText');
    const loginSpinner = document.getElementById('loginSpinner');
    
    if (loginBtn) {
        loginBtn.disabled = isLoading;
    }
    
    if (loginBtnText) {
        loginBtnText.textContent = isLoading ? 'Signing in...' : 'Sign In';
    }
    
    if (loginSpinner) {
        loginSpinner.style.display = isLoading ? 'inline-block' : 'none';
    }
}

/**
 * Redirect to dashboard
 */
function redirectToDashboard() {
    window.location.href = '/api/v1/auth/dashboard';
}

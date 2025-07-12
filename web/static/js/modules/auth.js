/**
 * Authentication Module
 * Handles login, logout, and token management
 */

class AuthManager {
    constructor() {
        this.API_BASE = 'http://127.0.0.1:5000/api/v1';
        this.TOKEN_KEY = 'cybernox_token';
        this.REMEMBER_KEY = 'cybernox_remember';
    }

    /**
     * Check if user is authenticated
     * @returns {boolean} Authentication status
     */
    async checkAuth() {
        const token = this.getToken();
        if (!token) {
            console.log('No token found, redirecting to login...');
            this.redirectToLogin();
            return false;
        }

        try {
            const response = await fetch(`${this.API_BASE}/status`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (!response.ok) {
                console.log('Token invalid, clearing and redirecting to login...');
                this.clearAuth();
                this.redirectToLogin();
                return false;
            }

            console.log('Authentication verified successfully');
            return true;
        } catch (error) {
            console.error('Auth check failed:', error);
            return false;
        }
    }

    /**
     * Login user with credentials
     * @param {string} username 
     * @param {string} password 
     * @param {boolean} rememberMe 
     * @returns {Promise<Object>} Login response
     */
    async login(username, password, rememberMe = false) {
        try {
            const response = await fetch(`${this.API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    password: password,
                    remember_me: rememberMe
                })
            });

            const data = await response.json();

            if (response.ok && data.token) {
                this.setToken(data.token);
                if (rememberMe) {
                    localStorage.setItem(this.REMEMBER_KEY, 'true');
                }
                console.log('Login successful');
                return { success: true, data };
            } else {
                console.log('Login failed:', data.error);
                return { success: false, error: data.error };
            }
        } catch (error) {
            console.error('Login request failed:', error);
            return { success: false, error: 'Network error' };
        }
    }

    /**
     * Logout user
     */
    async logout() {
        try {
            const token = this.getToken();
            if (token) {
                await fetch(`${this.API_BASE}/auth/logout`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
            }
        } catch (error) {
            console.error('Logout request failed:', error);
        } finally {
            this.clearAuth();
            this.redirectToLogin();
        }
    }

    /**
     * Get stored token
     * @returns {string|null} JWT token
     */
    getToken() {
        return localStorage.getItem(this.TOKEN_KEY);
    }

    /**
     * Set token in storage
     * @param {string} token JWT token
     */
    setToken(token) {
        localStorage.setItem(this.TOKEN_KEY, token);
    }

    /**
     * Clear all authentication data
     */
    clearAuth() {
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.removeItem(this.REMEMBER_KEY);
        localStorage.removeItem('cybernox_activities');
    }

    /**
     * Redirect to login page
     */
    redirectToLogin() {
        window.location.href = '/api/v1/auth/login';
    }

    /**
     * Redirect to dashboard
     */
    redirectToDashboard() {
        window.location.href = '/api/v1/auth/dashboard';
    }

    /**
     * Make authenticated API request
     * @param {string} url API endpoint
     * @param {Object} options Fetch options
     * @returns {Promise<Response>} Fetch response
     */
    async makeAuthenticatedRequest(url, options = {}) {
        const token = this.getToken();
        if (!token) {
            this.redirectToLogin();
            throw new Error('No authentication token');
        }

        const headers = {
            'Authorization': `Bearer ${token}`,
            ...options.headers
        };

        try {
            const response = await fetch(url, { ...options, headers });
            
            if (response.status === 401) {
                console.log('Token expired or invalid, redirecting to login...');
                this.clearAuth();
                this.redirectToLogin();
                throw new Error('Authentication failed');
            }

            return response;
        } catch (error) {
            if (error.message.includes('Authentication failed')) {
                throw error;
            }
            console.error('API request failed:', error);
            throw error;
        }
    }
}

// Export as global instance
window.authManager = new AuthManager();

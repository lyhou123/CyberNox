// CyberNox Admin Dashboard JavaScript
const API_BASE = 'http://127.0.0.1:5000/api/v1';
let vulnChart;

// Debug: Add window level logout function for testing
window.logout = logout;

// Check authentication on load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard loaded, checking authentication...');
    
    // Immediate auth check
    if (!checkAuth()) {
        return; // Stop loading if no token
    }
    
    initializeDashboard();
    loadDashboardData();
    
    // Update stats every 30 seconds
    setInterval(updateStats, 30000);
    
    // Check authentication every 5 minutes
    setInterval(function() {
        console.log('Periodic auth check...');
        checkAuth();
    }, 300000); // 5 minutes
});

function checkAuth() {
    const token = localStorage.getItem('cybernox_token');
    if (!token) {
        console.log('No token found, redirecting to login...');
        window.location.href = '/api/v1/auth/login';
        return false;
    }
    
    // Verify token with API
    fetch(`${API_BASE}/status`, {
        headers: { 'Authorization': `Bearer ${token}` }
    }).then(response => {
        if (!response.ok) {
            console.log('Token invalid, clearing and redirecting to login...');
            localStorage.removeItem('cybernox_token');
            localStorage.removeItem('cybernox_remember');
            window.location.href = '/api/v1/auth/login';
        } else {
            console.log('Authentication verified successfully');
        }
    }).catch(error => {
        console.error('Auth check failed:', error);
        console.log('Auth check failed, redirecting to login...');
        localStorage.removeItem('cybernox_token');
        localStorage.removeItem('cybernox_remember');
        window.location.href = '/api/v1/auth/login';
    });
    
    return true;
}

function initializeDashboard() {
    updateLastUpdate();
    initializeCharts();
    loadRecentActivity();
}

function initializeCharts() {
    const ctx = document.getElementById('vulnChart').getContext('2d');
    vulnChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [5, 12, 23, 8],
                backgroundColor: ['#ff4444', '#ff8800', '#ffbb33', '#00c851']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

async function loadDashboardData() {
    try {
        const response = await makeAuthenticatedRequest(`${API_BASE}/dashboard/data`);
        
        if (response.ok) {
            const data = await response.json();
            updateDashboardMetrics(data.data);
        } else {
            console.error('Failed to load dashboard data:', response.status);
        }
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
        // Don't redirect here as makeAuthenticatedRequest already handles auth errors
    }
}

function updateDashboardMetrics(data) {
    document.getElementById('totalScans').textContent = data.totals?.scans || 0;
    document.getElementById('totalVulns').textContent = data.totals?.vulnerabilities || 0;
    document.getElementById('totalTargets').textContent = data.totals?.targets || 0;
    
    // Update chart with real data
    if (data.vulnerability_distribution && vulnChart) {
        const labels = data.vulnerability_distribution.map(item => item.severity);
        const counts = data.vulnerability_distribution.map(item => item.count);
        
        vulnChart.data.labels = labels;
        vulnChart.data.datasets[0].data = counts;
        vulnChart.update();
    }
}

function loadRecentActivity() {
    const activities = JSON.parse(localStorage.getItem('cybernox_activities') || '[]');
    const activityDiv = document.getElementById('recentActivity');
    
    if (activities.length === 0) {
        activityDiv.innerHTML = '<p class="text-muted">No recent activity</p>';
        return;
    }
    
    const recentActivities = activities.slice(-10).reverse();
    let html = '';
    
    recentActivities.forEach(activity => {
        const iconClass = activity.action.includes('failed') ? 'danger' : 'success';
        const icon = activity.action.includes('login') ? 'fa-sign-in-alt' : 'fa-search';
        
        html += `
            <div class="activity-item">
                <div class="activity-icon ${iconClass}">
                    <i class="fas ${icon}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${formatActivityTitle(activity.action)}</div>
                    <div class="activity-desc">${formatActivityDesc(activity)}</div>
                </div>
                <div class="activity-time">${formatTime(activity.timestamp)}</div>
            </div>
        `;
    });
    
    activityDiv.innerHTML = html;
}

function formatActivityTitle(action) {
    const titles = {
        'admin_login': 'Admin Login',
        'failed_login': 'Failed Login Attempt',
        'scan_started': 'Scan Started',
        'scan_completed': 'Scan Completed'
    };
    return titles[action] || action.replace('_', ' ').toUpperCase();
}

function formatActivityDesc(activity) {
    if (activity.action.includes('login')) {
        return `User: ${activity.data.username}`;
    }
    return activity.data ? JSON.stringify(activity.data).substring(0, 50) + '...' : 'No details';
}

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleTimeString();
}

function updateLastUpdate() {
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
}

function updateStats() {
    updateLastUpdate();
    loadDashboardData();
}

// Navigation functions
function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.add('d-none');
    });
    
    // Show selected section
    document.getElementById(sectionName + '-section').classList.remove('d-none');
    
    // Update breadcrumb
    document.getElementById('currentSection').textContent = 
        sectionName.charAt(0).toUpperCase() + sectionName.slice(1);
    
    // Update active nav
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    event.target.classList.add('active');
}

function toggleSidebar() {
    const sidebar = document.getElementById('adminSidebar');
    const content = document.getElementById('adminContent');
    
    sidebar.classList.toggle('collapsed');
    content.classList.toggle('expanded');
}

// Quick action functions
function startQuickScan() {
    // Show modal for quick scan configuration
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-play"></i> Start Quick Scan</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="quickScanForm">
                        <div class="mb-3">
                            <label class="form-label">Target URL/IP:</label>
                            <input type="text" class="form-control" id="scanTarget" placeholder="e.g., 192.168.1.1 or example.com" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Scan Type:</label>
                            <select class="form-select" id="scanType">
                                <option value="port">Port Scan</option>
                                <option value="vuln">Vulnerability Scan</option>
                                <option value="recon">Reconnaissance</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="executeScan()">Start Scan</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal);
    bootstrapModal.show();
    
    // Remove modal when hidden
    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

function executeScan() {
    const target = document.getElementById('scanTarget').value;
    const scanType = document.getElementById('scanType').value;
    
    if (!target) {
        alert('Please enter a target URL or IP address');
        return;
    }
    
    // Close modal
    const modal = document.querySelector('.modal.show');
    if (modal) {
        bootstrap.Modal.getInstance(modal).hide();
    }
    
    // Show progress notification
    showNotification('Scan Started', `${scanType} scan initiated for ${target}`, 'success');
    
    // Simulate scan execution
    makeAuthenticatedRequest('/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scan_type: scanType })
    }).then(response => response.json())
    .then(data => {
        showNotification('Scan Update', data.message || 'Scan completed successfully', 'success');
        updateStats(); // Refresh dashboard stats
    }).catch(error => {
        showNotification('Scan Error', 'Failed to start scan. This is a demo feature.', 'warning');
    });
}

function generateReport() {
    // Show report generation options
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-file-pdf"></i> Generate Report</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="reportForm">
                        <div class="mb-3">
                            <label class="form-label">Report Type:</label>
                            <select class="form-select" id="reportType">
                                <option value="summary">Security Summary</option>
                                <option value="detailed">Detailed Vulnerability Report</option>
                                <option value="compliance">Compliance Report</option>
                                <option value="executive">Executive Summary</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Time Range:</label>
                            <select class="form-select" id="timeRange">
                                <option value="24h">Last 24 Hours</option>
                                <option value="7d">Last 7 Days</option>
                                <option value="30d">Last 30 Days</option>
                                <option value="custom">Custom Range</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Format:</label>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="format" id="formatPDF" value="pdf" checked>
                                <label class="form-check-label" for="formatPDF">PDF</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="format" id="formatHTML" value="html">
                                <label class="form-check-label" for="formatHTML">HTML</label>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="executeReportGeneration()">Generate Report</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal);
    bootstrapModal.show();
    
    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

function executeReportGeneration() {
    const reportType = document.getElementById('reportType').value;
    const timeRange = document.getElementById('timeRange').value;
    const format = document.querySelector('input[name="format"]:checked').value;
    
    // Close modal
    const modal = document.querySelector('.modal.show');
    if (modal) {
        bootstrap.Modal.getInstance(modal).hide();
    }
    
    showNotification('Report Generation', 'Generating report... This may take a few moments.', 'info');
    
    // Simulate report generation
    setTimeout(() => {
        const fileName = `cybernox_${reportType}_report_${new Date().toISOString().split('T')[0]}.${format}`;
        showNotification('Report Ready', `Report "${fileName}" has been generated successfully!`, 'success');
        
        // In a real implementation, you would download the file here
        console.log(`Generated report: ${fileName}`);
    }, 2000);
}

function viewLogs() {
    showSection('logs');
    
    // Load recent logs into the logs section
    const logsContainer = document.getElementById('activityLogs');
    if (logsContainer) {
        logsContainer.innerHTML = `
            <div class="log-viewer">
                <div class="log-controls mb-3">
                    <div class="row">
                        <div class="col-md-6">
                            <select class="form-select" id="logLevel">
                                <option value="all">All Levels</option>
                                <option value="error">Errors Only</option>
                                <option value="warning">Warnings Only</option>
                                <option value="info">Info Only</option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <button class="btn btn-outline-primary" onclick="refreshLogs()">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                            <button class="btn btn-outline-secondary" onclick="clearLogsView()">
                                <i class="fas fa-trash"></i> Clear View
                            </button>
                        </div>
                    </div>
                </div>
                <div class="log-content">
                    <div class="log-entry log-info">
                        <span class="log-time">${new Date().toLocaleString()}</span>
                        <span class="log-level">INFO</span>
                        <span class="log-message">Dashboard accessed by Administrator</span>
                    </div>
                    <div class="log-entry log-success">
                        <span class="log-time">${new Date(Date.now() - 300000).toLocaleString()}</span>
                        <span class="log-level">SUCCESS</span>
                        <span class="log-message">User authentication successful</span>
                    </div>
                    <div class="log-entry log-warning">
                        <span class="log-time">${new Date(Date.now() - 600000).toLocaleString()}</span>
                        <span class="log-level">WARNING</span>
                        <span class="log-message">Multiple failed login attempts detected</span>
                    </div>
                </div>
            </div>
        `;
    }
}

function refreshLogs() {
    showNotification('Logs', 'Refreshing activity logs...', 'info');
    // In a real implementation, this would fetch fresh logs from the API
    setTimeout(() => {
        showNotification('Logs', 'Activity logs refreshed successfully', 'success');
    }, 1000);
}

function clearLogsView() {
    const logContent = document.querySelector('.log-content');
    if (logContent) {
        logContent.innerHTML = '<div class="text-center text-muted py-4">Log view cleared</div>';
    }
}

function exportData() {
    // Show export options
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-download"></i> Export Data</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="exportForm">
                        <div class="mb-3">
                            <label class="form-label">Data Type:</label>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="exportVulns" checked>
                                <label class="form-check-label" for="exportVulns">Vulnerability Data</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="exportScans" checked>
                                <label class="form-check-label" for="exportScans">Scan Results</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="exportTargets">
                                <label class="form-check-label" for="exportTargets">Target Information</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="exportLogs">
                                <label class="form-check-label" for="exportLogs">Activity Logs</label>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Export Format:</label>
                            <select class="form-select" id="exportFormat">
                                <option value="json">JSON</option>
                                <option value="csv">CSV</option>
                                <option value="xml">XML</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="executeDataExport()">Export Data</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal);
    bootstrapModal.show();
    
    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

function executeDataExport() {
    const exportTypes = [];
    if (document.getElementById('exportVulns').checked) exportTypes.push('vulnerabilities');
    if (document.getElementById('exportScans').checked) exportTypes.push('scans');
    if (document.getElementById('exportTargets').checked) exportTypes.push('targets');
    if (document.getElementById('exportLogs').checked) exportTypes.push('logs');
    
    const format = document.getElementById('exportFormat').value;
    
    if (exportTypes.length === 0) {
        alert('Please select at least one data type to export');
        return;
    }
    
    // Close modal
    const modal = document.querySelector('.modal.show');
    if (modal) {
        bootstrap.Modal.getInstance(modal).hide();
    }
    
    showNotification('Export Started', `Exporting ${exportTypes.join(', ')} data in ${format.toUpperCase()} format...`, 'info');
    
    // Simulate export process
    setTimeout(() => {
        const fileName = `cybernox_export_${new Date().toISOString().split('T')[0]}.${format}`;
        showNotification('Export Complete', `Data exported successfully as "${fileName}"`, 'success');
        
        // In a real implementation, you would trigger the download here
        console.log(`Exported: ${exportTypes.join(', ')} as ${fileName}`);
    }, 1500);
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        // Clear all stored data
        localStorage.removeItem('cybernox_token');
        localStorage.removeItem('cybernox_remember');
        localStorage.removeItem('cybernox_activities');
        
        // Log logout activity before redirect
        logActivity('admin_logout', { 
            timestamp: new Date().toISOString(),
            user: 'admin'
        });
        
        // Show logout message
        console.log('Logging out...');
        
        // Redirect to login page
        window.location.href = '/api/v1/auth/login';
    }
}

// Add logout activity logging function
function logActivity(action, data) {
    try {
        const activities = JSON.parse(localStorage.getItem('cybernox_activities') || '[]');
        activities.push({
            action,
            data,
            timestamp: new Date().toISOString(),
            ip: 'localhost'
        });
        
        // Keep only last 100 activities
        if (activities.length > 100) {
            activities.splice(0, activities.length - 100);
        }
        
        localStorage.setItem('cybernox_activities', JSON.stringify(activities));
    } catch (error) {
        console.error('Failed to log activity:', error);
    }
}

// Universal function to check token before API calls
function makeAuthenticatedRequest(url, options = {}) {
    const token = localStorage.getItem('cybernox_token');
    
    if (!token) {
        console.log('No token available for API request, redirecting to login...');
        window.location.href = '/api/v1/auth/login';
        return Promise.reject(new Error('No authentication token'));
    }
    
    // Add Authorization header
    const headers = {
        'Authorization': `Bearer ${token}`,
        ...options.headers
    };
    
    const requestOptions = {
        ...options,
        headers
    };
    
    return fetch(url, requestOptions)
        .then(response => {
            if (response.status === 401) {
                console.log('Token expired or invalid, redirecting to login...');
                localStorage.removeItem('cybernox_token');
                localStorage.removeItem('cybernox_remember');
                window.location.href = '/api/v1/auth/login';
                throw new Error('Authentication failed');
            }
            return response;
        })
        .catch(error => {
            if (error.message.includes('Authentication failed')) {
                throw error;
            }
            console.error('API request failed:', error);
            throw error;
        });
}

// Notification system
function showNotification(title, message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.cybernox-notification');
    existingNotifications.forEach(notif => notif.remove());
    
    const notification = document.createElement('div');
    notification.className = `cybernox-notification alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        max-width: 400px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    
    notification.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="fas fa-${getNotificationIcon(type)} me-2"></i>
            <div>
                <strong>${title}</strong><br>
                <small>${message}</small>
            </div>
        </div>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 150);
        }
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'check-circle',
        'info': 'info-circle',
        'warning': 'exclamation-triangle',
        'error': 'times-circle',
        'danger': 'times-circle'
    };
    return icons[type] || 'info-circle';
}

// Add CSS for log viewer
function addLogViewerStyles() {
    if (!document.getElementById('logViewerStyles')) {
        const style = document.createElement('style');
        style.id = 'logViewerStyles';
        style.textContent = `
            .log-viewer {
                background: #f8f9fa;
                border-radius: 8px;
                padding: 1rem;
            }
            .log-content {
                background: #000;
                color: #00ff00;
                font-family: 'Courier New', monospace;
                font-size: 0.9rem;
                padding: 1rem;
                border-radius: 4px;
                max-height: 400px;
                overflow-y: auto;
            }
            .log-entry {
                margin-bottom: 0.5rem;
                padding: 0.25rem 0;
                border-bottom: 1px solid #333;
            }
            .log-time {
                color: #888;
                margin-right: 1rem;
            }
            .log-level {
                display: inline-block;
                width: 80px;
                font-weight: bold;
                margin-right: 1rem;
            }
            .log-info .log-level { color: #00ff00; }
            .log-success .log-level { color: #00ffff; }
            .log-warning .log-level { color: #ffff00; }
            .log-error .log-level { color: #ff0000; }
            .log-message {
                color: #fff;
            }
        `;
        document.head.appendChild(style);
    }
}

// Initialize log viewer styles when needed
document.addEventListener('DOMContentLoaded', function() {
    addLogViewerStyles();
    // ...existing DOMContentLoaded code...
});

// Mobile sidebar toggle
if (window.innerWidth <= 768) {
    document.querySelector('.sidebar-toggle').addEventListener('click', function() {
        document.getElementById('adminSidebar').classList.toggle('show');
    });
}

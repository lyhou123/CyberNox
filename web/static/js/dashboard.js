// CyberNox Admin Dashboard JavaScript
const API_BASE = 'http://127.0.0.1:5000/api/v1';
let vulnChart;

// Check authentication on load
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    initializeDashboard();
    loadDashboardData();
    setInterval(updateStats, 30000); // Update every 30 seconds
});

function checkAuth() {
    const token = localStorage.getItem('cybernox_token');
    if (!token) {
        window.location.href = '/api/v1/auth/login';
        return;
    }
    
    // Verify token with API
    fetch(`${API_BASE}/status`, {
        headers: { 'Authorization': `Bearer ${token}` }
    }).then(response => {
        if (!response.ok) {
            localStorage.removeItem('cybernox_token');
            window.location.href = '/api/v1/auth/login';
        }
    }).catch(error => {
        console.error('Auth check failed:', error);
    });
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
        const token = localStorage.getItem('cybernox_token');
        const response = await fetch(`${API_BASE}/dashboard/data`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            updateDashboardMetrics(data.data);
        }
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
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
    alert('Quick scan functionality would be implemented here');
}

function generateReport() {
    alert('Report generation functionality would be implemented here');
}

function viewLogs() {
    showSection('logs');
}

function exportData() {
    alert('Data export functionality would be implemented here');
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        localStorage.removeItem('cybernox_token');
        localStorage.removeItem('cybernox_remember');
        window.location.href = '/api/v1/auth/login';
    }
}

// Mobile sidebar toggle
if (window.innerWidth <= 768) {
    document.querySelector('.sidebar-toggle').addEventListener('click', function() {
        document.getElementById('adminSidebar').classList.toggle('show');
    });
}

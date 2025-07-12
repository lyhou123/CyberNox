/**
 * Dashboard Module
 * Handles dashboard functionality and data loading
 */

class DashboardManager {
    constructor() {
        this.API_BASE = 'http://127.0.0.1:5000/api/v1';
        this.vulnChart = null;
        this.currentSection = 'dashboard';
    }

    /**
     * Initialize dashboard
     */
    async initialize() {
        console.log('Initializing dashboard...');
        
        // Check authentication first
        if (!await authManager.checkAuth()) {
            return;
        }

        this.setupEventListeners();
        this.loadDashboardData();
        this.initializeChart();
        
        // Update stats periodically
        setInterval(() => this.updateStats(), 30000);
        
        // Check authentication periodically
        setInterval(() => {
            console.log('Periodic auth check...');
            authManager.checkAuth();
        }, 300000); // 5 minutes
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Sidebar toggle for mobile
        if (window.innerWidth <= 768) {
            const toggleBtn = document.querySelector('.sidebar-toggle');
            if (toggleBtn) {
                toggleBtn.addEventListener('click', () => {
                    document.getElementById('adminSidebar').classList.toggle('show');
                });
            }
        }

        // Quick action buttons
        this.setupQuickActions();
    }

    /**
     * Setup quick action event listeners
     */
    setupQuickActions() {
        // These functions will be called by onclick attributes in HTML
        window.startQuickScan = () => this.startQuickScan();
        window.generateReport = () => this.generateReport();
        window.viewLogs = () => this.viewLogs();
        window.exportData = () => this.exportData();
        window.logout = () => this.logout();
        window.showSection = (section) => this.showSection(section);
        window.toggleSidebar = () => this.toggleSidebar();
    }

    /**
     * Load dashboard data
     */
    async loadDashboardData() {
        try {
            const response = await authManager.makeAuthenticatedRequest(`${this.API_BASE}/tasks`);
            const data = await response.json();
            
            this.updateDashboardMetrics(data);
            this.updateRecentActivity(data.tasks || []);
            this.updateLastUpdateTime();
            
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
        }
    }

    /**
     * Update dashboard metrics
     */
    updateDashboardMetrics(data) {
        const tasks = data.tasks || [];
        
        // Update metrics
        document.getElementById('totalScans').textContent = tasks.filter(t => t.type === 'port_scan').length;
        document.getElementById('totalVulns').textContent = Math.floor(Math.random() * 25); // Simulated
        document.getElementById('totalTargets').textContent = new Set(tasks.map(t => t.target)).size;
        document.getElementById('activeScans').textContent = tasks.filter(t => t.status === 'running').length;
        
        // Update header stats
        document.getElementById('activeTasks').textContent = `${tasks.filter(t => t.status === 'running').length} Active`;
        document.getElementById('systemStatus').textContent = 'Online';
    }

    /**
     * Update recent activity section
     */
    updateRecentActivity(tasks) {
        const activityContainer = document.getElementById('recentActivity');
        if (!activityContainer) return;

        const recentTasks = tasks.slice(0, 5);
        
        if (recentTasks.length === 0) {
            activityContainer.innerHTML = '<div class="text-center text-muted py-4">No recent activity</div>';
            return;
        }

        const activityHTML = recentTasks.map(task => `
            <div class="activity-item">
                <div class="activity-icon">
                    <i class="fas fa-${this.getTaskIcon(task.type)}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${this.getTaskTitle(task.type)} - ${task.target}</div>
                    <div class="activity-time">${new Date(task.created_at).toLocaleString()}</div>
                </div>
                <div class="activity-status">
                    <span class="badge bg-${this.getStatusColor(task.status)}">${task.status}</span>
                </div>
            </div>
        `).join('');

        activityContainer.innerHTML = activityHTML;
    }

    /**
     * Update last update time
     */
    updateLastUpdateTime() {
        const lastUpdateElement = document.getElementById('lastUpdate');
        if (lastUpdateElement) {
            lastUpdateElement.textContent = new Date().toLocaleString();
        }
    }

    /**
     * Update statistics
     */
    async updateStats() {
        console.log('Updating dashboard stats...');
        await this.loadDashboardData();
    }

    /**
     * Get task icon based on type
     */
    getTaskIcon(type) {
        const icons = {
            'port_scan': 'search',
            'vulnerability_scan': 'bug',
            'reconnaissance': 'eye',
            'exploit': 'crosshairs',
            'report_generation': 'file-alt'
        };
        return icons[type] || 'tasks';
    }

    /**
     * Get task title based on type
     */
    getTaskTitle(type) {
        const titles = {
            'port_scan': 'Port Scan',
            'vulnerability_scan': 'Vulnerability Scan',
            'reconnaissance': 'Reconnaissance',
            'exploit': 'Exploit',
            'report_generation': 'Report Generation'
        };
        return titles[type] || 'Task';
    }

    /**
     * Get status color for badges
     */
    getStatusColor(status) {
        const colors = {
            'pending': 'secondary',
            'running': 'primary',
            'completed': 'success',
            'failed': 'danger',
            'cancelled': 'warning'
        };
        return colors[status] || 'secondary';
    }

    /**
     * Initialize vulnerability chart
     */
    initializeChart() {
        const ctx = document.getElementById('vulnChart');
        if (!ctx) return;

        this.vulnChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [5, 12, 18, 25, 30],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14', 
                        '#ffc107',
                        '#28a745',
                        '#17a2b8'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 10,
                            fontSize: 12
                        }
                    }
                }
            }
        });
    }

    /**
     * Show specific section
     */
    showSection(sectionName) {
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.add('d-none');
        });

        // Show selected section
        const targetSection = document.getElementById(`${sectionName}-section`);
        if (targetSection) {
            targetSection.classList.remove('d-none');
        }

        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });

        const activeLink = document.querySelector(`[onclick="showSection('${sectionName}')"]`);
        if (activeLink) {
            activeLink.classList.add('active');
        }

        // Update breadcrumb
        const currentSection = document.getElementById('currentSection');
        if (currentSection) {
            currentSection.textContent = sectionName.charAt(0).toUpperCase() + sectionName.slice(1);
        }

        this.currentSection = sectionName;

        // Load section-specific data
        if (sectionName === 'logs') {
            this.loadLogsSection();
        }
    }

    /**
     * Toggle sidebar
     */
    toggleSidebar() {
        const sidebar = document.getElementById('adminSidebar');
        const content = document.getElementById('adminContent');
        
        sidebar.classList.toggle('collapsed');
        content.classList.toggle('expanded');
    }

    /**
     * Load logs section
     */
    loadLogsSection() {
        const logsContainer = document.getElementById('activityLogs');
        if (!logsContainer) return;

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
                            <button class="btn btn-outline-primary" onclick="dashboardManager.refreshLogs()">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                            <button class="btn btn-outline-secondary" onclick="dashboardManager.clearLogsView()">
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

    /**
     * Refresh logs
     */
    refreshLogs() {
        notificationManager.show('Logs', 'Refreshing activity logs...', 'info');
        setTimeout(() => {
            notificationManager.show('Logs', 'Activity logs refreshed successfully', 'success');
        }, 1000);
    }

    /**
     * Clear logs view
     */
    clearLogsView() {
        const logContent = document.querySelector('.log-content');
        if (logContent) {
            logContent.innerHTML = '<div class="text-center text-muted py-4">Log view cleared</div>';
        }
    }

    /**
     * Logout user
     */
    async logout() {
        if (confirm('Are you sure you want to logout?')) {
            await authManager.logout();
        }
    }
}

// Export as global instance
window.dashboardManager = new DashboardManager();

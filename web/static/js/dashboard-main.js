/**
 * Main Dashboard Application
 * Loads and initializes all dashboard modules
 */

// Import all modules (these will be loaded via script tags)
// Modules: auth.js, dashboard.js, quickActions.js, notifications.js

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', async function() {
    console.log('CyberNox Dashboard starting...');
    
    // Add custom styles for log viewer and notifications
    addCustomStyles();
    
    // Initialize dashboard manager
    await dashboardManager.initialize();
    
    // Set up global quick action functions
    setupGlobalFunctions();
    
    console.log('CyberNox Dashboard initialized successfully');
});

/**
 * Add custom CSS styles
 */
function addCustomStyles() {
    if (!document.getElementById('cybernoxCustomStyles')) {
        const style = document.createElement('style');
        style.id = 'cybernoxCustomStyles';
        style.textContent = `
            /* Log Viewer Styles */
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
            
            /* Notification Styles */
            .cybernox-notification.show {
                transform: translateX(0) !important;
            }
            
            /* Activity Item Styles */
            .activity-item {
                display: flex;
                align-items: center;
                padding: 0.75rem;
                border-bottom: 1px solid #eee;
                transition: background-color 0.2s;
            }
            .activity-item:hover {
                background-color: #f8f9fa;
            }
            .activity-icon {
                width: 40px;
                height: 40px;
                border-radius: 50%;
                background: linear-gradient(45deg, #007bff, #6610f2);
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                margin-right: 1rem;
            }
            .activity-content {
                flex: 1;
            }
            .activity-title {
                font-weight: 500;
                color: #333;
            }
            .activity-time {
                font-size: 0.875rem;
                color: #666;
            }
            .activity-status {
                margin-left: 1rem;
            }
        `;
        document.head.appendChild(style);
    }
}

/**
 * Setup global functions for HTML onclick handlers
 */
function setupGlobalFunctions() {
    // Dashboard functions
    window.startQuickScan = () => quickActions.startQuickScan();
    window.generateReport = () => quickActions.generateReport();
    window.viewLogs = () => quickActions.viewLogs();
    window.exportData = () => quickActions.exportData();
    window.logout = () => dashboardManager.logout();
    window.showSection = (section) => dashboardManager.showSection(section);
    window.toggleSidebar = () => dashboardManager.toggleSidebar();
    
    // Quick action execution functions
    window.executeScan = () => quickActions.executeScan();
    window.executeReportGeneration = () => quickActions.executeReportGeneration();
    window.executeDataExport = () => quickActions.executeDataExport();
}

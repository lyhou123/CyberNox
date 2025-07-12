/**
 * Quick Actions Module
 * Handles all quick action functionality (scan, report, export, etc.)
 */

class QuickActionsManager {
    constructor() {
        this.API_BASE = 'http://127.0.0.1:5000/api/v1';
    }

    /**
     * Start quick scan
     */
    startQuickScan() {
        // Show modal for quick scan configuration
        const modal = this.createModal('quick-scan-modal', 'Start Quick Scan', this.getQuickScanModalContent());
        this.showModal(modal);
    }

    /**
     * Generate report
     */
    generateReport() {
        const modal = this.createModal('report-modal', 'Generate Report', this.getReportModalContent());
        this.showModal(modal);
    }

    /**
     * Export data
     */
    exportData() {
        const modal = this.createModal('export-modal', 'Export Data', this.getExportModalContent());
        this.showModal(modal);
    }

    /**
     * View logs
     */
    viewLogs() {
        dashboardManager.showSection('logs');
    }

    /**
     * Create modal element
     */
    createModal(id, title, content) {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = id;
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-play"></i> ${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        ${content}
                    </div>
                </div>
            </div>
        `;
        return modal;
    }

    /**
     * Show modal
     */
    showModal(modal) {
        document.body.appendChild(modal);
        const bootstrapModal = new bootstrap.Modal(modal);
        bootstrapModal.show();
        
        // Remove modal when hidden
        modal.addEventListener('hidden.bs.modal', () => modal.remove());
    }

    /**
     * Get quick scan modal content
     */
    getQuickScanModalContent() {
        return `
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
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="quickActions.executeScan()">Start Scan</button>
            </div>
        `;
    }

    /**
     * Get report modal content
     */
    getReportModalContent() {
        return `
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
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="quickActions.executeReportGeneration()">Generate Report</button>
            </div>
        `;
    }

    /**
     * Get export modal content
     */
    getExportModalContent() {
        return `
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
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="quickActions.executeDataExport()">Export Data</button>
            </div>
        `;
    }

    /**
     * Execute scan
     */
    async executeScan() {
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
        notificationManager.show('Scan Started', `${scanType} scan initiated for ${target}`, 'success');
        
        try {
            const response = await authManager.makeAuthenticatedRequest(`${this.API_BASE}/scan/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, scan_type: scanType })
            });
            
            const data = await response.json();
            notificationManager.show('Scan Update', data.message || 'Scan completed successfully', 'success');
            dashboardManager.updateStats(); // Refresh dashboard stats
        } catch (error) {
            notificationManager.show('Scan Error', 'Failed to start scan. This is a demo feature.', 'warning');
        }
    }

    /**
     * Execute report generation
     */
    async executeReportGeneration() {
        const reportType = document.getElementById('reportType').value;
        const timeRange = document.getElementById('timeRange').value;
        const format = document.querySelector('input[name="format"]:checked').value;
        
        // Close modal
        const modal = document.querySelector('.modal.show');
        if (modal) {
            bootstrap.Modal.getInstance(modal).hide();
        }
        
        notificationManager.show('Report Generation', 'Generating report... This may take a few moments.', 'info');
        
        // Simulate report generation
        setTimeout(() => {
            const fileName = `cybernox_${reportType}_report_${new Date().toISOString().split('T')[0]}.${format}`;
            notificationManager.show('Report Ready', `Report "${fileName}" has been generated successfully!`, 'success');
            
            // In a real implementation, you would download the file here
            console.log(`Generated report: ${fileName}`);
        }, 2000);
    }

    /**
     * Execute data export
     */
    async executeDataExport() {
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
        
        notificationManager.show('Export Started', `Exporting ${exportTypes.join(', ')} data in ${format.toUpperCase()} format...`, 'info');
        
        // Simulate export process
        setTimeout(() => {
            const fileName = `cybernox_export_${new Date().toISOString().split('T')[0]}.${format}`;
            notificationManager.show('Export Complete', `Data exported successfully as "${fileName}"`, 'success');
            
            // In a real implementation, you would trigger the download here
            console.log(`Exported: ${exportTypes.join(', ')} as ${fileName}`);
        }, 1500);
    }
}

// Export as global instance
window.quickActions = new QuickActionsManager();

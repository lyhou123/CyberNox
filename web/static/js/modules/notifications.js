/**
 * Notification Module
 * Handles all notification display and management
 */

class NotificationManager {
    constructor() {
        this.notifications = [];
        this.maxNotifications = 5;
    }

    /**
     * Show notification
     * @param {string} title Notification title
     * @param {string} message Notification message
     * @param {string} type Notification type (success, error, warning, info)
     * @param {number} duration Auto-hide duration in milliseconds (0 = no auto-hide)
     */
    show(title, message, type = 'info', duration = 5000) {
        // Remove existing notifications if at max
        if (this.notifications.length >= this.maxNotifications) {
            this.removeOldest();
        }

        const notification = this.createNotification(title, message, type, duration);
        document.body.appendChild(notification);
        
        // Add to tracking array
        this.notifications.push(notification);
        
        // Show with animation
        setTimeout(() => notification.classList.add('show'), 100);
        
        // Auto-hide if duration is set
        if (duration > 0) {
            setTimeout(() => this.hide(notification), duration);
        }
        
        return notification;
    }

    /**
     * Create notification element
     */
    createNotification(title, message, type, duration) {
        const notification = document.createElement('div');
        notification.className = `cybernox-notification alert alert-${this.getAlertClass(type)} alert-dismissible fade`;
        notification.style.cssText = `
            position: fixed;
            top: ${20 + (this.notifications.length * 80)}px;
            right: 20px;
            z-index: 9999;
            min-width: 300px;
            max-width: 400px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            transform: translateX(100%);
            transition: transform 0.3s ease-in-out;
        `;
        
        notification.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas fa-${this.getIcon(type)} me-2"></i>
                <div>
                    <strong>${title}</strong><br>
                    <small>${message}</small>
                </div>
            </div>
            <button type="button" class="btn-close" onclick="notificationManager.hide(this.parentElement)"></button>
        `;
        
        return notification;
    }

    /**
     * Hide notification
     */
    hide(notification) {
        if (!notification || !notification.parentNode) return;
        
        notification.style.transform = 'translateX(100%)';
        
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
            
            // Remove from tracking array
            const index = this.notifications.indexOf(notification);
            if (index > -1) {
                this.notifications.splice(index, 1);
            }
            
            // Reposition remaining notifications
            this.repositionNotifications();
        }, 300);
    }

    /**
     * Remove oldest notification
     */
    removeOldest() {
        if (this.notifications.length > 0) {
            this.hide(this.notifications[0]);
        }
    }

    /**
     * Clear all notifications
     */
    clearAll() {
        [...this.notifications].forEach(notification => this.hide(notification));
    }

    /**
     * Reposition notifications after one is removed
     */
    repositionNotifications() {
        this.notifications.forEach((notification, index) => {
            if (notification.parentNode) {
                notification.style.top = `${20 + (index * 80)}px`;
            }
        });
    }

    /**
     * Get Bootstrap alert class for type
     */
    getAlertClass(type) {
        const classes = {
            'success': 'success',
            'error': 'danger',
            'danger': 'danger',
            'warning': 'warning',
            'info': 'info',
            'primary': 'primary'
        };
        return classes[type] || 'info';
    }

    /**
     * Get icon for notification type
     */
    getIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'times-circle',
            'danger': 'times-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle',
            'primary': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }
}

// Export as global instance
window.notificationManager = new NotificationManager();

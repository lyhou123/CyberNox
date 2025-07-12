"""
Database support for CyberNox - SQLite and advanced data management
"""

import sqlite3
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from contextlib import contextmanager
from utils.logger import logger

class CyberNoxDatabase:
    """Professional database manager for CyberNox"""
    
    def __init__(self, db_path: str = "cybernox.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database with required tables"""
        with self.get_connection() as conn:
            # Scan results table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    results TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    duration REAL,
                    status TEXT DEFAULT 'completed'
                )
            """)
            
            # Vulnerabilities table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    target TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    cvss_score REAL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_results (scan_id)
                )
            """)
            
            # Targets table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE NOT NULL,
                    target_type TEXT NOT NULL,
                    description TEXT,
                    added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_scanned DATETIME,
                    scan_count INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0
                )
            """)
            
            # Ports table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    state TEXT NOT NULL,
                    service TEXT,
                    version TEXT,
                    banner TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_results (scan_id)
                )
            """)
            
            # Subdomains table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    domain TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    ip_address TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_results (scan_id)
                )
            """)
            
            # Reports table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE,
                    title TEXT NOT NULL,
                    description TEXT,
                    format TEXT NOT NULL,
                    file_path TEXT,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    scan_ids TEXT
                )
            """)
            
            # Configuration table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS configuration (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    description TEXT,
                    updated_date DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_type ON scan_results(scan_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target ON vulnerabilities(target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ports_target ON ports(target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain)")
            
            conn.commit()
            logger.info("Database initialized successfully")
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
        finally:
            conn.close()
    
    def generate_scan_id(self, scan_type: str, target: str) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().isoformat()
        data = f"{scan_type}_{target}_{timestamp}"
        return hashlib.md5(data.encode()).hexdigest()[:16]
    
    def save_scan_result(self, scan_type: str, target: str, results: Dict[str, Any], 
                        duration: float = None) -> str:
        """Save scan results to database"""
        scan_id = self.generate_scan_id(scan_type, target)
        
        with self.get_connection() as conn:
            # Save main scan result
            conn.execute("""
                INSERT OR REPLACE INTO scan_results 
                (scan_id, scan_type, target, results, duration)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, scan_type, target, json.dumps(results), duration))
            
            # Save detailed information based on scan type
            if scan_type == 'port_scan' and 'open_ports' in results:
                self._save_port_results(conn, scan_id, target, results['open_ports'])
            
            elif scan_type == 'vulnerability_scan' and 'vulnerabilities' in results:
                self._save_vulnerability_results(conn, scan_id, target, results['vulnerabilities'])
            
            elif scan_type == 'subdomain_enum' and 'subdomains' in results:
                self._save_subdomain_results(conn, scan_id, target, results['subdomains'])
            
            # Update target information
            self._update_target_info(conn, target, scan_type)
            
            conn.commit()
            logger.info(f"Scan results saved with ID: {scan_id}")
            
        return scan_id
    
    def _save_port_results(self, conn, scan_id: str, target: str, ports: List[Dict]):
        """Save port scan results"""
        for port_info in ports:
            conn.execute("""
                INSERT INTO ports (scan_id, target, port, protocol, state, service, banner)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, target, port_info.get('port'), 
                port_info.get('protocol', 'tcp'), port_info.get('state', 'open'),
                port_info.get('service'), port_info.get('banner')
            ))
    
    def _save_vulnerability_results(self, conn, scan_id: str, target: str, vulnerabilities: List[Dict]):
        """Save vulnerability scan results"""
        for vuln in vulnerabilities:
            conn.execute("""
                INSERT INTO vulnerabilities 
                (scan_id, target, vulnerability_type, severity, description, evidence, cvss_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, target, vuln.get('type'), vuln.get('severity'),
                vuln.get('description'), vuln.get('evidence'), vuln.get('cvss_score')
            ))
    
    def _save_subdomain_results(self, conn, scan_id: str, target: str, subdomains: List[Dict]):
        """Save subdomain enumeration results"""
        for subdomain in subdomains:
            conn.execute("""
                INSERT INTO subdomains (scan_id, domain, subdomain, ip_address)
                VALUES (?, ?, ?, ?)
            """, (scan_id, target, subdomain.get('subdomain'), subdomain.get('ip')))
    
    def _update_target_info(self, conn, target: str, scan_type: str):
        """Update target information"""
        conn.execute("""
            INSERT OR REPLACE INTO targets 
            (target, target_type, last_scanned, scan_count)
            VALUES (?, ?, CURRENT_TIMESTAMP, 
                    COALESCE((SELECT scan_count FROM targets WHERE target = ?), 0) + 1)
        """, (target, scan_type, target))
    
    def get_scan_history(self, target: str = None, scan_type: str = None, 
                        limit: int = 100) -> List[Dict]:
        """Get scan history with optional filters"""
        query = "SELECT * FROM scan_results WHERE 1=1"
        params = []
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        if scan_type:
            query += " AND scan_type = ?"
            params.append(scan_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_vulnerabilities(self, target: str = None, severity: str = None, 
                           limit: int = 100) -> List[Dict]:
        """Get vulnerabilities with optional filters"""
        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_target_statistics(self, target: str) -> Dict[str, Any]:
        """Get comprehensive statistics for a target"""
        with self.get_connection() as conn:
            # Basic target info
            target_info = conn.execute("""
                SELECT * FROM targets WHERE target = ?
            """, (target,)).fetchone()
            
            if not target_info:
                return {"error": "Target not found"}
            
            # Vulnerability statistics
            vuln_stats = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities 
                WHERE target = ?
                GROUP BY severity
            """, (target,)).fetchall()
            
            # Port statistics
            port_stats = conn.execute("""
                SELECT COUNT(*) as open_ports, COUNT(DISTINCT port) as unique_ports
                FROM ports 
                WHERE target = ? AND state = 'open'
            """, (target,)).fetchone()
            
            # Recent scans
            recent_scans = conn.execute("""
                SELECT scan_type, timestamp
                FROM scan_results 
                WHERE target = ?
                ORDER BY timestamp DESC
                LIMIT 10
            """, (target,)).fetchall()
            
            return {
                "target_info": dict(target_info),
                "vulnerability_stats": {row['severity']: row['count'] for row in vuln_stats},
                "port_stats": dict(port_stats),
                "recent_scans": [dict(row) for row in recent_scans]
            }
    
    def generate_dashboard_data(self) -> Dict[str, Any]:
        """Generate data for security dashboard"""
        with self.get_connection() as conn:
            # Total statistics
            total_targets = conn.execute("SELECT COUNT(*) as count FROM targets").fetchone()['count']
            total_scans = conn.execute("SELECT COUNT(*) as count FROM scan_results").fetchone()['count']
            total_vulnerabilities = conn.execute("SELECT COUNT(*) as count FROM vulnerabilities").fetchone()['count']
            
            # Recent activity
            recent_scans = conn.execute("""
                SELECT scan_type, target, timestamp, status
                FROM scan_results 
                ORDER BY timestamp DESC 
                LIMIT 10
            """).fetchall()
            
            # Vulnerability distribution
            vuln_distribution = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                GROUP BY severity
                ORDER BY 
                    CASE severity
                        WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3
                        WHEN 'Low' THEN 4
                        ELSE 5
                    END
            """).fetchall()
            
            # Top vulnerable targets
            top_vulnerable = conn.execute("""
                SELECT target, COUNT(*) as vuln_count
                FROM vulnerabilities
                GROUP BY target
                ORDER BY vuln_count DESC
                LIMIT 10
            """).fetchall()
            
            return {
                "totals": {
                    "targets": total_targets,
                    "scans": total_scans,
                    "vulnerabilities": total_vulnerabilities
                },
                "recent_activity": [dict(row) for row in recent_scans],
                "vulnerability_distribution": [dict(row) for row in vuln_distribution],
                "top_vulnerable_targets": [dict(row) for row in top_vulnerable]
            }
    
    def export_data(self, format_type: str = 'json', output_file: str = None) -> str:
        """Export database data to file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"cybernox_export_{timestamp}.{format_type}"
        
        dashboard_data = self.generate_dashboard_data()
        
        if format_type == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(dashboard_data, f, indent=2, default=str)
        
        logger.info(f"Data exported to {output_file}")
        return output_file
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old scan data"""
        with self.get_connection() as conn:
            # Delete old scan results
            deleted_scans = conn.execute("""
                DELETE FROM scan_results 
                WHERE timestamp < datetime('now', '-{} days')
            """.format(days)).rowcount
            
            # Delete orphaned vulnerabilities
            deleted_vulns = conn.execute("""
                DELETE FROM vulnerabilities 
                WHERE scan_id NOT IN (SELECT scan_id FROM scan_results)
            """).rowcount
            
            # Delete orphaned ports
            deleted_ports = conn.execute("""
                DELETE FROM ports 
                WHERE scan_id NOT IN (SELECT scan_id FROM scan_results)
            """).rowcount
            
            # Delete orphaned subdomains
            deleted_subdomains = conn.execute("""
                DELETE FROM subdomains 
                WHERE scan_id NOT IN (SELECT scan_id FROM scan_results)
            """).rowcount
            
            conn.commit()
            
            logger.info(f"Cleanup completed: {deleted_scans} scans, {deleted_vulns} vulnerabilities, "
                       f"{deleted_ports} ports, {deleted_subdomains} subdomains removed")

# Global database instance
db = CyberNoxDatabase()

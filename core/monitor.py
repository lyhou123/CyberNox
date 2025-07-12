"""
Network monitoring and traffic analysis module for CyberNox
"""

import socket
import threading
import time
from datetime import datetime
from collections import defaultdict
from utils.logger import logger
from utils.config import config

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available, advanced packet capture disabled")

class NetworkMonitor:
    """Network monitoring and traffic analysis"""
    
    def __init__(self):
        self.monitoring = False
        self.packets_captured = 0
        self.connections = defaultdict(int)
        self.protocols = defaultdict(int)
        self.suspicious_activity = []
        self.start_time = None
        
    def start_monitoring(self, interface=None, duration=60, packet_count=1000):
        """Start network monitoring"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available, cannot start packet capture")
            return {"error": "Scapy library required for packet capture"}
        
        logger.info(f"Starting network monitoring for {duration} seconds")
        self.monitoring = True
        self.start_time = datetime.now()
        self.packets_captured = 0
        self.connections.clear()
        self.protocols.clear()
        self.suspicious_activity.clear()
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                prn=self._process_packet,
                timeout=duration,
                count=packet_count,
                stop_filter=lambda x: not self.monitoring
            )
            
            self.monitoring = False
            end_time = datetime.now()
            duration_actual = (end_time - self.start_time).total_seconds()
            
            logger.info(f"Network monitoring completed. Captured {self.packets_captured} packets")
            
            return {
                "status": "completed",
                "start_time": self.start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration": duration_actual,
                "packets_captured": self.packets_captured,
                "unique_connections": len(self.connections),
                "protocols": dict(self.protocols),
                "top_connections": self._get_top_connections(),
                "suspicious_activity": self.suspicious_activity
            }
            
        except Exception as e:
            self.monitoring = False
            error_msg = f"Network monitoring failed: {e}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        logger.info("Network monitoring stopped")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        self.packets_captured += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            # Count connections
            connection = f"{src_ip} -> {dst_ip}"
            self.connections[connection] += 1
            
            # Count protocols
            if TCP in packet:
                self.protocols['TCP'] += 1
                self._analyze_tcp_packet(packet)
            elif UDP in packet:
                self.protocols['UDP'] += 1
                self._analyze_udp_packet(packet)
            elif ICMP in packet:
                self.protocols['ICMP'] += 1
                self._analyze_icmp_packet(packet)
            else:
                self.protocols['Other'] += 1
            
            # Detect suspicious activity
            self._detect_suspicious_activity(packet)
    
    def _analyze_tcp_packet(self, packet):
        """Analyze TCP packet for suspicious activity"""
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # Detect port scanning (SYN scan)
            if flags == 2:  # SYN flag only
                self._log_suspicious_activity("Port Scan", 
                    f"SYN scan detected from {packet[IP].src}:{src_port} to {packet[IP].dst}:{dst_port}")
            
            # Detect suspicious ports
            suspicious_ports = [4444, 5555, 6666, 1234, 31337, 12345]
            if dst_port in suspicious_ports:
                self._log_suspicious_activity("Suspicious Port",
                    f"Connection to suspicious port {dst_port} from {packet[IP].src}")
    
    def _analyze_udp_packet(self, packet):
        """Analyze UDP packet for suspicious activity"""
        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Detect DNS tunneling (excessive DNS traffic)
            if dst_port == 53 or src_port == 53:
                # Basic DNS traffic analysis would go here
                pass
    
    def _analyze_icmp_packet(self, packet):
        """Analyze ICMP packet for suspicious activity"""
        if ICMP in packet:
            icmp_type = packet[ICMP].type
            
            # Detect ICMP tunneling
            if icmp_type == 8:  # Echo request
                if len(packet) > 84:  # Unusually large ICMP packet
                    self._log_suspicious_activity("ICMP Tunneling",
                        f"Large ICMP packet ({len(packet)} bytes) from {packet[IP].src}")
    
    def _detect_suspicious_activity(self, packet):
        """General suspicious activity detection"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Detect potential DDoS (high packet rate from single source)
        # This would require more sophisticated rate tracking
        
        # Detect connections to suspicious IP ranges
        suspicious_ranges = [
            '10.0.0.0/8',    # Private networks (if monitoring external traffic)
            '172.16.0.0/12',
            '192.168.0.0/16'
        ]
        
        # Basic implementation - would need proper CIDR checking
        for range_ip in suspicious_ranges:
            if dst_ip.startswith(range_ip.split('/')[0].rsplit('.', 1)[0]):
                # This is a simplified check
                pass
    
    def _log_suspicious_activity(self, activity_type, description):
        """Log suspicious activity"""
        activity = {
            "timestamp": datetime.now().isoformat(),
            "type": activity_type,
            "description": description
        }
        self.suspicious_activity.append(activity)
        logger.warning(f"Suspicious activity detected: {activity_type} - {description}")
    
    def _get_top_connections(self, limit=10):
        """Get top connections by packet count"""
        return sorted(self.connections.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def port_scan_detection(self, interface=None, duration=30):
        """Dedicated port scan detection"""
        logger.info("Starting port scan detection")
        
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy library required"}
        
        scan_attempts = defaultdict(set)
        
        def detect_scan(packet):
            if IP in packet and TCP in packet:
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Detect SYN scans
                if flags == 2:  # SYN flag
                    scan_attempts[src_ip].add(dst_port)
        
        try:
            sniff(iface=interface, prn=detect_scan, timeout=duration)
            
            # Analyze results
            scanners = []
            for src_ip, ports in scan_attempts.items():
                if len(ports) > 10:  # Threshold for port scan detection
                    scanners.append({
                        "source_ip": src_ip,
                        "ports_scanned": len(ports),
                        "ports": sorted(list(ports))
                    })
            
            return {
                "duration": duration,
                "scanners_detected": len(scanners),
                "scanners": scanners
            }
            
        except Exception as e:
            error_msg = f"Port scan detection failed: {e}"
            logger.error(error_msg)
            return {"error": error_msg}

class BasicNetworkMonitor:
    """Basic network monitoring without Scapy"""
    
    def __init__(self):
        self.monitoring = False
        self.connections = []
    
    def monitor_connections(self, duration=60):
        """Monitor network connections using basic socket operations"""
        logger.info(f"Starting basic network monitoring for {duration} seconds")
        
        start_time = time.time()
        self.monitoring = True
        
        while self.monitoring and (time.time() - start_time) < duration:
            try:
                # This is a very basic implementation
                # Real monitoring would use netstat or similar tools
                time.sleep(1)
                
            except KeyboardInterrupt:
                break
        
        self.monitoring = False
        logger.info("Basic network monitoring completed")
        
        return {
            "status": "completed",
            "duration": time.time() - start_time,
            "connections": self.connections
        }

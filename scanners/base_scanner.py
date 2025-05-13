#!/usr/bin/env python3
"""
Base scanner class for ICS protocol scanners.
All protocol-specific scanners should inherit from this class.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import logging
import time
import socket
from datetime import datetime

class BaseScanner:
    """
    Base scanner class that provides common functionality for all protocol scanners.
    
    MottaSec ICS Ninja Scanner - Core component for all protocol-specific scanners.
    """
    
    def __init__(self, intensity='low', timeout=5, verify=True):
        """
        Initialize the scanner.
        
        Args:
            intensity (str): Scan intensity level ('low', 'medium', 'high')
            timeout (int): Connection timeout in seconds
            verify (bool): Whether to verify SSL/TLS certificates
        """
        self.intensity = intensity
        self.timeout = timeout
        self.verify = verify
        self.name = self.__class__.__name__
        self.standard_ports = []
        self.scan_start_time = None
        self.scan_end_time = None
        
        # Setup logging
        self.logger = logging.getLogger(f"MottaSec.{self.name}")
        
    def scan(self, target, open_ports=None):
        """
        Scan a target for the specific protocol.
        This method should be overridden by subclasses.
        
        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)
            
        Returns:
            dict: Scan results with the following format:
                {
                    'device_info': {
                        'type': 'Device type',
                        'version': 'Version info',
                        'other_key': 'other_value'
                    },
                    'issues': [
                        {
                            'severity': 'critical|high|medium|low|info',
                            'description': 'Issue description',
                            'details': 'Additional details',
                            'remediation': 'How to fix'
                        }
                    ]
                }
        """
        raise NotImplementedError("Subclasses must implement the scan method")
    
    def check_port_open(self, target, port):
        """
        Check if a specific port is open on the target.
        
        Args:
            target (str): Target IP address
            port (int): Port number to check
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception as e:
            self.logger.debug(f"MottaSec port check error: {str(e)}")
            return False
    
    def create_issue(self, severity, description, details=None, remediation=None):
        """
        Create an issue entry in a standard format.
        
        Args:
            severity (str): Issue severity ('critical', 'high', 'medium', 'low', 'info')
            description (str): Brief description of the issue
            details (str, optional): Detailed information about the issue
            remediation (str, optional): Guidance for fixing the issue
            
        Returns:
            dict: Issue entry in standard format
        """
        issue = {
            'severity': severity,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        
        if details:
            issue['details'] = details
            
        if remediation:
            issue['remediation'] = remediation
            
        return issue
    
    def start_scan_timer(self):
        """Start the scan timer to measure scan duration."""
        self.scan_start_time = time.time()
        
    def stop_scan_timer(self):
        """Stop the scan timer and return the duration in seconds."""
        if self.scan_start_time:
            self.scan_end_time = time.time()
            return self.scan_end_time - self.scan_start_time
        return None
    
    def get_scan_duration(self):
        """Get the scan duration in seconds."""
        if self.scan_start_time and self.scan_end_time:
            return self.scan_end_time - self.scan_start_time
        return None
    
    def mottasec_banner(self):
        """Return a MottaSec banner for the scanner."""
        return f"""
        ╔═══════════════════════════════════════════════╗
        ║  MottaSec ICS Ninja Scanner - {self.name:<15} ║
        ║  Intensity: {self.intensity:<6}  Timeout: {self.timeout}s        ║
        ╚═══════════════════════════════════════════════╝
        """ 
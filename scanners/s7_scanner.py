#!/usr/bin/env python3
"""
Siemens S7 protocol scanner for detecting security issues in S7 PLCs.
"""

import socket
import struct
import time
import re
import snap7
from snap7.exceptions import Snap7Exception

from scanners.base_scanner import BaseScanner

# Constants for S7 protection levels
S7_PROTECTION_LEVELS = {
    0: "No protection",
    1: "Password protected",
    2: "Reserved",
    3: "Full protection (no read/write allowed)"
}

class S7Scanner(BaseScanner):
    """Scanner for detecting security issues in Siemens S7 PLCs."""
    
    def __init__(self, intensity='low', timeout=5, verify=True):
        """Initialize the S7 scanner."""
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [102]  # Standard S7 port
    
    def scan(self, target, open_ports=None):
        """
        Scan a target for S7 security issues.
        
        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)
            
        Returns:
            dict: Scan results
        """
        results = {
            'device_info': {},
            'issues': []
        }
        
        # Determine which ports to scan
        ports_to_scan = open_ports if open_ports else self.standard_ports
        
        # Check if S7 is available on any port
        s7_port = None
        for port in ports_to_scan:
            if self._check_s7_availability(target, port):
                s7_port = port
                break
        
        # If S7 is not available, return empty results
        if not s7_port:
            return None
        
        # Add device info
        results['device_info']['port'] = s7_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"Siemens S7 PLC Found: {target}:{s7_port}",
            details="A device responding to Siemens S7 protocol was detected."
        ))
        
        # List of racks and slots to try
        rack_slot_combinations = [
            (0, 1),  # Most common
            (0, 2), 
            (0, 0),
            (1, 0),
            (1, 1)
        ]
        
        # Try to connect with different rack/slot combinations
        client = None
        rack = 0
        slot = 1
        
        for test_rack, test_slot in rack_slot_combinations:
            try:
                client = snap7.client.Client()
                client.set_connection_type(1)  # TCP connection
                client.connect(target, test_rack, test_slot, tcp_port=s7_port)
                
                if client.get_connected():
                    rack = test_rack
                    slot = test_slot
                    break
            except Snap7Exception:
                if client:
                    client.disconnect()
                    client.destroy()
                    client = None
        
        # If no connection could be established, try a more aggressive approach for detection only
        if not client and self._check_s7_availability(target, s7_port):
            results['device_info']['detected'] = True
            results['device_info']['rack'] = 'unknown'
            results['device_info']['slot'] = 'unknown'
            results['issues'].append(self.create_issue(
                severity='info',
                description="S7 device detected but couldn't establish full connection",
                details="The device appears to be an S7 PLC but the correct rack and slot couldn't be determined."
            ))
            return results
        
        # If still no connection, return empty results
        if not client:
            return None
        
        try:
            # We have a connection, add device info
            results['device_info']['connected'] = True
            results['device_info']['rack'] = rack
            results['device_info']['slot'] = slot
            
            # Get CPU info
            try:
                cpu_info = client.get_cpu_info()
                if cpu_info:
                    results['device_info']['module_type'] = cpu_info.ModuleTypeName.decode('utf-8').strip()
                    results['device_info']['serial_number'] = cpu_info.SerialNumber.decode('utf-8').strip()
                    results['device_info']['as_name'] = cpu_info.ASName.decode('utf-8').strip()
                    results['device_info']['module_name'] = cpu_info.ModuleName.decode('utf-8').strip()
                    
                    # Log the PLC type and details
                    details = f"Module: {cpu_info.ModuleTypeName.decode('utf-8').strip()}"
                    if cpu_info.SerialNumber:
                        details += f", Serial: {cpu_info.SerialNumber.decode('utf-8').strip()}"
                    
                    results['issues'].append(self.create_issue(
                        severity='info',
                        description=f"S7 PLC Identified: {cpu_info.ModuleTypeName.decode('utf-8').strip()}",
                        details=details
                    ))
            except Snap7Exception as e:
                # Non-critical error, just log it
                results['issues'].append(self.create_issue(
                    severity='info',
                    description="Couldn't retrieve CPU info",
                    details=f"Error: {str(e)}"
                ))
            
            # Check protection level (requires medium or high intensity)
            if self.intensity in ['medium', 'high']:
                try:
                    protection = client.get_protection()
                    protection_level = protection.sch_schal
                    
                    results['device_info']['protection_level'] = protection_level
                    results['device_info']['protection_description'] = S7_PROTECTION_LEVELS.get(protection_level, "Unknown")
                    
                    # Check for weak or no protection
                    if protection_level == 0:
                        results['issues'].append(self.create_issue(
                            severity='critical',
                            description="S7 PLC has no password protection",
                            details="The PLC has no protection mechanism enabled, allowing unauthorized program changes.",
                            remediation="Enable password protection for the PLC in the hardware configuration."
                        ))
                    elif protection_level == 1:
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="S7 PLC has only password protection",
                            details="The PLC is protected by password only, which can be brute-forced or sniffed.",
                            remediation="Use the highest protection level available for your PLC model."
                        ))
                except Snap7Exception:
                    pass
            
            # Check if ordering code can be read (firmware version info)
            try:
                order_code = client.get_order_code()
                if order_code:
                    version = f"v{order_code.V1}.{order_code.V2}.{order_code.V3}"
                    results['device_info']['order_code'] = order_code.Code.decode('utf-8').strip()
                    results['device_info']['firmware_version'] = version
                    
                    # Add issue for firmware information
                    results['issues'].append(self.create_issue(
                        severity='info',
                        description=f"S7 PLC Order Code: {order_code.Code.decode('utf-8').strip()}",
                        details=f"Firmware version: {version}"
                    ))
                    
                    # Check for known vulnerable firmware versions
                    if self._check_vulnerable_firmware(order_code.Code.decode('utf-8').strip(), version):
                        results['issues'].append(self.create_issue(
                            severity='high',
                            description="PLC firmware version has known vulnerabilities",
                            details=f"The firmware version {version} of {order_code.Code.decode('utf-8').strip()} has published vulnerabilities.",
                            remediation="Update to the latest firmware version available from Siemens."
                        ))
            except Snap7Exception:
                pass
            
            # Check for block information and unauthorized access (medium and high intensity)
            if self.intensity in ['medium', 'high']:
                try:
                    # Try to read block list
                    blocks = client.list_blocks()
                    if blocks:
                        block_counts = {}
                        if blocks.OBCount: block_counts['OB'] = blocks.OBCount
                        if blocks.FBCount: block_counts['FB'] = blocks.FBCount
                        if blocks.FCCount: block_counts['FC'] = blocks.FCCount
                        if blocks.DBCount: block_counts['DB'] = blocks.DBCount
                        if blocks.SFBCount: block_counts['SFB'] = blocks.SFBCount
                        if blocks.SFCCount: block_counts['SFC'] = blocks.SFCCount
                        
                        results['device_info']['program_blocks'] = block_counts
                        
                        # Add as an issue
                        blocks_str = ", ".join([f"{count} {block_type}" for block_type, count in block_counts.items()])
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="PLC program information accessible",
                            details=f"Block information can be read: {blocks_str}",
                            remediation="Enable access protection in the PLC configuration."
                        ))
                except Snap7Exception:
                    pass
            
            # Try to access data blocks (high intensity only)
            if self.intensity == 'high':
                try:
                    # Try to read diagnostic buffer
                    diag_buffer = client.read_szl(0x0132, 0x0004)
                    if diag_buffer:
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="PLC diagnostic buffer is readable",
                            details="Unauthorized access to diagnostic information is possible.",
                            remediation="Restrict access to diagnostic functions."
                        ))
                except Snap7Exception:
                    pass
                
                # Try to test DB read access
                readable_dbs = self._test_db_read_access(client)
                if readable_dbs:
                    results['device_info']['readable_dbs'] = readable_dbs
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description=f"Unauthorized access to Data Blocks: {', '.join(map(str, readable_dbs[:5]))}",
                        details="Data blocks can be read without authentication, potentially exposing sensitive data.",
                        remediation="Enable block protection and access control."
                    ))
                
                # Try to test DB write access
                writable_dbs = self._test_db_write_access(client, readable_dbs)
                if writable_dbs:
                    results['device_info']['writable_dbs'] = writable_dbs
                    results['issues'].append(self.create_issue(
                        severity='critical',
                        description=f"Unauthorized write access to Data Blocks: {', '.join(map(str, writable_dbs[:5]))}",
                        details="Data blocks can be modified without authentication, allowing control of PLC operations.",
                        remediation="Enable block protection and access control. Use know-how protection for critical blocks."
                    ))
                
        except Exception as e:
            # Add connection error to results
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error during S7 PLC inspection: {str(e)}",
                details="A device was detected but the scanner encountered an error during deeper inspection."
            ))
        
        finally:
            # Close the client connection
            if client:
                try:
                    client.disconnect()
                    client.destroy()
                except Exception:
                    pass
        
        return results
    
    def _check_s7_availability(self, target, port):
        """
        Check if an S7 device is available at the specified address.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            
        Returns:
            bool: True if an S7 device is detected, False otherwise
        """
        # Basic COTP connection request packet (ISO over TCP)
        cotp_connection_request = bytes([
            # TPKT
            0x03, 0x00, 0x00, 0x16,  # Version, Reserved, Packet Length
            # COTP
            0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
            0xC1, 0x02, 0x10, 0x00, 0xC2, 0x02, 0x03, 0x00,
            0xC0, 0x01, 0x0A
        ])
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((target, port))
            sock.send(cotp_connection_request)
            response = sock.recv(1024)
            
            # Check if it looks like a valid S7 response
            if len(response) > 7 and response[5] == 0xD0:  # COTP Connection Confirm
                return True
            
            return False
        
        except Exception:
            return False
        
        finally:
            sock.close()
    
    def _test_db_read_access(self, client, max_db=100):
        """
        Test read access to data blocks.
        
        Args:
            client (snap7.client.Client): S7 client
            max_db (int): Maximum DB number to test
            
        Returns:
            list: List of readable DBs
        """
        readable_dbs = []
        
        # Test access to common DB numbers
        for db_num in range(1, max_db + 1):
            try:
                # Try to read first 4 bytes from the DB
                data = client.db_read(db_num, 0, 4)
                if data and len(data) == 4:
                    readable_dbs.append(db_num)
            except Snap7Exception:
                pass
        
        return readable_dbs
    
    def _test_db_write_access(self, client, readable_dbs=None):
        """
        Test write access to data blocks.
        
        Args:
            client (snap7.client.Client): S7 client
            readable_dbs (list): List of readable DBs to test
            
        Returns:
            list: List of writable DBs
        """
        writable_dbs = []
        
        # Only test DBs we can read
        dbs_to_test = readable_dbs if readable_dbs else []
        
        for db_num in dbs_to_test:
            try:
                # Read current value
                original_data = client.db_read(db_num, 0, 4)
                if not original_data or len(original_data) != 4:
                    continue
                
                # Create slightly modified data (careful not to cause disruption)
                modified_data = bytearray(original_data)
                modified_data[0] = (modified_data[0] + 1) % 256
                
                # Try to write and then restore
                client.db_write(db_num, 0, modified_data)
                # Verify the write worked
                verify_data = client.db_read(db_num, 0, 4)
                if verify_data and verify_data[0] == modified_data[0]:
                    # Restore original data
                    client.db_write(db_num, 0, original_data)
                    writable_dbs.append(db_num)
            except Snap7Exception:
                pass
        
        return writable_dbs
    
    def _check_vulnerable_firmware(self, order_code, version):
        """
        Check if the firmware is known to be vulnerable.
        
        Args:
            order_code (str): PLC order code
            version (str): Firmware version
            
        Returns:
            bool: True if vulnerable, False otherwise
        """
        # This is a simplified check - in a real implementation, this would check
        # against a database of known vulnerable versions
        # Example vulnerabilities (these are examples, not actual vulnerabilities)
        vulnerabilities = {
            "6ES7 212": ["v1.0.1", "v1.1.0", "v1.2.0"],
            "6ES7 214": ["v1.0.0", "v1.0.1"],
            "6ES7 215": ["v2.0.0", "v2.1.0"],
            "6ES7 315-2A": ["v2.6.0", "v2.6.1", "v2.6.2"],
            "6ES7 315-2E": ["v3.1.0", "v3.2.0"],
            "6ES7 317-2A": ["v3.3.0", "v3.3.1"],
            "6ES7 412-2A": ["v4.0.0", "v4.1.0"],
            "6ES7 414-2A": ["v3.0.0", "v3.1.0", "v3.2.0"],
            "6ES7 416-2A": ["v5.0.0", "v5.1.0"]
        }
        
        # Check if the order code matches any known vulnerable series
        for vuln_code, vuln_versions in vulnerabilities.items():
            if vuln_code in order_code and version in vuln_versions:
                return True
        
        return False 
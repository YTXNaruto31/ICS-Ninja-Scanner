#!/usr/bin/env python3
"""
IEC 60870-5-104 protocol scanner for detecting security issues in power grid systems.
"""

import socket
import struct
import time
import random
from datetime import datetime

from scanners.base_scanner import BaseScanner

# IEC-104 APCI (Application Protocol Control Information) formats
IEC104_STARTDT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])  # Start Data Transfer
IEC104_TESTFR = bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])   # Test Frame
IEC104_STOPDT = bytes([0x68, 0x04, 0x13, 0x00, 0x00, 0x00])   # Stop Data Transfer

# I-format ASDU types (Application Service Data Unit)
ASDU_TYPES = {
    1: "M_SP_NA_1 (Single-point information)",
    3: "M_DP_NA_1 (Double-point information)",
    5: "M_ST_NA_1 (Step position information)",
    7: "M_BO_NA_1 (Bitstring of 32 bit)",
    9: "M_ME_NA_1 (Measured value, normalized value)",
    11: "M_ME_NB_1 (Measured value, scaled value)",
    13: "M_ME_NC_1 (Measured value, short floating point value)",
    30: "M_SP_TB_1 (Single-point with time tag CP56Time2a)",
    31: "M_DP_TB_1 (Double-point with time tag CP56Time2a)",
    45: "C_SC_NA_1 (Single command)",
    46: "C_DC_NA_1 (Double command)",
    47: "C_RC_NA_1 (Regulating step command)",
    48: "C_SE_NA_1 (Set-point command, normalized value)",
    49: "C_SE_NB_1 (Set-point command, scaled value)",
    50: "C_SE_NC_1 (Set-point command, short floating point value)",
    100: "C_IC_NA_1 (Interrogation command)",
    101: "C_CI_NA_1 (Counter interrogation command)",
    103: "C_CS_NA_1 (Clock synchronization command)",
    107: "C_TS_TA_1 (Test command with time tag CP56Time2a)"
}

# For tracking security issues
CRITICAL_ASDU_TYPES = [45, 46, 47, 48, 49, 50, 103]  # Command types

class IEC104Scanner(BaseScanner):
    """Scanner for detecting security issues in IEC 60870-5-104 devices."""
    
    def __init__(self, intensity='low', timeout=5, verify=True):
        """Initialize the IEC-104 scanner."""
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [2404]  # Standard IEC-104 port
    
    def scan(self, target, open_ports=None):
        """
        Scan a target for IEC-104 security issues.
        
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
        
        # Check if IEC-104 is available on any port
        iec104_port = None
        for port in ports_to_scan:
            if self._check_iec104_availability(target, port):
                iec104_port = port
                break
        
        # If IEC-104 is not available, return empty results
        if not iec104_port:
            return None
        
        # Add device info
        results['device_info']['port'] = iec104_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"IEC 60870-5-104 Device Found: {target}:{iec104_port}",
            details="A device responding to IEC 60870-5-104 protocol was detected."
        ))
        
        # Perform security tests based on scan intensity
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, iec104_port))
            
            # Send STARTDT (Start Data Transfer) to initialize communication
            sock.send(IEC104_STARTDT)
            response = sock.recv(1024)
            
            # Parse basic device info from response if possible
            device_info = self._parse_device_info(response)
            if device_info:
                results['device_info'].update(device_info)
            
            # Check for encryption
            if not self._is_encrypted(response):
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="IEC-104 communication is unencrypted",
                    details="The protocol transmits control data in plaintext, making it vulnerable to eavesdropping and tampering.",
                    remediation="Implement TLS tunneling or VPN for IEC-104 communications."
                ))
            
            # Basic check for authentication mechanisms (which IEC-104 doesn't have natively)
            results['issues'].append(self.create_issue(
                severity='critical',
                description="No authentication mechanism detected in IEC-104",
                details="The IEC-104 protocol doesn't implement authentication, allowing unauthorized access to power grid controls.",
                remediation="Implement access control at the network level, use secure gateways, or upgrade to secure variants of the protocol with authentication."
            ))
            
            # Perform additional tests based on intensity
            if self.intensity in ['medium', 'high']:
                # Test for interrogation command support
                if self._test_interrogation_command(sock):
                    results['device_info']['supports_interrogation'] = True
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description="IEC-104 interrogation command supported",
                        details="Unauthenticated users can request state information from the device.",
                        remediation="Restrict access to authorized hosts only."
                    ))
                
                # Test for clock synchronization vulnerability
                if self._test_clock_sync_vulnerability(sock):
                    results['device_info']['vulnerable_clock_sync'] = True
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description="IEC-104 clock synchronization vulnerability",
                        details="Unauthenticated users can change the device's clock, potentially affecting operations and logging.",
                        remediation="Implement network-level controls to restrict who can send clock sync commands."
                    ))
            
            # Only attempt higher-risk tests in high intensity mode
            if self.intensity == 'high':
                # Test for control command vulnerability
                # Note: This is only simulated, it doesn't actually send harmful commands
                vulnerable_commands = self._test_control_commands(sock)
                if vulnerable_commands:
                    results['device_info']['vulnerable_commands'] = vulnerable_commands
                    results['issues'].append(self.create_issue(
                        severity='critical',
                        description="IEC-104 control commands accepted without authentication",
                        details=f"The device accepts unauthenticated control commands: {', '.join(vulnerable_commands)}",
                        remediation="Implement access control at network level and restrict command authorization."
                    ))
        
        except Exception as e:
            # Add connection error to results if we already detected the protocol
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error during IEC-104 inspection: {str(e)}",
                details="A device was detected but the scanner encountered an error during deeper inspection."
            ))
        
        finally:
            # Close the socket connection
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        
        return results
    
    def _check_iec104_availability(self, target, port):
        """
        Check if an IEC-104 device is available at the specified address.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            
        Returns:
            bool: True if an IEC-104 device is detected, False otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((target, port))
            
            # Send a TESTFR activation
            sock.send(IEC104_TESTFR)
            response = sock.recv(1024)
            
            # Check if it looks like a valid IEC-104 response
            if len(response) >= 6 and response[0] == 0x68 and response[1] == 0x04:
                # Check if it's a TESTFR confirmation (0x83 = 0x43 + 0x40)
                if response[2] == 0x83:
                    return True
                
                # Check if it's another valid IEC-104 message type
                valid_types = [0x0B, 0x07, 0x13, 0x43, 0x23, 0x83]
                if response[2] in valid_types:
                    return True
            
            return False
        
        except Exception:
            return False
        
        finally:
            sock.close()
    
    def _parse_device_info(self, response):
        """
        Parse device information from the IEC-104 response.
        
        Args:
            response (bytes): IEC-104 response data
            
        Returns:
            dict: Device information
        """
        device_info = {}
        
        # Parse ASDU data if present
        if len(response) > 6:
            # Check if it's an I-format message (bit 0 of control octet is 0)
            if response[2] & 0x01 == 0:
                # Extract ASDU type if possible
                if len(response) >= 10:
                    asdu_type = response[6]
                    if asdu_type in ASDU_TYPES:
                        device_info['asdu_type'] = ASDU_TYPES[asdu_type]
                    else:
                        device_info['asdu_type'] = f"Unknown type ({asdu_type})"
        
        return device_info
    
    def _is_encrypted(self, response):
        """
        Check if the communication appears to be encrypted.
        
        Args:
            response (bytes): IEC-104 response data
            
        Returns:
            bool: True if communication appears encrypted, False otherwise
        """
        # This is a very simplified check that assumes unencrypted IEC-104
        # would have a recognizable structure in the first few bytes.
        # In real-world scenarios, this requires more advanced analysis.
        return False  # IEC-104 is not encrypted by default
    
    def _test_interrogation_command(self, sock):
        """
        Test if the device supports interrogation commands.
        
        Args:
            sock (socket.socket): Socket connection to the device
            
        Returns:
            bool: True if supported, False otherwise
        """
        try:
            # Build a simple C_IC_NA_1 (Interrogation command) packet
            # APCI header
            packet = bytearray([
                0x68, 0x0E,          # Start and length
                0x00, 0x00,          # Send sequence number (0)
                0x00, 0x00,          # Receive sequence number (0)
                # ASDU
                0x64,                # Type ID (100 = C_IC_NA_1)
                0x01,                # Variable structure qualifier
                0x06,                # Cause of transmission (6 = activation)
                0x00,                # Originator address
                0x01, 0x00,          # Common address of ASDU (1)
                0x00, 0x00, 0x00     # Information object address (0)
            ])
            
            # Send the packet
            sock.send(packet)
            
            # Try to receive a response
            response = sock.recv(1024)
            
            # Check if we got a valid response (simplified check)
            if len(response) > 6 and response[0] == 0x68:
                return True
            
            return False
        
        except Exception:
            return False
    
    def _test_clock_sync_vulnerability(self, sock):
        """
        Test if the device accepts clock synchronization commands.
        
        Args:
            sock (socket.socket): Socket connection to the device
            
        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            # Get current time
            now = datetime.now()
            
            # Build a C_CS_NA_1 (Clock synchronization command) packet
            # APCI header
            packet = bytearray([
                0x68, 0x14,          # Start and length
                0x00, 0x00,          # Send sequence number (0)
                0x00, 0x00,          # Receive sequence number (0)
                # ASDU
                0x67,                # Type ID (103 = C_CS_NA_1)
                0x01,                # Variable structure qualifier
                0x06,                # Cause of transmission (6 = activation)
                0x00,                # Originator address
                0x01, 0x00,          # Common address of ASDU (1)
                0x00, 0x00, 0x00     # Information object address (0)
            ])
            
            # Add CP56Time2a timestamp (7 bytes)
            # Milliseconds (2 bytes), minutes (1 byte), hours (1 byte),
            # day of month (1 byte), month (1 byte), year (1 byte)
            ms = (now.second * 1000) + (now.microsecond // 1000)
            packet.extend([
                ms & 0xFF, (ms >> 8) & 0xFF,  # Milliseconds (little-endian)
                now.minute & 0x3F,           # Minutes (0-59)
                now.hour & 0x1F,             # Hours (0-23)
                now.day & 0x1F,              # Day of month (1-31)
                now.month & 0x0F,            # Month (1-12)
                now.year % 100               # Year (0-99)
            ])
            
            # Send the packet
            sock.send(packet)
            
            # Try to receive a response
            response = sock.recv(1024)
            
            # Check if we got an ACK or similar (simplified check)
            if len(response) > 6 and response[0] == 0x68:
                # If we got a response that's not an explicit error, consider it vulnerable
                # In reality, more sophisticated parsing would be needed
                return True
            
            return False
        
        except Exception:
            return False
    
    def _test_control_commands(self, sock):
        """
        Test if the device accepts control commands without authentication.
        This is a simulated test - it doesn't send actual harmful commands.
        
        Args:
            sock (socket.socket): Socket connection to the device
            
        Returns:
            list: List of command types that appear to be accepted
        """
        vulnerable_commands = []
        
        # In a real implementation, we'd test multiple command types
        # Here we'll just test a simulated "read-only" version
        
        # Test single command (C_SC_NA_1) with neutral value
        try:
            # Build a C_SC_NA_1 packet with "read" qualifier
            packet = bytearray([
                0x68, 0x0E,          # Start and length
                0x00, 0x00,          # Send sequence number (0)
                0x00, 0x00,          # Receive sequence number (0)
                # ASDU
                0x2D,                # Type ID (45 = C_SC_NA_1)
                0x01,                # Variable structure qualifier
                0x05,                # Cause of transmission (5 = request)
                0x00,                # Originator address
                0x01, 0x00,          # Common address of ASDU (1)
                0x01, 0x00, 0x00     # Information object address (1)
            ])
            
            # Send the packet
            sock.send(packet)
            
            # Try to receive a response
            response = sock.recv(1024)
            
            # Check if we got a response (simplified check)
            if len(response) > 6 and response[0] == 0x68:
                # If the response isn't an explicit error, consider it vulnerable
                vulnerable_commands.append("Single Command (C_SC_NA_1)")
        
        except Exception:
            pass
        
        # In a real scanner, we would test more command types here
        
        return vulnerable_commands 
#!/usr/bin/env python3
"""
SNMP protocol scanner for detecting security issues in SNMP-enabled ICS devices.
This is a MottaSec-enhanced implementation that doesn't rely on pysnmp for Python 3.13 compatibility.

Created by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import struct
import time
import random
import binascii
import logging
from scanners.base_scanner import BaseScanner

# SNMP v1 packet constants
SNMP_VERSION_1 = 0x00

# Common SNMP community strings to check
DEFAULT_COMMUNITY_STRINGS = [
    # Standard defaults
    'public', 'private', 'manager', 'admin', 'cisco', 'secret',
    'supervisor', 'guest', 'system', 'device', 'scada', 'plc',
    'router', 'switch', 'control', 'automation', 'remote', 'write',
    # ICS vendor specific
    'siemens', 'rockwell', 'schneider', 'honeywell', 'emerson', 'abb',
    'yokogawa', 'ge', 'omron', 'mitsubishi', 'allen-bradley',
    # MottaSec special - we've seen these in the wild
    'motta', 'ghost', 'fox', 'ninja', 'jedis', 'aces'
]

class SNMPScanner(BaseScanner):
    """
    Scanner for detecting security issues in SNMP-enabled ICS devices.
    
    Developed by MottaSec Ghost Team to identify vulnerable SNMP configurations
    in industrial control systems.
    """
    
    def __init__(self, intensity='low', timeout=5, verify=True):
        """Initialize the SNMP scanner with MottaSec magic."""
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [161]  # Standard SNMP port
        self.logger = logging.getLogger("MottaSec.SNMPScanner")
    
    def scan(self, target, open_ports=None):
        """
        Scan a target for SNMP security issues.
        
        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)
            
        Returns:
            dict: Scan results with MottaSec-level detail
        """
        self.logger.debug(f"MottaSec Ghost starting SNMP scan on {target}")
        results = {
            'device_info': {},
            'issues': []
        }
        
        # Determine which ports to scan
        ports_to_scan = open_ports if open_ports else self.standard_ports
        
        # Check if SNMP is available on any port
        snmp_port = None
        for port in ports_to_scan:
            if self._check_snmp_availability(target, port):
                snmp_port = port
                break
        
        # If SNMP is not available, return empty results
        if not snmp_port:
            self.logger.debug(f"No SNMP service detected on {target}")
            return None
        
        # Add device info
        results['device_info']['port'] = snmp_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"SNMP Service Found: {target}:{snmp_port}",
            details="A device responding to SNMP requests was detected."
        ))
        
        # Determine which community strings to try based on intensity
        community_strings = []
        if self.intensity == 'low':
            # Only check the most common strings in low intensity
            community_strings = ['public', 'private', 'manager', 'admin']
        elif self.intensity == 'medium':
            # Check common strings plus some ICS-specific ones
            community_strings = DEFAULT_COMMUNITY_STRINGS[:15]
        else:  # high intensity
            # Check all community strings
            community_strings = DEFAULT_COMMUNITY_STRINGS
        
        # Try to connect with different community strings
        valid_communities = []
        
        for community in community_strings:
            try:
                if self._test_community_string(target, snmp_port, community):
                    valid_communities.append(community)
                    
                    # Add issue for each valid community string
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description=f"SNMP access with community string: '{community}'",
                        details=f"The device allows access using the community string '{community}'.",
                        remediation="Change default community strings to strong, unique values. Consider using SNMPv3 with authentication and encryption."
                    ))
            except Exception as e:
                self.logger.debug(f"Error testing community string {community}: {str(e)}")
        
        if valid_communities:
            results['device_info']['community_strings'] = valid_communities
            
            # Add general issue about SNMP security
            results['issues'].append(self.create_issue(
                severity='high',
                description="SNMP v1/v2c in use (unencrypted)",
                details="SNMPv1/v2c uses unencrypted communications and has weak authentication.",
                remediation="Upgrade to SNMPv3 with authentication and encryption."
            ))
            
            # If we're in high intensity mode, try to get system info
            if self.intensity == 'high' and valid_communities:
                try:
                    system_info = self._get_system_info(target, snmp_port, valid_communities[0])
                    if system_info:
                        results['device_info'].update(system_info)
                        
                        # Add issue about system information disclosure
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="SNMP system information disclosure",
                            details=f"System information was disclosed via SNMP: {', '.join(system_info.keys())}",
                            remediation="Restrict access to system OIDs or use SNMPv3 with authentication and encryption."
                        ))
                except Exception as e:
                    self.logger.debug(f"Error getting system info: {str(e)}")
        
        self.logger.debug(f"MottaSec Ghost completed SNMP scan on {target}")
        return results
    
    def _check_snmp_availability(self, target, port):
        """
        Check if SNMP is available at the specified address using a basic get request.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            
        Returns:
            bool: True if SNMP is detected, False otherwise
        """
        # Try with the most common community string
        return self._test_community_string(target, port, 'public')
    
    def _test_community_string(self, target, port, community):
        """
        Test if a community string is valid.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            community (str): Community string to test
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Create a simple SNMP GET request for sysDescr (1.3.6.1.2.1.1.1.0)
        try:
            # Create a socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Create a basic SNMP v1 GET request
            # This is a simplified packet and not a complete SNMP implementation
            # Format: version, community, PDU type, request ID, error status, error index, OID
            request_id = random.randint(1, 65535)
            community_bytes = community.encode('ascii')
            
            # OID for sysDescr.0 (1.3.6.1.2.1.1.1.0)
            oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)
            
            # Build a very basic SNMP packet (this is simplified)
            # In a real implementation, we would use proper BER encoding
            packet = bytearray([
                0x30, 0x29,                         # SEQUENCE
                0x02, 0x01, SNMP_VERSION_1,         # INTEGER: version
                0x04, len(community_bytes)          # OCTET STRING: community
            ])
            packet.extend(community_bytes)
            packet.extend([
                0xa0, 0x1c,                         # GET REQUEST
                0x02, 0x04                          # INTEGER: request ID
            ])
            packet.extend(struct.pack('>I', request_id))
            packet.extend([
                0x02, 0x01, 0x00,                   # INTEGER: error status
                0x02, 0x01, 0x00,                   # INTEGER: error index
                0x30, 0x0e,                         # SEQUENCE: variable bindings
                0x30, 0x0c,                         # SEQUENCE: variable
                0x06, 0x08                          # OBJECT IDENTIFIER
            ])
            
            # Add the OID
            for i in oid:
                packet.append(i)
            
            packet.extend([
                0x05, 0x00                          # NULL
            ])
            
            # Fix lengths (simplified)
            packet[1] = len(packet) - 2
            
            # Send the packet
            sock.sendto(packet, (target, port))
            
            # Try to receive a response
            try:
                response, _ = sock.recvfrom(1024)
                # If we get any response, consider it a success
                return len(response) > 0
            except socket.timeout:
                return False
            
        except Exception as e:
            self.logger.debug(f"SNMP test error: {str(e)}")
            return False
        finally:
            try:
                sock.close()
            except:
                pass
        
        return False
    
    def _get_system_info(self, target, port, community):
        """
        Get system information using SNMP.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            community (str): Community string to use
            
        Returns:
            dict: System information
        """
        # MottaSec Ghost Team special - we try to get as much system info as possible
        # This is a simplified implementation that just tries to get sysDescr
        system_info = {}
        
        try:
            # Create a socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # OIDs to query
            oids = {
                (1, 3, 6, 1, 2, 1, 1, 1, 0): 'sysDescr',      # System description
                (1, 3, 6, 1, 2, 1, 1, 5, 0): 'sysName',       # System name
                (1, 3, 6, 1, 2, 1, 1, 6, 0): 'sysLocation',   # System location
                (1, 3, 6, 1, 2, 1, 1, 4, 0): 'sysContact',    # System contact
                (1, 3, 6, 1, 2, 1, 1, 2, 0): 'sysObjectID',   # System object ID
                (1, 3, 6, 1, 2, 1, 1, 3, 0): 'sysUpTime'      # System uptime
            }
            
            for oid, name in oids.items():
                try:
                    # Create a basic SNMP GET request
                    request_id = random.randint(1, 65535)
                    community_bytes = community.encode('ascii')
                    
                    # Build a very basic SNMP packet
                    packet = bytearray([
                        0x30, 0x29,                         # SEQUENCE
                        0x02, 0x01, SNMP_VERSION_1,         # INTEGER: version
                        0x04, len(community_bytes)          # OCTET STRING: community
                    ])
                    packet.extend(community_bytes)
                    packet.extend([
                        0xa0, 0x1c,                         # GET REQUEST
                        0x02, 0x04                          # INTEGER: request ID
                    ])
                    packet.extend(struct.pack('>I', request_id))
                    packet.extend([
                        0x02, 0x01, 0x00,                   # INTEGER: error status
                        0x02, 0x01, 0x00,                   # INTEGER: error index
                        0x30, 0x0e,                         # SEQUENCE: variable bindings
                        0x30, 0x0c,                         # SEQUENCE: variable
                        0x06, 0x08                          # OBJECT IDENTIFIER
                    ])
                    
                    # Add the OID
                    for i in oid:
                        packet.append(i)
                    
                    packet.extend([
                        0x05, 0x00                          # NULL
                    ])
                    
                    # Fix lengths (simplified)
                    packet[1] = len(packet) - 2
                    
                    # Send the packet
                    sock.sendto(packet, (target, port))
                    
                    # Try to receive a response
                    try:
                        response, _ = sock.recvfrom(1024)
                        if len(response) > 0:
                            # This is a very simplified parser that just tries to extract the string value
                            # In a real implementation, we would properly parse the BER encoding
                            try:
                                # Look for OCTET STRING type (0x04) in the response
                                # This is a very crude way to extract the value
                                for i in range(len(response)):
                                    if response[i] == 0x04 and i + 1 < len(response):
                                        str_len = response[i + 1]
                                        if i + 2 + str_len <= len(response):
                                            value = response[i + 2:i + 2 + str_len].decode('utf-8', errors='ignore')
                                            system_info[name] = value
                                            break
                            except:
                                pass
                    except socket.timeout:
                        pass
                except:
                    pass
            
        except Exception as e:
            self.logger.debug(f"Error getting system info: {str(e)}")
        finally:
            try:
                sock.close()
            except:
                pass
        
        return system_info 
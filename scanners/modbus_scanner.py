#!/usr/bin/env python3
"""
Modbus protocol scanner for detecting security issues in Modbus devices.
"""

import socket
import struct
import time
import random
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException, ModbusIOException
from pymodbus.pdu import ExceptionResponse
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadDecoder

from scanners.base_scanner import BaseScanner

class ModbusScanner(BaseScanner):
    """Scanner for detecting security issues in Modbus devices."""
    
    def __init__(self, intensity='low', timeout=5, verify=True):
        """Initialize the Modbus scanner."""
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [502]  # Standard Modbus TCP port
    
    def scan(self, target, open_ports=None):
        """
        Scan a target for Modbus security issues.
        
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
        
        # Check if Modbus is available on any port
        modbus_port = None
        for port in ports_to_scan:
            if self._check_modbus_availability(target, port):
                modbus_port = port
                break
        
        # If Modbus is not available, return empty results
        if not modbus_port:
            return None
        
        # Add device info
        results['device_info']['port'] = modbus_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"Modbus Device Found: {target}:{modbus_port}",
            details="A device responding to Modbus TCP protocol was detected."
        ))
        
        # Create Modbus client
        client = ModbusTcpClient(target, port=modbus_port, timeout=self.timeout)
        try:
            client.connect()
            
            # Add connection information
            connected = client.is_socket_open()
            if connected:
                results['device_info']['connected'] = True
                
                # Check for unit ID scanning if medium or high intensity
                if self.intensity in ['medium', 'high']:
                    valid_unit_ids = self._scan_unit_ids(client)
                    if valid_unit_ids:
                        results['device_info']['unit_ids'] = valid_unit_ids
                        if len(valid_unit_ids) > 1:
                            results['issues'].append(self.create_issue(
                                severity='medium',
                                description=f"Multiple Modbus Unit IDs detected: {valid_unit_ids}",
                                details="Multiple Unit IDs may indicate the presence of multiple devices or a Modbus gateway.",
                                remediation="Verify all Unit IDs are authorized devices and restrict access if needed."
                            ))
                
                # Check if authentication is required (which is normally not in Modbus)
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="Unauthenticated Modbus access detected",
                    details="Modbus protocol does not implement authentication mechanisms, allowing unauthorized access.",
                    remediation="Implement network segmentation, access control lists, or a secure gateway for Modbus communications."
                ))
                
                # Test read access to holding registers
                if self.intensity in ['medium', 'high']:
                    readable_registers = self._test_read_access(client)
                    if readable_registers:
                        readable_text = ', '.join([str(reg) for reg in readable_registers[:10]])
                        if len(readable_registers) > 10:
                            readable_text += f" and {len(readable_registers) - 10} more"
                            
                        results['device_info']['readable_registers'] = readable_registers
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description=f"Readable holding registers: {readable_text}",
                            details="Unauthenticated read access to registers could expose sensitive information.",
                            remediation="Restrict access to Modbus registers through firewall rules or access control lists."
                        ))
                
                # Test write access to coils and holding registers
                if self.intensity == 'high':
                    writable_coils = self._test_write_access_coils(client)
                    if writable_coils:
                        writable_text = ', '.join([str(coil) for coil in writable_coils[:10]])
                        if len(writable_coils) > 10:
                            writable_text += f" and {len(writable_coils) - 10} more"
                            
                        results['device_info']['writable_coils'] = writable_coils
                        results['issues'].append(self.create_issue(
                            severity='high',
                            description=f"Writable coils: {writable_text}",
                            details="Unauthenticated write access to coils allows control of device operations.",
                            remediation="Implement write protection or access control for control registers."
                        ))
                    
                    writable_registers = self._test_write_access_registers(client)
                    if writable_registers:
                        writable_text = ', '.join([str(reg) for reg in writable_registers[:10]])
                        if len(writable_registers) > 10:
                            writable_text += f" and {len(writable_registers) - 10} more"
                            
                        results['device_info']['writable_registers'] = writable_registers
                        results['issues'].append(self.create_issue(
                            severity='critical',
                            description=f"Writable holding registers: {writable_text}",
                            details="Unauthenticated write access to holding registers allows modification of device settings.",
                            remediation="Implement write protection or access control for holding registers."
                        ))
                
                # Test for Modbus function code scanning
                if self.intensity in ['medium', 'high']:
                    supported_functions = self._scan_function_codes(client)
                    if supported_functions:
                        results['device_info']['supported_functions'] = supported_functions
                        
                        # Check for diagnostic functions
                        diagnostic_functions = [8, 43, 125, 126, 127]
                        supported_diagnostic = [f for f in supported_functions if f in diagnostic_functions]
                        if supported_diagnostic:
                            results['issues'].append(self.create_issue(
                                severity='medium',
                                description=f"Diagnostic function codes supported: {supported_diagnostic}",
                                details="Diagnostic functions may allow attackers to gather system information or cause DoS.",
                                remediation="Disable unused diagnostic functions if possible."
                            ))
                        
                        # Check for programming/firmware functions
                        program_functions = [90, 91, 125, 126]
                        supported_program = [f for f in supported_functions if f in program_functions]
                        if supported_program:
                            results['issues'].append(self.create_issue(
                                severity='critical',
                                description=f"Programming function codes supported: {supported_program}",
                                details="Programming functions may allow attackers to modify firmware or program logic.",
                                remediation="Disable programming functions in production or implement strong access controls."
                            ))
        
        except Exception as e:
            # Add connection error to results
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error connecting to Modbus device: {str(e)}",
                details="A device was detected but the scanner encountered an error during deeper inspection."
            ))
        
        finally:
            # Close the client connection
            if client and client.is_socket_open():
                client.close()
        
        return results
    
    def _check_modbus_availability(self, target, port):
        """
        Check if a Modbus device is available at the specified address.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            
        Returns:
            bool: True if a Modbus device is detected, False otherwise
        """
        # Try to connect to the device
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((target, port))
            
            # Send a Modbus TCP packet (Read Holding Registers, unit 1, address 0, count 1)
            # Transaction ID (2 bytes), Protocol ID (2 bytes), Length (2 bytes), Unit ID (1 byte), Function code (1 byte), Address (2 bytes), Count (2 bytes)
            packet = struct.pack('>HHHBBHH', 1, 0, 6, 1, 3, 0, 1)
            sock.send(packet)
            
            # Receive response
            response = sock.recv(1024)
            
            # Check if it's a valid Modbus response
            if len(response) >= 9 and response[7] == 3:  # Function code 3 (Read Holding Registers)
                return True
            elif len(response) >= 9 and response[7] == 131:  # Exception response for function code 3
                return True
            
            return False
        
        except Exception:
            return False
        
        finally:
            sock.close()
    
    def _scan_unit_ids(self, client, max_id=247):
        """
        Scan for valid Modbus unit IDs.
        
        Args:
            client (ModbusTcpClient): Modbus client
            max_id (int): Maximum unit ID to scan
            
        Returns:
            list: List of valid unit IDs
        """
        valid_ids = []
        
        for unit_id in range(1, max_id + 1):
            try:
                # Try to read a single register from each unit ID
                response = client.read_holding_registers(0, 1, unit=unit_id)
                if not response.isError():
                    valid_ids.append(unit_id)
            except Exception:
                pass
        
        return valid_ids
    
    def _test_read_access(self, client, unit_id=1):
        """
        Test read access to holding registers.
        
        Args:
            client (ModbusTcpClient): Modbus client
            unit_id (int): Unit ID to test
            
        Returns:
            list: List of readable registers
        """
        readable_registers = []
        
        # Common register ranges to test
        ranges = [
            (0, 10),       # Common configuration and status registers
            (1000, 1010),  # Common process variables
            (4000, 4010),  # Common Modbus 4xxxx registers
            (40000, 40010) # Alternate notation for 4xxxx registers
        ]
        
        for start, end in ranges:
            for address in range(start, end):
                try:
                    response = client.read_holding_registers(address, 1, unit=unit_id)
                    if not response.isError():
                        readable_registers.append(address)
                except Exception:
                    pass
        
        return readable_registers
    
    def _test_write_access_coils(self, client, unit_id=1):
        """
        Test write access to coils.
        
        Args:
            client (ModbusTcpClient): Modbus client
            unit_id (int): Unit ID to test
            
        Returns:
            list: List of writable coils
        """
        writable_coils = []
        
        # Common coil ranges to test
        ranges = [(0, 10), (100, 110)]
        
        for start, end in ranges:
            for address in range(start, end):
                try:
                    # Try to read the current value
                    read_response = client.read_coils(address, 1, unit=unit_id)
                    if read_response.isError():
                        continue
                    
                    original_value = read_response.bits[0]
                    
                    # Try to write the opposite value
                    write_response = client.write_coil(address, not original_value, unit=unit_id)
                    if not write_response.isError():
                        # Write back the original value to avoid disruption
                        client.write_coil(address, original_value, unit=unit_id)
                        writable_coils.append(address)
                except Exception:
                    pass
        
        return writable_coils
    
    def _test_write_access_registers(self, client, unit_id=1):
        """
        Test write access to holding registers.
        
        Args:
            client (ModbusTcpClient): Modbus client
            unit_id (int): Unit ID to test
            
        Returns:
            list: List of writable registers
        """
        writable_registers = []
        
        # Common register ranges to test
        ranges = [
            (0, 10),       # Common configuration registers
            (1000, 1010),  # Common process variables
            (4000, 4010),  # Common Modbus 4xxxx registers
            (40000, 40010) # Alternate notation for 4xxxx registers
        ]
        
        for start, end in ranges:
            for address in range(start, end):
                try:
                    # Try to read the current value
                    read_response = client.read_holding_registers(address, 1, unit=unit_id)
                    if read_response.isError():
                        continue
                    
                    original_value = read_response.registers[0]
                    
                    # Calculate a "safe" test value (close to original to minimize impact)
                    test_value = original_value + 1 if original_value < 65535 else original_value - 1
                    
                    # Try to write the test value
                    write_response = client.write_register(address, test_value, unit=unit_id)
                    if not write_response.isError():
                        # Write back the original value to avoid disruption
                        client.write_register(address, original_value, unit=unit_id)
                        writable_registers.append(address)
                except Exception:
                    pass
        
        return writable_registers
    
    def _scan_function_codes(self, client, unit_id=1):
        """
        Scan for supported Modbus function codes.
        
        Args:
            client (ModbusTcpClient): Modbus client
            unit_id (int): Unit ID to test
            
        Returns:
            list: List of supported function codes
        """
        supported_functions = []
        
        # Common function codes to test
        function_tests = {
            1: lambda: client.read_coils(0, 1, unit=unit_id),
            2: lambda: client.read_discrete_inputs(0, 1, unit=unit_id),
            3: lambda: client.read_holding_registers(0, 1, unit=unit_id),
            4: lambda: client.read_input_registers(0, 1, unit=unit_id),
            5: lambda: client._execute(5, struct.pack('>HH', 0, 0xFF00), unit=unit_id),  # Write Single Coil
            6: lambda: client._execute(6, struct.pack('>HH', 0, 0), unit=unit_id),        # Write Single Register
            15: lambda: client._execute(15, struct.pack('>HHBc', 0, 1, 1, bytes([0])), unit=unit_id),  # Write Multiple Coils
            16: lambda: client._execute(16, struct.pack('>HHBcc', 0, 1, 2, bytes([0]), bytes([0])), unit=unit_id),  # Write Multiple Registers
            22: lambda: client._execute(22, struct.pack('>HHcc', 0, 0, bytes([0]), bytes([0])), unit=unit_id),  # Mask Write Register
            23: lambda: client._execute(23, struct.pack('>HHHHB', 0, 1, 0, 1, 2), unit=unit_id)   # Read/Write Multiple Registers
        }
        
        for function_code, test_func in function_tests.items():
            try:
                response = test_func()
                # If we got a response that's not an exception, or the exception is "illegal data address" (rather than illegal function),
                # the function is supported
                if not isinstance(response, ExceptionResponse) or response.exception_code == 2:
                    supported_functions.append(function_code)
            except Exception:
                pass
        
        return supported_functions 
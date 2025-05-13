#!/usr/bin/env python3
"""
Test suite for the SNMP scanner.
Created by MottaSec Fox Team for the MottaSec ICS Ninja Scanner.
"""

import unittest
from unittest.mock import patch, MagicMock
from scanners.snmp_scanner import SNMPScanner
import socket

class TestSNMPScanner(unittest.TestCase):
    """Test cases for the SNMPScanner class."""
    
    def test_initialization(self):
        """Test the initialization of the SNMPScanner class."""
        scanner = SNMPScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [161])
    
    @patch('scanners.snmp_scanner.SNMPScanner._check_snmp_availability')
    def test_scan_no_snmp_available(self, mock_check):
        """Test scan when SNMP is not available."""
        mock_check.return_value = False
        scanner = SNMPScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)
        mock_check.assert_called_once_with('192.168.1.1', 161)
    
    @patch('scanners.snmp_scanner.SNMPScanner._check_snmp_availability')
    @patch('scanners.snmp_scanner.SNMPScanner._test_community_string')
    def test_scan_with_snmp_available(self, mock_test_community, mock_check):
        """Test scan when SNMP is available."""
        # Mock SNMP being available
        mock_check.return_value = True
        
        # Mock community string tests - public works, private doesn't
        def mock_community_side_effect(target, port, community):
            return community == 'public'
        
        mock_test_community.side_effect = mock_community_side_effect
        
        # Create scanner with low intensity (only tests a few community strings)
        scanner = SNMPScanner(intensity='low')
        result = scanner.scan('192.168.1.1')
        
        # Check that the result contains the expected data
        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 161)
        self.assertEqual(result['device_info']['community_strings'], ['public'])
        
        # Check that we have the expected issues
        self.assertEqual(len(result['issues']), 3)  # Info + High (community) + High (unencrypted)
        
        # Check issue severities and descriptions
        severities = [issue['severity'] for issue in result['issues']]
        self.assertIn('info', severities)
        self.assertIn('high', severities)
        
        # Check that we have the right community string in the issue
        for issue in result['issues']:
            if issue['severity'] == 'high' and 'community string' in issue['description']:
                self.assertIn('public', issue['description'])
    
    @patch('scanners.snmp_scanner.socket.socket')
    def test_test_community_string(self, mock_socket):
        """Test the _test_community_string method."""
        # Setup mock socket
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock successful response
        mock_socket_instance.recvfrom.return_value = (b'some response', ('192.168.1.1', 161))
        
        scanner = SNMPScanner()
        result = scanner._test_community_string('192.168.1.1', 161, 'public')
        
        self.assertTrue(result)
        mock_socket_instance.sendto.assert_called_once()
        mock_socket_instance.recvfrom.assert_called_once()
        mock_socket_instance.close.assert_called_once()
    
    @patch('scanners.snmp_scanner.socket.socket')
    def test_test_community_string_timeout(self, mock_socket):
        """Test the _test_community_string method with timeout."""
        # Setup mock socket
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock timeout
        mock_socket_instance.recvfrom.side_effect = socket.timeout()
        
        scanner = SNMPScanner()
        result = scanner._test_community_string('192.168.1.1', 161, 'public')
        
        self.assertFalse(result)
        mock_socket_instance.sendto.assert_called_once()
        mock_socket_instance.close.assert_called_once()

if __name__ == '__main__':
    unittest.main() 
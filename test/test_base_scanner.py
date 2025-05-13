#!/usr/bin/env python3
"""
Test suite for the base scanner class.
Created by MottaSec Jedis for the MottaSec ICS Ninja Scanner.
"""

import unittest
from scanners.base_scanner import BaseScanner

class TestBaseScanner(unittest.TestCase):
    """Test cases for the BaseScanner class."""
    
    def test_initialization(self):
        """Test the initialization of the BaseScanner class."""
        scanner = BaseScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.name, 'BaseScanner')
        self.assertEqual(scanner.standard_ports, [])
    
    def test_create_issue(self):
        """Test the create_issue method."""
        scanner = BaseScanner()
        
        # Test with minimal parameters
        issue = scanner.create_issue('high', 'Test issue')
        self.assertEqual(issue['severity'], 'high')
        self.assertEqual(issue['description'], 'Test issue')
        self.assertNotIn('details', issue)
        self.assertNotIn('remediation', issue)
        
        # Test with all parameters
        issue = scanner.create_issue(
            'critical', 
            'Critical issue', 
            'This is a critical issue that needs attention',
            'Apply patch XYZ'
        )
        self.assertEqual(issue['severity'], 'critical')
        self.assertEqual(issue['description'], 'Critical issue')
        self.assertEqual(issue['details'], 'This is a critical issue that needs attention')
        self.assertEqual(issue['remediation'], 'Apply patch XYZ')
    
    def test_scan_not_implemented(self):
        """Test that the scan method raises NotImplementedError."""
        scanner = BaseScanner()
        with self.assertRaises(NotImplementedError):
            scanner.scan('192.168.1.1')

if __name__ == '__main__':
    unittest.main() 
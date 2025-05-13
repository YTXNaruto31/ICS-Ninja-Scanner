#!/usr/bin/env python3
"""
MQTT protocol scanner for detecting security issues in IIoT and SCADA-to-cloud communications.
"""

import socket
import struct
import time
import random
import ssl
import paho.mqtt.client as mqtt

from scanners.base_scanner import BaseScanner

# Common topics to check for read access
COMMON_MQTT_TOPICS = [
    "#",                # All topics (wildcard)
    "+/+",              # Two-level wildcard
    "sensor/#",         # All sensor topics
    "device/#",         # All device topics
    "scada/#",          # All SCADA topics
    "plc/#",            # All PLC topics
    "control/#",        # All control topics
    "factory/#",        # All factory topics
    "building/#",       # All building topics
    "energy/#",         # All energy topics
    "power/#",          # All power topics
    "status/#",         # All status topics
    "data/#",           # All data topics
    "telemetry/#",      # All telemetry topics
    "alarm/#",          # All alarm topics
    "alert/#",          # All alert topics
    "config/#",         # All configuration topics
    "command/#",        # All command topics
    "system/#",         # All system topics
    "$SYS/#"            # Broker internal topics
]

class MQTTScanner(BaseScanner):
    """Scanner for detecting security issues in MQTT brokers and clients."""
    
    def __init__(self, intensity='low', timeout=5, verify=True, test_mode=False):
        """Initialize the MQTT scanner."""
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [1883, 8883]  # Standard MQTT and MQTT over TLS ports
        self.test_mode = test_mode
    
    def scan(self, target, open_ports=None):
        """
        Scan a target for MQTT security issues.
        
        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)
            
        Returns:
            dict: Scan results
        """
        self.start_scan_timer()
        self.logger.debug(f"Starting MQTT scan on {target}")
        
        results = {
            'device_info': {},
            'issues': []
        }
        
        # Determine which ports to scan
        ports_to_scan = open_ports if open_ports else self.standard_ports
        
        # Check if MQTT is available on any port
        mqtt_ports = []
        for port in ports_to_scan:
            protocol = self._check_mqtt_availability(target, port)
            if protocol:
                mqtt_ports.append((port, protocol))
        
        # If MQTT is not available, return empty results
        if not mqtt_ports:
            self.logger.debug(f"No MQTT service detected on {target}")
            return None
        
        # Add device info
        results['device_info']['ports'] = [p for p, _ in mqtt_ports]
        results['device_info']['protocols'] = [p for _, p in mqtt_ports]
        
        for port, protocol in mqtt_ports:
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"MQTT Broker Found: {target}:{port} ({protocol})",
                details=f"A device responding to MQTT protocol was detected on port {port}."
            ))
            
            # Test authentication
            auth_results = self._test_authentication(target, port, protocol)
            
            if auth_results.get('anonymous_access'):
                results['issues'].append(self.create_issue(
                    severity='critical',
                    description="MQTT broker allows anonymous access",
                    details="The broker allows connections without authentication, enabling unauthorized access to data and commands.",
                    remediation="Configure the broker to require username and password authentication."
                ))
            
            if auth_results.get('default_credentials'):
                for cred in auth_results['default_credentials']:
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description=f"MQTT broker accepts default credentials: {cred[0]}:{cred[1]}",
                        details="The broker accepts well-known default credentials.",
                        remediation="Change default credentials and implement a strong password policy."
                    ))
            
            # If TLS is not used
            if protocol == 'mqtt':
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="MQTT traffic is unencrypted",
                    details="The broker accepts connections without TLS encryption, exposing data and credentials to eavesdropping.",
                    remediation="Configure the broker to use TLS (MQTT over SSL) on port 8883."
                ))
            
            # Skip topic access tests in test mode or test environments to avoid errors
            if not self.test_mode and self.intensity in ['medium', 'high'] and (auth_results.get('anonymous_access') or auth_results.get('default_credentials')):
                # Use the first successful credentials (or None for anonymous)
                credentials = None
                if auth_results.get('default_credentials'):
                    credentials = auth_results['default_credentials'][0]
                
                try:
                    # Test access to topics
                    topics_access = self._test_topics_access(target, port, protocol, credentials)
                    
                    if topics_access.get('readable_topics'):
                        topics_list = ", ".join(topics_access['readable_topics'][:5])
                        if len(topics_access['readable_topics']) > 5:
                            topics_list += f" and {len(topics_access['readable_topics']) - 5} more"
                        
                        results['device_info']['readable_topics'] = topics_access['readable_topics']
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description=f"Unauthorized read access to MQTT topics: {topics_list}",
                            details="The broker allows reading from topics without proper authentication.",
                            remediation="Implement access control lists (ACLs) to restrict topic access."
                        ))
                    
                    if topics_access.get('writable_topics'):
                        topics_list = ", ".join(topics_access['writable_topics'][:5])
                        if len(topics_access['writable_topics']) > 5:
                            topics_list += f" and {len(topics_access['writable_topics']) - 5} more"
                        
                        results['device_info']['writable_topics'] = topics_access['writable_topics']
                        results['issues'].append(self.create_issue(
                            severity='critical',
                            description=f"Unauthorized write access to MQTT topics: {topics_list}",
                            details="The broker allows publishing to topics without proper authentication, potentially allowing command injection.",
                            remediation="Implement access control lists (ACLs) to restrict topic access."
                        ))
                except Exception as e:
                    self.logger.debug(f"Error testing topic access: {str(e)}")
            
            # For medium and high intensity scans, check for information disclosure
            if not self.test_mode and self.intensity in ['medium', 'high'] and (auth_results.get('anonymous_access') or auth_results.get('default_credentials')):
                # Use the first successful credentials (or None for anonymous)
                credentials = None
                if auth_results.get('default_credentials'):
                    credentials = auth_results['default_credentials'][0]
                
                try:
                    system_info = self._get_system_info(target, port, protocol, credentials)
                    if system_info:
                        results['device_info']['broker_info'] = system_info
                        
                        # Extract version if available
                        if 'version' in system_info:
                            results['issues'].append(self.create_issue(
                                severity='medium',
                                description=f"MQTT broker version disclosed: {system_info['version']}",
                                details="The broker version is exposed, which may help attackers identify known vulnerabilities.",
                                remediation="Restrict access to $SYS topics and use the latest broker version."
                            ))
                        
                        # Check for client information disclosure
                        if 'connected_clients' in system_info:
                            results['issues'].append(self.create_issue(
                                severity='medium',
                                description=f"MQTT client information is exposed: {len(system_info['connected_clients'])} clients visible",
                                details="The broker exposes information about connected clients.",
                                remediation="Restrict access to $SYS/# topics that contain client information."
                            ))
                except Exception as e:
                    self.logger.debug(f"Error getting system info: {str(e)}")
        
        scan_duration = self.stop_scan_timer()
        self.logger.debug(f"MQTT scan completed in {scan_duration:.2f} seconds")
        return results
    
    def _check_mqtt_availability(self, target, port):
        """
        Check if an MQTT broker is available at the specified address.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            
        Returns:
            str: 'mqtt' for unencrypted, 'mqtts' for TLS, None if not available
        """
        # First, check for unencrypted MQTT
        if port == 1883 or port != 8883:
            try:
                # Create client with proper API version
                client = mqtt.Client(client_id="ics_scanner_probe", callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
                client.connect_async(target, port, 60)
                client.loop_start()
                
                # Wait a short time to allow connection
                time.sleep(1)
                
                if client.is_connected():
                    client.disconnect()
                    client.loop_stop()
                    return 'mqtt'
                else:
                    client.loop_stop()
            except Exception as e:
                self.logger.debug(f"Error checking MQTT availability on port {port}: {str(e)}")
        
        # If port is 8883, try MQTT over TLS
        if port == 8883:
            try:
                # Create client with proper API version
                client = mqtt.Client(client_id="ics_scanner_probe", callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
                client.tls_set(cert_reqs=ssl.CERT_NONE)  # Don't verify certs
                client.tls_insecure_set(True)  # Don't check hostnames
                client.connect_async(target, port, 60)
                client.loop_start()
                
                # Wait a short time to allow connection
                time.sleep(1)
                
                if client.is_connected():
                    client.disconnect()
                    client.loop_stop()
                    return 'mqtts'
                else:
                    client.loop_stop()
            except Exception as e:
                self.logger.debug(f"Error checking MQTT/TLS availability on port {port}: {str(e)}")
        
        return None
    
    def _test_authentication(self, target, port, protocol):
        """
        Test if the MQTT broker requires authentication.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            protocol (str): 'mqtt' or 'mqtts'
            
        Returns:
            dict: Authentication test results
        """
        result = {
            'anonymous_access': False,
            'default_credentials': []
        }
        
        # Try anonymous access
        try:
            # Create client with proper API version
            client = mqtt.Client(client_id="ics_scanner_auth", callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
            
            if protocol == 'mqtts':
                client.tls_set(cert_reqs=ssl.CERT_NONE)
                client.tls_insecure_set(True)
            
            client.connect(target, port, 5)
            client.loop_start()
            
            # Wait a short time to allow connection
            time.sleep(1)
            
            if client.is_connected():
                result['anonymous_access'] = True
                client.disconnect()
            
            client.loop_stop()
        except Exception as e:
            self.logger.debug(f"Error testing anonymous access: {str(e)}")
        
        # Try default credentials if intensity is medium or high
        if self.intensity in ['medium', 'high']:
            # List of default credentials to try: (username, password)
            default_creds = [
                ('admin', 'admin'),
                ('user', 'user'),
                ('mqtt', 'mqtt'),
                ('mosquitto', 'mosquitto'),
                ('pi', 'raspberry'),
                ('root', 'root'),
                ('admin', 'password'),
                ('device', 'device'),
                ('subscriber', 'subscriber'),
                ('publisher', 'publisher')
            ]
            
            for username, password in default_creds:
                try:
                    # Create client with proper API version
                    client = mqtt.Client(client_id="ics_scanner_auth", callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
                    client.username_pw_set(username, password)
                    
                    if protocol == 'mqtts':
                        client.tls_set(cert_reqs=ssl.CERT_NONE)
                        client.tls_insecure_set(True)
                    
                    client.connect(target, port, 5)
                    client.loop_start()
                    
                    # Wait a short time to allow connection
                    time.sleep(1)
                    
                    if client.is_connected():
                        result['default_credentials'].append((username, password))
                        client.disconnect()
                    
                    client.loop_stop()
                except Exception as e:
                    self.logger.debug(f"Error testing credentials {username}:{password}: {str(e)}")
        
        return result
    
    def _test_topics_access(self, target, port, protocol, credentials=None):
        """
        Test access to MQTT topics.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            protocol (str): 'mqtt' or 'mqtts'
            credentials (tuple): (username, password) or None for anonymous
            
        Returns:
            dict: Topic access test results
        """
        result = {
            'readable_topics': [],
            'writable_topics': []
        }
        
        try:
            # Setup client with proper API version
            client = mqtt.Client(client_id="ics_scanner_topic_test", callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
            
            if credentials:
                client.username_pw_set(credentials[0], credentials[1])
            
            if protocol == 'mqtts':
                client.tls_set(cert_reqs=ssl.CERT_NONE)
                client.tls_insecure_set(True)
            
            # Topics to test (limit number based on intensity)
            topics_to_test = COMMON_MQTT_TOPICS[:5]  # For low intensity
            if self.intensity == 'medium':
                topics_to_test = COMMON_MQTT_TOPICS[:10]
            elif self.intensity == 'high':
                topics_to_test = COMMON_MQTT_TOPICS
            
            # Set up a message callback
            received_messages = []
            topics_with_messages = set()
            
            def on_message(client, userdata, message):
                received_messages.append((message.topic, message.payload))
                topics_with_messages.add(message.topic)
            
            client.on_message = on_message
            
            client.connect(target, port, 5)
            client.loop_start()
            
            # Wait a short time to allow connection
            time.sleep(1)
            
            if client.is_connected():
                # Subscribe to topics to test read access
                for topic in topics_to_test:
                    try:
                        client.subscribe(topic, 0)
                    except Exception as e:
                        self.logger.debug(f"Error subscribing to topic {topic}: {str(e)}")
                
                # Wait a bit to receive any published messages
                time.sleep(2)
                
                # Test write access - publish to each topic
                for topic in topics_to_test:
                    # Don't publish to wildcards or broker topics
                    if '#' in topic or '+' in topic or topic.startswith('$'):
                        continue
                    
                    test_message = f"ICS Scanner Test Message (Harmless) - {random.randint(1000, 9999)}"
                    try:
                        result_code = client.publish(topic, test_message, 0, retain=False)
                        if result_code.rc == mqtt.MQTT_ERR_SUCCESS:
                            result['writable_topics'].append(topic)
                    except Exception as e:
                        self.logger.debug(f"Error publishing to topic {topic}: {str(e)}")
                
                # If we received any messages, those topics are readable
                # Use specific topics from received messages rather than wildcards
                if topics_with_messages:
                    for topic, _ in received_messages:
                        if topic not in result['readable_topics'] and not topic.startswith('$'):
                            result['readable_topics'].append(topic)
                
                # If we didn't receive any real messages but could subscribe to wildcards,
                # consider them "readable" although we don't know what specific topics exist
                for topic in topics_to_test:
                    if ('#' in topic or '+' in topic) and topic not in result['readable_topics']:
                        result['readable_topics'].append(topic)
                
                client.disconnect()
            
            client.loop_stop()
        except Exception as e:
            self.logger.debug(f"Error testing topic access: {str(e)}")
        
        return result
    
    def _get_system_info(self, target, port, protocol, credentials=None):
        """
        Get broker system information from $SYS topics.
        
        Args:
            target (str): Target IP address
            port (int): Port number
            protocol (str): 'mqtt' or 'mqtts'
            credentials (tuple): (username, password) or None for anonymous
            
        Returns:
            dict: System information
        """
        system_info = {}
        
        try:
            # Setup client with proper API version
            client = mqtt.Client(client_id="ics_scanner_system_info", callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
            
            if credentials:
                client.username_pw_set(credentials[0], credentials[1])
            
            if protocol == 'mqtts':
                client.tls_set(cert_reqs=ssl.CERT_NONE)
                client.tls_insecure_set(True)
            
            # Topics to retrieve system info
            system_topics = {
                '$SYS/broker/version': 'version',
                '$SYS/broker/uptime': 'uptime',
                '$SYS/broker/clients/total': 'total_clients',
                '$SYS/broker/clients/connected': 'connected_client_count',
                '$SYS/broker/subscriptions/count': 'subscription_count',
                '$SYS/broker/messages/stored': 'stored_messages',
                '$SYS/broker/clients/maximum': 'max_clients',
                '$SYS/broker/messages/received': 'messages_received',
                '$SYS/broker/messages/sent': 'messages_sent',
                '$SYS/broker/load/connections/1min': 'connection_rate',
                '$SYS/broker/memory/bytes': 'memory_used'
            }
            
            # Set up a message callback
            def on_message(client, userdata, message):
                topic = message.topic
                payload = message.payload.decode('utf-8', errors='ignore')
                
                # Map to our internal keys
                if topic in system_topics:
                    system_info[system_topics[topic]] = payload
                
                # Extract client information
                if topic.startswith('$SYS/broker/clients/') and '/clients/' not in topic[18:]:
                    if 'connected_clients' not in system_info:
                        system_info['connected_clients'] = []
                    system_info['connected_clients'].append({
                        'topic': topic,
                        'info': payload
                    })
            
            client.on_message = on_message
            
            client.connect(target, port, 5)
            client.loop_start()
            
            # Wait a short time to allow connection
            time.sleep(1)
            
            if client.is_connected():
                # Subscribe to system topics
                client.subscribe('$SYS/#', 0)
                
                # Wait to receive system info
                time.sleep(3)
                
                client.disconnect()
            
            client.loop_stop()
        except Exception as e:
            self.logger.debug(f"Error getting system info: {str(e)}")
        
        return system_info 
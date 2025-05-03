"""
Integration tests for the RSA Client-Server application.
These tests verify the end-to-end functionality including:
- Server startup and shutdown
- Client connection to server
- Key exchange
- Command execution
- Error handling
"""

import unittest
import sys
import os
import threading
import time
import json
import tempfile
import shutil
from unittest.mock import patch

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the necessary classes from the main module
from rsa_client_server import RSA, KeyManager, SecureProtocol, Server, Client


class TestIntegration(unittest.TestCase):
    """Integration test suite for the RSA Client-Server application."""

    @classmethod
    def setUpClass(cls):
        """Set up the test environment once for all tests."""
        # Create a temporary directory for key storage
        cls.temp_dir = tempfile.mkdtemp()
        
        # Use a non-standard port to avoid conflicts
        cls.server_port = 45678
        
        # Use shorter keys for faster testing
        cls.key_size = 512
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests have run."""
        # Remove the temporary directory
        shutil.rmtree(cls.temp_dir)
    
    def setUp(self):
        """Set up before each test."""
        # Create a key manager with the temporary directory
        self.key_manager = KeyManager(key_dir=self.temp_dir)
        
        # Start server in a separate thread
        self.server = Server(host='localhost', port=self.server_port, key_size=self.key_size)
        self.server.key_manager = self.key_manager
        
        # Setting up the server thread
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Give the server time to start
        time.sleep(0.5)
        
        # Create a client
        self.client = Client(server_host='localhost', server_port=self.server_port, key_size=self.key_size)
        self.client.key_manager = self.key_manager
    
    def tearDown(self):
        """Clean up after each test."""
        # Stop the server
        if hasattr(self, 'server') and self.server.running:
            self.server.stop()
        
        # Disconnect the client
        if hasattr(self, 'client') and self.client.connected:
            self.client.disconnect()
        
        # Give threads time to clean up
        time.sleep(0.5)
    
    def test_server_startup(self):
        """Test that the server starts up correctly."""
        self.assertTrue(self.server.running, "Server should be running after start")
        self.assertIsNotNone(self.server.server_socket, "Server socket should be created")
        
        # Check that the server generated or loaded keys
        self.assertIsNotNone(self.server.server_public_key, "Server should have a public key")
        self.assertIsNotNone(self.server.server_private_key, "Server should have a private key")
    
    def test_client_connection(self):
        """Test that the client can connect to the server."""
        # Connect the client
        success = self.client.connect()
        
        self.assertTrue(success, "Client connection should succeed")
        self.assertTrue(self.client.connected, "Client should be marked as connected")
        self.assertIsNotNone(self.client.socket, "Client socket should be created")
        self.assertIsNotNone(self.client.server_public_key, "Client should have server's public key")
        
        # Server should have the client in its clients dictionary
        client_address = self.client.socket.getsockname()
        self.assertIn(client_address, self.server.clients, "Server should track the connected client")
    
    def test_key_exchange(self):
        """Test that key exchange works correctly."""
        # Connect the client (which performs key exchange)
        self.client.connect()
        
        # Get client's socket address
        client_address = self.client.socket.getsockname()
        
        # Verify the server has the client's public key
        self.assertIn(client_address, self.server.clients, "Server should have client's public key")
        server_copy_of_client_key = self.server.clients[client_address]
        
        # Verify the client has the server's public key
        self.assertIsNotNone(self.client.server_public_key, "Client should have server's public key")
        
        # Verify the keys match
        self.assertEqual(
            self.client.client_public_key[0],
            server_copy_of_client_key[0],
            "Server's copy of client's public exponent should match"
        )
        self.assertEqual(
            self.client.client_public_key[1],
            server_copy_of_client_key[1],
            "Server's copy of client's modulus should match"
        )
    
    def test_echo_command(self):
        """Test that the echo command works end-to-end."""
        # Connect the client
        self.client.connect()
        
        # Test message
        test_message = "Hello, integration test!"
        
        # Send echo command
        response = self.client.send_request("echo", message=test_message)
        
        # Verify response
        self.assertEqual("success", response["status"], "Echo command should succeed")
        self.assertEqual(test_message, response["result"], "Echo response should match sent message")
    
    def test_time_command(self):
        """Test that the time command works end-to-end."""
        # Connect the client
        self.client.connect()
        
        # Send time command
        response = self.client.send_request("time")
        
        # Verify response
        self.assertEqual("success", response["status"], "Time command should succeed")
        self.assertIn("result", response, "Time response should include result")
        self.assertIsInstance(response["result"], str, "Time result should be a string")
        
        # Test with custom format
        custom_format = "%Y-%m-%d"
        response = self.client.send_request("time", format=custom_format)
        
        # Verify custom format response
        self.assertEqual("success", response["status"], "Time command with custom format should succeed")
        self.assertIn("result", response, "Time response should include result")
        
        # Try to parse the date to verify format
        try:
            time.strptime(response["result"], custom_format)
            format_valid = True
        except ValueError:
            format_valid = False
        
        self.assertTrue(format_valid, f"Time result should match format {custom_format}")
    
    def test_calc_command(self):
        """Test that the calc command works end-to-end."""
        # Connect the client
        self.client.connect()
        
        # Test cases
        test_cases = [
            ("add", 5, 3, 8),
            ("subtract", 10, 4, 6),
            ("multiply", 6, 7, 42),
            ("divide", 20, 5, 4)
        ]
        
        for operation, a, b, expected in test_cases:
            # Send calc command
            response = self.client.send_request("calc", operation=operation, a=a, b=b)
            
            # Verify response
            self.assertEqual("success", response["status"], f"Calc {operation} should succeed")
            self.assertEqual(expected, response["result"], f"Calc {operation} result should be {expected}")
        
        # Test division by zero error
        response = self.client.send_request("calc", operation="divide", a=10, b=0)
        self.assertEqual("error", response["status"], "Division by zero should return error status")
        self.assertIn("error", response, "Division by zero should include error message")
        self.assertIn("Division by zero", response["error"], "Error message should mention division by zero")
    
    def test_info_command(self):
        """Test that the info command works end-to-end."""
        # Connect the client
        self.client.connect()
        
        # Send info command
        response = self.client.send_request("info")
        
        # Verify response
        self.assertEqual("success", response["status"], "Info command should succeed")
        self.assertIn("server", response, "Info response should include server name")
        self.assertIn("version", response, "Info response should include version")
        self.assertIn("encryption", response, "Info response should include encryption type")
        self.assertIn("key_size", response, "Info response should include key size")
        self.assertIn("active_clients", response, "Info response should include active clients count")
        self.assertIn("uptime", response, "Info response should include uptime")
        
        # Verify specific values
        self.assertEqual("RSA", response["encryption"], "Encryption should be RSA")
        self.assertEqual(self.key_size, response["key_size"], "Key size should match server configuration")
        self.assertEqual(1, response["active_clients"], "There should be 1 active client (us)")
    
    def test_help_command(self):
        """Test that the help command works end-to-end."""
        # Connect the client
        self.client.connect()
        
        # Send help command
        response = self.client.send_request("help")
        
        # Verify response
        self.assertEqual("success", response["status"], "Help command should succeed")
        self.assertIn("available_commands", response, "Help response should include available commands")
        self.assertIn("usage", response, "Help response should include usage information")
        
        # Verify specific values
        self.assertIsInstance(response["available_commands"], list, "Available commands should be a list")
        self.assertIn("echo", response["available_commands"], "Echo command should be available")
        self.assertIn("time", response["available_commands"], "Time command should be available")
        self.assertIn("calc", response["available_commands"], "Calc command should be available")
        self.assertIn("info", response["available_commands"], "Info command should be available")
        self.assertIn("help", response["available_commands"], "Help command should be available")
    
    def test_unknown_command(self):
        """Test handling of unknown commands."""
        # Connect the client
        self.client.connect()
        
        # Send unknown command
        response = self.client.send_request("nonexistent")
        
        # Verify response
        self.assertEqual("error", response["status"], "Unknown command should return error status")
        self.assertIn("error", response, "Unknown command response should include error message")
        self.assertIn("Unknown command", response["error"], "Error message should mention unknown command")
    
    def test_client_reconnection(self):
        """Test that the client can reconnect after disconnection."""
        # Connect the client
        self.client.connect()
        self.assertTrue(self.client.connected, "Client should be connected")
        
        # Disconnect
        self.client.disconnect()
        self.assertFalse(self.client.connected, "Client should be disconnected")
        
        # Reconnect
        success = self.client.connect()
        self.assertTrue(success, "Client should be able to reconnect")
        self.assertTrue(self.client.connected, "Client should be marked as connected after reconnection")
        
        # Test that functionality still works
        response = self.client.send_request("echo", message="Reconnection test")
        self.assertEqual("success", response["status"], "Echo command should work after reconnection")
        self.assertEqual("Reconnection test", response["result"], "Echo response should match sent message")
    
    def test_multiple_clients(self):
        """Test that multiple clients can connect simultaneously."""
        # Connect first client
        self.client.connect()
        
        # Create and connect second client
        second_client = Client(server_host='localhost', server_port=self.server_port, key_size=self.key_size)
        second_client.key_manager = self.key_manager
        success = second_client.connect()
        
        try:
            self.assertTrue(success, "Second client should connect successfully")
            self.assertTrue(second_client.connected, "Second client should be marked as connected")
            
            # Verify both clients can communicate
            response1 = self.client.send_request("echo", message="Client 1")
            response2 = second_client.send_request("echo", message="Client 2")
            
            self.assertEqual("Client 1", response1["result"], "First client should receive correct response")
            self.assertEqual("Client 2", response2["result"], "Second client should receive correct response")
            
            # Check server info reflects multiple clients
            response = self.client.send_request("info")
            self.assertEqual(2, response["active_clients"], "Server should report 2 active clients")
        finally:
            # Clean up second client
            if second_client.connected:
                second_client.disconnect()
    
    def test_server_restart(self):
        """Test that the server can be stopped and restarted."""
        # Connect client
        self.client.connect()
        self.assertTrue(self.client.connected, "Client should be connected")
        
        # Stop the server
        self.server.stop()
        self.assertFalse(self.server.running, "Server should not be running after stop")
        
        # Give server time to shut down
        time.sleep(0.5)
        
        # Try to use client - should fail
        self.client.connected = False  # Reset flag since server is down
        
        # Restart the server
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Give server time to start up
        time.sleep(0.5)
        
        # Reconnect client
        success = self.client.connect()
        self.assertTrue(success, "Client should be able to connect after server restart")
        
        # Verify functionality works
        response = self.client.send_request("echo", message="Server restart test")
        self.assertEqual("success", response["status"], "Echo command should work after server restart")
        self.assertEqual("Server restart test", response["result"], "Echo response should match sent message")
    
    def test_invalid_command_parameters(self):
        """Test handling of commands with invalid parameters."""
        # Connect client
        self.client.connect()
        
        # Test calc command with missing parameters
        response = self.client.send_request("calc", operation="add")  # Missing a and b
        self.assertEqual("error", response["status"], "Command with missing parameters should return error")
        self.assertIn("error", response, "Response should include error message")
        
        # Test calc command with invalid operation
        response = self.client.send_request("calc", operation="invalid", a=5, b=3)
        self.assertEqual("error", response["status"], "Command with invalid operation should return error")
        self.assertIn("error", response, "Response should include error message")
        self.assertIn("Invalid operation", response["error"], "Error message should mention invalid operation")
    
    def test_protocol_error_handling(self):
        """Test handling of protocol errors."""
        # Connect client
        self.client.connect()
        
        # Patch the send_message method to simulate protocol error
        original_send = SecureProtocol.send_message
        
        def mock_send(*args, **kwargs):
            # Call the original but then disconnect the socket to simulate error
            result = original_send(*args, **kwargs)
            # Manually close the socket to simulate connection error
            self.client.socket.close()
            return result
        
        # Apply the patch
        with patch('rsa_client_server.SecureProtocol.send_message', side_effect=mock_send):
            # This should raise an exception that's caught by the client
            with self.assertRaises(ConnectionError):
                self.client.send_request("echo", message="This will fail")
        
        # The client should detect the disconnection
        self.assertFalse(self.client.connected, "Client should detect disconnection")
    
    def test_client_timeout(self):
        """Test client timeouts during connection."""
        # Create a client with a short timeout
        timeout_client = Client(
            server_host='localhost',
            server_port=self.server_port,
            key_size=self.key_size,
            timeout=0.1  # Very short timeout
        )
        timeout_client.key_manager = self.key_manager
        
        # Stop the server to simulate timeout
        self.server.stop()
        time.sleep(0.5)
        
        # Try to connect - should fail with timeout
        success = timeout_client.connect()
        self.assertFalse(success, "Connection should fail with timeout")
        self.assertFalse(timeout_client.connected, "Client should not be marked as connected")
    
    def test_key_persistence(self):
        """Test that keys are correctly saved and loaded."""
        # Connect client to generate keys
        self.client.connect()
        
        # Get the original keys
        original_server_key = self.server.server_public_key
        original_client_key = self.client.client_public_key
        
        # Disconnect and stop everything
        self.client.disconnect()
        self.server.stop()
        time.sleep(0.5)
        
        # Restart with same key directory
        self.server = Server(host='localhost', port=self.server_port, key_size=self.key_size)
        self.server.key_manager = self.key_manager
        
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(0.5)
        
        self.client = Client(server_host='localhost', server_port=self.server_port, key_size=self.key_size)
        self.client.key_manager = self.key_manager
        self.client.connect()
        
        # Verify keys are the same
        self.assertEqual(original_server_key, self.server.server_public_key, 
                         "Server should load the same public key")
        self.assertEqual(original_client_key, self.client.client_public_key, 
                         "Client should load the same public key")


if __name__ == '__main__':
    unittest.main()

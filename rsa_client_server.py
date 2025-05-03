"""
RSA Encrypted Client-Server Communication System
==============================================

A secure client-server application implementing RSA encryption from scratch.
All communications between client and server are encrypted using custom RSA implementation.

Features:
- Custom RSA encryption/decryption implementation (no crypto libraries)
- Socket-based client-server communication
- Command processing system for various services
- Comprehensive key generation and management
- Clean architecture with separation of concerns

Author: Amit Mondal
Date: May 3, 2025
"""

import socket
import json
import math
import random
import threading
import time
import os
import sys
from typing import Dict, Tuple, List, Union, Optional, Callable

# ====================== RSA Implementation ======================

class RSA:
    """
    Custom implementation of RSA encryption algorithm.
    Provides methods for key generation, encryption, and decryption.
    """
    
    @staticmethod
    def is_prime(n: int, k: int = 5) -> bool:
        """
        Miller-Rabin primality test.
        
        Args:
            n: Number to test for primality
            k: Number of rounds of testing
            
        Returns:
            bool: True if probably prime, False if definitely composite
        """
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True
            
        # Find r and d such that n-1 = 2^r * d, where d is odd
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1
            
        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
                
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
                
        return True
        
    @staticmethod
    def generate_prime(bits: int) -> int:
        """
        Generate a prime number with specified bit length.
        
        Args:
            bits: Bit length of the prime number
            
        Returns:
            int: A prime number
        """
        while True:
            # Generate a random odd number of the desired bit length
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if RSA.is_prime(p, 10):  # Higher k for better certainty
                return p
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm to find gcd and coefficients.
        
        Args:
            a, b: Integers for which to find gcd and coefficients
            
        Returns:
            Tuple[int, int, int]: (gcd, x, y) where gcd = ax + by
        """
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSA.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    @staticmethod
    def mod_inverse(e: int, phi: int) -> int:
        """
        Find the modular inverse of e modulo phi.
        
        Args:
            e: The number to find inverse for
            phi: The modulus
            
        Returns:
            int: The modular inverse of e
        """
        gcd, x, _ = RSA.extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % phi + phi) % phi
    
    @staticmethod
    def generate_keypair(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate RSA key pair.
        
        Args:
            bits: Bit length of each prime factor (so key length is ~2*bits)
            
        Returns:
            Tuple[Tuple[int, int], Tuple[int, int]]: ((e, n), (d, n))
            representing public and private keys
        """
        # Generate two distinct primes
        p = RSA.generate_prime(bits // 2)
        q = RSA.generate_prime(bits // 2)
        
        # Ensure p and q are different
        while p == q:
            q = RSA.generate_prime(bits // 2)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Common value for e is 65537
        e = 65537
        
        # Ensure e and phi are coprime
        while math.gcd(e, phi) != 1:
            e = random.randrange(2, phi)
        
        # Compute the private key d
        d = RSA.mod_inverse(e, phi)
        
        # Return public key (e, n) and private key (d, n)
        return ((e, n), (d, n))
    
    @staticmethod
    def encrypt(message: Union[str, int], public_key: Tuple[int, int]) -> List[int]:
        """
        Encrypt a message using RSA public key.

        Args:
            message: The message to encrypt (string or integer)
            public_key: Tuple (e, n) representing RSA public key
            
        Returns:
            List[int]: List of encrypted blocks
        """
        e, n = public_key
        
        # Convert string to integer if needed
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
            
            # Calculate block size for encryption
            # We need to ensure each block < n
            # Using bytes as the block unit
            block_size = (n.bit_length() - 1) // 8  # conservative block size
            
            if block_size < 1:
                block_size = 1  # Ensure at least 1 byte per block
                
            # Split message into blocks and encrypt each block
            encrypted_blocks = []
            for i in range(0, len(message_bytes), block_size):
                block = message_bytes[i:i+block_size]
                block_int = int.from_bytes(block, 'big')
                
                # Ensure block is smaller than n
                if block_int >= n:
                    raise ValueError("Block size too large for the given key")
                    
                # Encrypt: c = m^e mod n
                encrypted_block = pow(block_int, e, n)
                encrypted_blocks.append(encrypted_block)
                
            return encrypted_blocks
        else:
            # Encrypt a single integer
            return [pow(message, e, n)]
    
    @staticmethod
    def decrypt(encrypted_blocks: List[int], private_key: Tuple[int, int], 
                output_as_string: bool = True) -> Union[str, List[int]]:
        """
        Decrypt encrypted blocks using RSA private key.

        Args:
            encrypted_blocks: List of encrypted integer blocks
            private_key: Tuple (d, n) representing RSA private key
            output_as_string: Whether to return the result as a string
            
        Returns:
            Union[str, List[int]]: Decrypted message as string or list of integers
        """
        d, n = private_key
        
        # Decrypt each block
        decrypted_blocks = []
        for block in encrypted_blocks:
            # Decrypt: m = c^d mod n
            decrypted_block = pow(block, d, n)
            decrypted_blocks.append(decrypted_block)
        
        if output_as_string:
            # Convert decrypted blocks to bytes and then to string
            bytes_list = []
            for block in decrypted_blocks:
                # Calculate the minimum number of bytes needed to represent this block
                block_bytes = block.to_bytes((block.bit_length() + 7) // 8, 'big')
                bytes_list.append(block_bytes)
            
            try:
                return b''.join(bytes_list).decode('utf-8')
            except UnicodeDecodeError:
                return "Error: Could not decode decrypted message"
        else:
            return decrypted_blocks


# ====================== Key Management ======================

class KeyManager:
    """
    Handles RSA key generation, storage, and retrieval.
    """
    
    def __init__(self, key_dir: str = "keys"):
        """
        Initialize KeyManager.
        
        Args:
            key_dir: Directory to store keys
        """
        self.key_dir = key_dir
        os.makedirs(key_dir, exist_ok=True)
        
    def generate_and_save_keys(self, name: str, bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate and save a new RSA key pair.
        
        Args:
            name: Name identifier for the key pair
            bits: Bit length for the keys
            
        Returns:
            Tuple[Tuple[int, int], Tuple[int, int]]: Public and private keys
        """
        public_key, private_key = RSA.generate_keypair(bits)
        
        # Save public key
        with open(os.path.join(self.key_dir, f"{name}_public.json"), 'w') as f:
            json.dump({"e": public_key[0], "n": public_key[1]}, f)
            
        # Save private key
        with open(os.path.join(self.key_dir, f"{name}_private.json"), 'w') as f:
            json.dump({"d": private_key[0], "n": private_key[1]}, f)
            
        return public_key, private_key
    
    def load_public_key(self, name: str) -> Tuple[int, int]:
        """
        Load public key from file.
        
        Args:
            name: Name identifier for the key
            
        Returns:
            Tuple[int, int]: Public key as (e, n)
        """
        try:
            with open(os.path.join(self.key_dir, f"{name}_public.json"), 'r') as f:
                key_data = json.load(f)
                return (key_data["e"], key_data["n"])
        except FileNotFoundError:
            raise FileNotFoundError(f"Public key '{name}' not found")
    
    def load_private_key(self, name: str) -> Tuple[int, int]:
        """
        Load private key from file.
        
        Args:
            name: Name identifier for the key
            
        Returns:
            Tuple[int, int]: Private key as (d, n)
        """
        try:
            with open(os.path.join(self.key_dir, f"{name}_private.json"), 'r') as f:
                key_data = json.load(f)
                return (key_data["d"], key_data["n"])
        except FileNotFoundError:
            raise FileNotFoundError(f"Private key '{name}' not found")


# ====================== Protocol Implementation ======================

class SecureProtocol:
    """
    Protocol for secure communication between client and server.
    Handles message formatting, encryption, and decryption.
    """
    
    @staticmethod
    def format_message(message_type: str, payload: Dict) -> Dict:
        """
        Format a message according to the protocol.
        
        Args:
            message_type: Type of message (e.g., "request", "response")
            payload: Message data
            
        Returns:
            Dict: Formatted message
        """
        return {
            "type": message_type,
            "timestamp": time.time(),
            "payload": payload
        }
    
    @staticmethod
    def encrypt_message(message: Dict, public_key: Tuple[int, int]) -> Dict:
        """
        Encrypt a message for transmission.
        
        Args:
            message: Message to encrypt
            public_key: RSA public key of the recipient
            
        Returns:
            Dict: Encrypted message
        """
        message_str = json.dumps(message)
        encrypted_blocks = RSA.encrypt(message_str, public_key)
        
        return {
            "encrypted": True,
            "blocks": encrypted_blocks
        }
    
    @staticmethod
    def decrypt_message(encrypted_message: Dict, private_key: Tuple[int, int]) -> Dict:
        """
        Decrypt a received message.
        
        Args:
            encrypted_message: Encrypted message
            private_key: RSA private key
            
        Returns:
            Dict: Decrypted message
        """
        if not encrypted_message.get("encrypted", False):
            return encrypted_message
            
        encrypted_blocks = encrypted_message["blocks"]
        decrypted_str = RSA.decrypt(encrypted_blocks, private_key)
        
        try:
            return json.loads(decrypted_str)
        except json.JSONDecodeError:
            raise ValueError("Failed to decode decrypted message")
    
    @staticmethod
    def send_message(sock: socket.socket, message: Dict) -> None:
        """
        Send a message over a socket.
        
        Args:
            sock: Socket to send through
            message: Message to send
        """
        # Convert message to JSON string
        message_json = json.dumps(message)
        
        # Prefix with message length for proper framing
        message_bytes = message_json.encode('utf-8')
        length_prefix = len(message_bytes).to_bytes(4, byteorder='big')
        
        # Send length prefix followed by message
        sock.sendall(length_prefix + message_bytes)
    
    @staticmethod
    def receive_message(sock: socket.socket) -> Dict:
        """
        Receive a message from a socket.
        
        Args:
            sock: Socket to receive from
            
        Returns:
            Dict: Received message
        """
        # Receive length prefix
        length_prefix = sock.recv(4)
        if not length_prefix:
            raise ConnectionError("Connection closed by peer")
            
        message_length = int.from_bytes(length_prefix, byteorder='big')
        
        # Receive message data in chunks
        chunks = []
        bytes_received = 0
        while bytes_received < message_length:
            chunk = sock.recv(min(4096, message_length - bytes_received))
            if not chunk:
                raise ConnectionError("Connection closed by peer")
            chunks.append(chunk)
            bytes_received += len(chunk)
            
        # Combine chunks and parse JSON
        message_bytes = b''.join(chunks)
        message_json = message_bytes.decode('utf-8')
        
        return json.loads(message_json)


# ====================== Server Implementation ======================

class Server:
    """
    Secure server that accepts client connections and processes requests.
    All communication is encrypted using RSA.
    """
    
    def __init__(self, host: str = 'localhost', port: int = 8080, key_size: int = 1024):
        """
        Initialize the server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            key_size: Size of RSA keys in bits
        """
        self.host = host
        self.port = port
        self.key_manager = KeyManager()
        self.key_size = key_size
        self.running = False
        self.server_socket = None
        self.clients = {}  # Maps client addresses to their public keys
        self.command_handlers = self._register_commands()
        
    def _register_commands(self) -> Dict[str, Callable]:
        """
        Register command handlers.
        
        Returns:
            Dict[str, Callable]: Mapping of command names to handler functions
        """
        return {
            "echo": self._handle_echo,
            "time": self._handle_time,
            "calc": self._handle_calc,
            "info": self._handle_info,
            "help": self._handle_help
        }
        
    def _handle_echo(self, data: Dict) -> Dict:
        """Handle echo command by returning the message."""
        return {"result": data.get("message", ""), "status": "success"}
        
    def _handle_time(self, data: Dict) -> Dict:
        """Handle time command by returning current server time."""
        format_str = data.get("format", "%Y-%m-%d %H:%M:%S")
        try:
            return {
                "result": time.strftime(format_str), 
                "timestamp": time.time(),
                "status": "success"
            }
        except ValueError:
            return {"error": "Invalid time format", "status": "error"}
        
    def _handle_calc(self, data: Dict) -> Dict:
        """Handle calculation command."""
        operation = data.get("operation")
        a = data.get("a")
        b = data.get("b")
        
        if None in (operation, a, b):
            return {"error": "Missing parameters", "status": "error"}
        
        try:
            a, b = float(a), float(b)
            result = None
            
            if operation == "add":
                result = a + b
            elif operation == "subtract":
                result = a - b
            elif operation == "multiply":
                result = a * b
            elif operation == "divide":
                if b == 0:
                    return {"error": "Division by zero", "status": "error"}
                result = a / b
            else:
                return {"error": f"Unknown operation: {operation}", "status": "error"}
                
            return {"result": result, "status": "success"}
        except ValueError:
            return {"error": "Invalid numeric parameters", "status": "error"}
        
    def _handle_info(self, data: Dict) -> Dict:
        """Handle server info command."""
        return {
            "server": "RSA Encrypted Server",
            "version": "1.0.0",
            "encryption": "RSA",
            "key_size": self.key_size,
            "active_clients": len(self.clients),
            "uptime": time.time() - self.start_time,
            "status": "success"
        }
        
    def _handle_help(self, data: Dict) -> Dict:
        """Handle help command by returning available commands."""
        return {
            "available_commands": list(self.command_handlers.keys()),
            "usage": {
                "echo": {"message": "text to echo"},
                "time": {"format": "(optional) strftime format string"},
                "calc": {"operation": "add/subtract/multiply/divide", "a": "first number", "b": "second number"},
                "info": "No parameters needed",
                "help": "No parameters needed"
            },
            "status": "success"
        }
        
    def start(self) -> None:
        """Start the server and listen for connections."""
        # Generate server keys if they don't exist
        try:
            self.server_public_key = self.key_manager.load_public_key("server")
            self.server_private_key = self.key_manager.load_private_key("server")
            print("Loaded existing server keys")
        except FileNotFoundError:
            print("Generating new server keys...")
            self.server_public_key, self.server_private_key = self.key_manager.generate_and_save_keys(
                "server", self.key_size
            )
            print("Server keys generated")
            
        # Create and configure server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        self.running = True
        self.start_time = time.time()
        
        print(f"Server started on {self.host}:{self.port}")
        print(f"Public key (e, n): ({self.server_public_key[0]}, {self.server_public_key[1]})")
        
        try:
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"New connection from {client_address[0]}:{client_address[1]}")
                    
                    # Start a new thread to handle this client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except Exception as e:
                    print(f"Error accepting connection: {e}")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("Server stopped")
    
    def handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        """
        Handle communication with a client.
        
        Args:
            client_socket: Socket connected to the client
            client_address: Client's address as (host, port)
        """
        try:
            # First, exchange keys
            self._key_exchange(client_socket, client_address)
            
            # Now handle client requests
            while self.running:
                try:
                    # Receive encrypted message
                    encrypted_message = SecureProtocol.receive_message(client_socket)
                    
                    # Decrypt message
                    message = SecureProtocol.decrypt_message(
                        encrypted_message, 
                        self.server_private_key
                    )
                    
                    # Process message
                    if message["type"] == "request":
                        response = self._process_request(message["payload"])
                        
                        # Format and encrypt response
                        response_message = SecureProtocol.format_message("response", response)
                        encrypted_response = SecureProtocol.encrypt_message(
                            response_message,
                            self.clients[client_address]  # Client's public key
                        )
                        
                        # Send encrypted response
                        SecureProtocol.send_message(client_socket, encrypted_response)
                        
                    else:
                        print(f"Received unknown message type: {message['type']}")
                except ConnectionError:
                    break
                except Exception as e:
                    print(f"Error handling client {client_address}: {e}")
                    break
        finally:
            # Clean up
            if client_address in self.clients:
                del self.clients[client_address]
            client_socket.close()
            print(f"Connection with {client_address[0]}:{client_address[1]} closed")
    
    def _key_exchange(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        """
        Perform key exchange with client.
        
        Args:
            client_socket: Socket connected to the client
            client_address: Client's address
        """
        try:
            # Send server's public key
            server_key_message = {
                "type": "key_exchange",
                "public_key": {
                    "e": self.server_public_key[0],
                    "n": self.server_public_key[1]
                }
            }
            SecureProtocol.send_message(client_socket, server_key_message)
            
            # Receive client's public key
            client_key_message = SecureProtocol.receive_message(client_socket)
            if client_key_message["type"] != "key_exchange":
                raise ValueError("Expected key exchange message from client")
                
            client_public_key = (
                client_key_message["public_key"]["e"],
                client_key_message["public_key"]["n"]
            )
            
            # Store client's public key
            self.clients[client_address] = client_public_key
            
            print(f"Key exchange completed with {client_address[0]}:{client_address[1]}")
        except Exception as e:
            print(f"Key exchange failed with {client_address}: {e}")
            raise
    
    def _process_request(self, request: Dict) -> Dict:
        """
        Process a client request.
        
        Args:
            request: Request data
            
        Returns:
            Dict: Response data
        """
        command = request.get("command")
        if not command:
            return {"error": "No command specified", "status": "error"}
            
        handler = self.command_handlers.get(command)
        if not handler:
            return {"error": f"Unknown command: {command}", "status": "error"}
            
        try:
            return handler(request)
        except Exception as e:
            return {"error": f"Error processing command: {str(e)}", "status": "error"}


# ====================== Client Implementation ======================

class Client:
    """
    Secure client that communicates with the server using RSA encryption.
    """
    
    def __init__(self, server_host: str = 'localhost', server_port: int = 8080, key_size: int = 1024):
        """
        Initialize the client.
        
        Args:
            server_host: Server hostname
            server_port: Server port
            key_size: Size of RSA keys in bits
        """
        self.server_host = server_host
        self.server_port = server_port
        self.key_manager = KeyManager()
        self.key_size = key_size
        self.socket = None
        self.server_public_key = None
        self.connected = False
        
    def connect(self) -> bool:
        """
        Connect to the server and perform key exchange.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        if self.connected:
            return True
            
        # Generate client keys if they don't exist
        try:
            self.client_public_key = self.key_manager.load_public_key("client")
            self.client_private_key = self.key_manager.load_private_key("client")
            print("Loaded existing client keys")
        except FileNotFoundError:
            print("Generating new client keys...")
            self.client_public_key, self.client_private_key = self.key_manager.generate_and_save_keys(
                "client", self.key_size
            )
            print("Client keys generated")
        
        try:
            # Connect to server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            
            # Perform key exchange
            self._key_exchange()
            
            self.connected = True
            print(f"Connected to server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            if self.socket:
                self.socket.close()
                self.socket = None
            return False
    
    def disconnect(self) -> None:
        """Disconnect from the server."""
        if self.connected and self.socket:
            self.socket.close()
            self.socket = None
            self.connected = False
            print("Disconnected from server")
    
    def _key_exchange(self) -> None:
        """Perform key exchange with server."""
        try:
            # Receive server's public key
            server_key_message = SecureProtocol.receive_message(self.socket)
            if server_key_message["type"] != "key_exchange":
                raise ValueError("Expected key exchange message from server")
                
            self.server_public_key = (
                server_key_message["public_key"]["e"],
                server_key_message["public_key"]["n"]
            )
            
            # Send client's public key
            client_key_message = {
                "type": "key_exchange",
                "public_key": {
                    "e": self.client_public_key[0],
                    "n": self.client_public_key[1]
                }
            }
            SecureProtocol.send_message(self.socket, client_key_message)
            
            print("Key exchange completed with server")
        except Exception as e:
            print(f"Key exchange failed: {e}")
            raise
    
    def send_request(self, command: str, **params) -> Dict:
        """
        Send a request to the server and get the response.
        
        Args:
            command: Command to execute
            **params: Command parameters
            
        Returns:
            Dict: Server response
        """
        if not self.connected:
            if not self.connect():
                return {"error": "Not connected to server", "status": "error"}
        
        # Prepare request
        request_payload = {"command": command, **params}
        request_message = SecureProtocol.format_message("request", request_payload)
        
        # Encrypt request
        encrypted_request = SecureProtocol.encrypt_message(request_message, self.server_public_key)
        
        try:
            # Send encrypted request
            SecureProtocol.send_message(self.socket, encrypted_request)
            
            # Receive encrypted response
            encrypted_response = SecureProtocol.receive_message(self.socket)
            
            # Decrypt response
            response = SecureProtocol.decrypt_message(encrypted_response, self.client_private_key)
            
            return response["payload"]
        except Exception as e:
            print(f"Error sending request: {e}")
            self.disconnect()
            return {"error": f"Communication error: {str(e)}", "status": "error"}


# ====================== Command Line Interface ======================

class ClientCLI:
    """
    Command-line interface for the client.
    """
    
    def __init__(self, client: Client):
        """
        Initialize the CLI.
        
        Args:
            client: Client instance
        """
        self.client = client
        self.commands = {
            "connect": self._connect,
            "disconnect": self._disconnect,
            "echo": self._echo,
            "time": self._time,
            "calc": self._calc,
            "info": self._info,
            "help": self._help,
            "exit": self._exit
        }
        self.running = False
        
    def start(self) -> None:
        """Start the command-line interface."""
        self.running = True
        
        print("===============================================")
        print("  RSA Encrypted Client - Command Line Interface")
        print("===============================================")
        print("Type 'help' for available commands")
        
        while self.running:
            try:
                cmd_line = input("\n> ").strip()
                if not cmd_line:
                    continue
                    
                parts = cmd_line.split()
                cmd = parts[0].lower()
                args = parts[1:]
                
                if cmd in self.commands:
                    self.commands[cmd](args)
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type 'help' for available commands")
            except KeyboardInterrupt:
                print("\nInterrupted by user")
                self._exit([])
            except Exception as e:
                print(f"Error: {e}")
                
    def _connect(self, args: List[str]) -> None:
        """Handle connect command."""
        if self.client.connected:
            print("Already connected to server")
            return
            
        print("Connecting to server...")
        if self.client.connect():
            print("Connection successful")
        else:
            print("Connection failed")
    
    def _disconnect(self, args: List[str]) -> None:
        """Handle disconnect command."""
        if not self.client.connected:
            print("Not connected to server")
            return
            
        self.client.disconnect()
        print("Disconnected from server")
    
    def _echo(self, args: List[str]) -> None:
        """Handle echo command."""
        if not self.client.connected:
            print("Not connected to server")
            return
            
        message = " ".join(args)
        response = self.client.send_request("echo", message=message)
        
        if response["status"] == "success":
            print(f"Server echoed: {response['result']}")
        else:
            print(f"Error: {response.get('error', 'Unknown error')}")
    
    def _time(self, args: List[str]) -> None:
        """Handle time command."""
        if not self.client.connected:
            print("Not connected to server")
            return
            
        format_str = " ".join(args) if args else "%Y-%m-%d %H:%M:%S"
        response = self.client.send_request("time", format=format_str)
        
        if response["status"] == "success":
            print(f"Server time: {response['result']}")
        else:
            print(f"Error: {response.get('error', 'Unknown error')}")
    
    def _calc(self, args: List[str]) -> None:
        """Handle calc command."""
        if not self.client.connected:
            print("Not connected to server")
            return
            
        if len(args) != 3:
            print("Usage: calc <operation> <number1> <number2>")
            print("Operations: add, subtract, multiply, divide")
            return
            
        operation, a, b = args
        response = self.client.send_request("calc", operation=operation, a=a, b=b)
        
        if response["status"] == "success":
            print(f"Result: {response['result']}")
        else:
            print(f"Error: {response.get('error', 'Unknown error')}")
    
    def _info(self, args: List[str]) -> None:
        """Handle info command."""
        if not self.client.connected:
            print("Not connected to server")
            return
            
        response = self.client.send_request("info")
        
        if response["status"] == "success":
            print("\nServer Information:")
            print("-------------------")
            for key, value in response.items():
                if key != "status":
                    print(f"{key.capitalize()}: {value}")
        else:
            print(f"Error: {response.get('error', 'Unknown error')}")
    
    def _help(self, args: List[str]) -> None:
        """Handle help command."""
        print("\nAvailable Commands:")
        print("------------------")
        print("connect     - Connect to the server")
        print("disconnect  - Disconnect from the server")
        print("echo <msg>  - Send message to echo")
        print("time [fmt]  - Get server time (optional format)")
        print("calc <op> <a> <b> - Calculate: add, subtract, multiply, divide")
        print("info        - Get server information")
        print("help        - Show this help message")
        print("exit        - Exit the client")
        
        if self.client.connected:
            # Get server-side commands
            response = self.client.send_request("help")
            if response["status"] == "success":
                print("\nServer Commands:")
                print("---------------")
                for cmd, usage in response["usage"].items():
                    if isinstance(usage, dict):
                        params = ", ".join(f"{k}={v}" for k, v in usage.items())
                        print(f"{cmd} - Parameters: {params}")
                    else:
                        print(f"{cmd} - {usage}")
    
    def _exit(self, args: List[str]) -> None:
        """Handle exit command."""
        if self.client.connected:
            self.client.disconnect()
            
        self.running = False
        print("Exiting client")


# ====================== Main Entry Points ======================

def start_server(host: str = 'localhost', port: int = 8080, key_size: int = 1024) -> None:
    """
    Start the server application.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        key_size: Size of RSA keys in bits
    """
    server = Server(host, port, key_size)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer stopping...")
    finally:
        server.stop()

def start_client(server_host: str = 'localhost', server_port: int = 8080, key_size: int = 1024) -> None:
    """
    Start the client application.
    
    Args:
        server_host: Server hostname
        server_port: Server port
        key_size: Size of RSA keys in bits
    """
    client = Client(server_host, server_port, key_size)
    cli = ClientCLI(client)
    
    try:
        cli.start()
    except KeyboardInterrupt:
        print("\nClient stopping...")
    finally:
        if client.connected:
            client.disconnect()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RSA Encrypted Client-Server Application")
    subparsers = parser.add_subparsers(dest="mode", help="Mode of operation")
    
    # Server arguments
    server_parser = subparsers.add_parser("server", help="Run in server mode")
    server_parser.add_argument("--host", default="localhost", help="Host to bind to")
    server_parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    server_parser.add_argument("--key-size", type=int, default=1024, help="RSA key size in bits")
    
    # Client arguments
    client_parser = subparsers.add_parser("client", help="Run in client mode")
    client_parser.add_argument("--host", default="localhost", help="Server hostname")
    client_parser.add_argument("--port", type=int, default=8080, help="Server port")
    client_parser.add_argument("--key-size", type=int, default=1024, help="RSA key size in bits")
    
    args = parser.parse_args()
    
    if args.mode == "server":
        start_server(args.host, args.port, args.key_size)
    elif args.mode == "client":
        start_client(args.host, args.port, args.key_size)
    else:
        parser.print_help()
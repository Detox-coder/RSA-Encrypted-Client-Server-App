# 🔐 RSA Encrypted Client-Server System

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A secure client-server application featuring RSA encryption implemented from scratch. This project demonstrates fundamental cryptographic principles, network programming, and secure communications without relying on external cryptographic libraries.

## ✨ Features

- **Custom RSA Implementation**: Complete implementation of RSA encryption algorithm from first principles
- **Socket-Based Communication**: Reliable client-server communication using Python sockets
- **Secure Protocol**: All messages encrypted with RSA for secure transmission
- **Key Management**: Generation, storage, and exchange of cryptographic keys
- **Command Processing System**: Extensible command architecture
- **Interactive CLI**: User-friendly command-line interface for the client
- **Zero Dependencies**: Built entirely with Python standard library

## 📁 Project Structure

```
.
├── README.md
├── requirements.txt (empty - only standard library used)
├── keys/                  # Directory for storing RSA keys
│   ├── client_private.json  # Client's private key
│   ├── client_public.json   # Client's public key
│   ├── server_private.json  # Server's private key
│   └── server_public.json   # Server's public key
├── rsa_client_server.py   # Main application code
└── tests/                 # Unit tests
    ├── test_rsa.py          # RSA implementation tests
    ├── test_protocol.py     # Protocol tests
    └── test_integration.py  # End-to-end tests
```

## 🔑 How RSA Encryption Works

This project implements the RSA (Rivest–Shamir–Adleman) algorithm from scratch:

### Key Generation

```
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│  Generate Primes   │    │  Calculate Values  │    │ Create Key Pairs   │
│                    │    │                    │    │                    │
│  p = large prime   │───▶│  n = p × q         │───▶│  Public: (e, n)    │
│  q = large prime   │    │  φ(n) = (p-1)(q-1) │    │  Private: (d, n)   │
└────────────────────┘    └────────────────────┘    └────────────────────┘
```

1. **Prime Generation**:
   - Generate two large prime numbers (p and q) using Miller-Rabin primality testing
   - Ensure p ≠ q for security

2. **Key Calculation**:
   - Calculate modulus: n = p × q
   - Calculate Euler's totient function: φ(n) = (p-1) × (q-1)
   - Choose public exponent e: typically 65537, ensuring gcd(e, φ(n)) = 1
   - Calculate private exponent d: find d such that (d × e) % φ(n) = 1 using Extended Euclidean Algorithm
   - Public key is (e, n), private key is (d, n)

### Encryption & Decryption

```
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│    Plain Text      │    │    Encryption      │    │    Cipher Text     │
│                    │───▶│                    │───▶│                    │
│  "Hello World"     │    │  c = m^e mod n     │    │  [encrypted data]  │
└────────────────────┘    └────────────────────┘    └────────────────────┘
                                                              │
┌────────────────────┐    ┌────────────────────┐              │
│    Plain Text      │    │    Decryption      │              │
│                    │◀───│                    │◀─────────────┘
│  "Hello World"     │    │  m = c^d mod n     │
└────────────────────┘    └────────────────────┘
```

1. **Encryption**:
   - Split message into blocks that fit within the key size
   - For each block m, calculate ciphertext: c = m^e mod n
   - Combine encrypted blocks

2. **Decryption**:
   - For each encrypted block c, calculate plaintext: m = c^d mod n
   - Combine blocks to recover the original message

## 🚀 Installation

No external dependencies required! This project uses only the Python standard library.

```bash
# Clone the repository
git clone https://github.com/Detox-coder/RSA-Encrypted-Client-Server-App.git
cd rsa-encrypted-client-server

# Make sure you have Python 3.6+
python --version
```

## 📝 Usage

### Starting the Server

```bash
python rsa_client_server.py server [--host HOST] [--port PORT] [--key-size SIZE]
```

Example:
```bash
python rsa_client_server.py server --port 8888 --key-size 2048
```

### Starting the Client

```bash
python rsa_client_server.py client [--host HOST] [--port PORT] [--key-size SIZE]
```

Example:
```bash
python rsa_client_server.py client --host 192.168.1.100 --port 8888
```

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--host` | Host address to bind/connect to | localhost |
| `--port` | Port number to use | 8080 |
| `--key-size` | Size of RSA keys in bits | 1024 |

### 💻 Client Commands

Once the client is running, you can use the following commands:

| Command | Description | Example |
|---------|-------------|---------|
| `connect` | Connect to the server | `connect` |
| `disconnect` | Disconnect from the server | `disconnect` |
| `echo <message>` | Send a message for echo | `echo Hello World` |
| `time [format]` | Get server time | `time %H:%M:%S` |
| `calc <op> <a> <b>` | Perform calculation | `calc multiply 3.14 2` |
| `info` | Get server information | `info` |
| `help` | Show available commands | `help` |
| `exit` | Exit the client | `exit` |

### 📋 Example Session

```
===============================================
  RSA Encrypted Client - Command Line Interface
===============================================
Type 'help' for available commands

> connect
Generating new client keys...
Client keys generated
Connecting to server...
Key exchange completed with server
Connected to server at localhost:8080
Connection successful

> info
Server Information:
-------------------
Server: RSA Encrypted Server
Version: 1.0.0
Encryption: RSA
Key_size: 1024
Active_clients: 1
Uptime: 45.72

> echo Hello, encrypted world!
Server echoed: Hello, encrypted world!

> calc multiply 6.5 7
Result: 45.5

> time %Y-%m-%d %H:%M:%S
Server time: 2025-05-03 14:32:45

> exit
Disconnecting from server...
Exiting client
```

## 🔒 Security Considerations

This implementation is for educational purposes and demonstrates the principles of RSA encryption. For production use, consider:

| Consideration | Description |
|---------------|-------------|
| 🛡️ **Established Libraries** | Use battle-tested crypto libraries like `cryptography` or `PyNaCl` |
| 🔄 **Key Management** | Implement proper key rotation and secure storage |
| 🔀 **Forward Secrecy** | Add perfect forward secrecy with ephemeral keys |
| ✅ **Authentication** | Include message authentication codes (MACs) |
| 🔑 **Session Handling** | Implement secure session management |
| 📏 **Key Size** | Use at least 2048-bit keys in production |
| 🧪 **Side-Channel Protection** | Guard against timing attacks and other side-channels |

## ⚡ Performance Notes

RSA operations, especially key generation and decryption of large messages, can be computationally intensive. For optimal performance:

```
┌───────────────────────────────────────────────────────────────────────┐
│                   RSA Performance Considerations                      │
├───────────────────────────┬───────────────────────────────────────────┤
│ Operation                 │ Performance Characteristics               │
├───────────────────────────┼───────────────────────────────────────────┤
│ Key Generation            │ Slow - Finding large primes is expensive  │
│ Encryption                │ Moderate - Uses public key (e)            │
│ Decryption                │ Slow - Uses private key (d)               │
│ Processing Large Messages │ Slow - Messages must be split into blocks │
└───────────────────────────┴───────────────────────────────────────────┘
```

Performance recommendations:
- Use appropriate key sizes (1024-2048 bits for educational purposes)
- Consider message chunking for larger data transmissions
- For production systems, consider hybrid encryption (RSA for key exchange, symmetric for data)
- Generate keys in advance for time-sensitive applications

## 🧰 Technical Details

### Core Components

1. **RSA Class**
   - Primality testing with Miller-Rabin algorithm
   - Extended Euclidean Algorithm for modular inverse
   - Block-based processing for messages

2. **KeyManager Class**
   - Key generation and storage
   - JSON-based key serialization
   - Easy key retrieval

3. **SecureProtocol Class**
   - Message formatting and framing
   - Encryption/decryption pipeline
   - Socket communication handling

4. **Server Class**
   - Multi-threaded connection handling
   - Command processing architecture
   - Client key management

5. **Client Class**
   - Server connection management
   - Request/response handling
   - User-friendly CLI

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

- 🐛 **Report bugs**: Open an issue describing the bug and how to reproduce it
- 💡 **Suggest features**: Have ideas for improvements? Share them in issues
- 🛠️ **Submit PRs**: Implement fixes or add new features
- 📚 **Improve docs**: Help clarify or expand the documentation
- 📧 **Email:** amitmondalxii@gmail.com

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Based on fundamental principles of public-key cryptography introduced by Rivest, Shamir, and Adleman
- Inspired by educational implementations of RSA algorithms
- Special thanks to the open-source community for resources on cryptographic implementations

## 📚 Further Reading

- [RSA Algorithm - Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Understanding RSA Algorithm](https://simple.wikipedia.org/wiki/RSA_algorithm)
- [Network Socket Programming in Python](https://docs.python.org/3/library/socket.html)
- [Public Key Cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)

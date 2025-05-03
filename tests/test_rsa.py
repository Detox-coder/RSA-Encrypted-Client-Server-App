"""
Unit tests for the RSA encryption implementation.
These tests verify the correctness of the RSA algorithm implementation including:
- Prime number detection
- Key generation
- Encryption and decryption of various data types
- Edge cases and error handling
"""

import unittest
import sys
import os
import random
import string

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the RSA class from the main module
from rsa_client_server import RSA


class TestRSA(unittest.TestCase):
    """Test suite for the RSA encryption implementation."""

    def setUp(self):
        """Set up test environment before each test method."""
        # Generate a key pair for testing
        self.public_key, self.private_key = RSA.generate_keypair(bits=512)  # Smaller keys for faster tests
        
    def test_prime_detection(self):
        """Test the primality testing function."""
        # Known primes
        known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        for prime in known_primes:
            self.assertTrue(RSA.is_prime(prime), f"{prime} should be identified as prime")
            
        # Known non-primes
        known_non_primes = [1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21]
        for non_prime in known_non_primes:
            self.assertFalse(RSA.is_prime(non_prime), f"{non_prime} should be identified as non-prime")
    
    def test_key_generation(self):
        """Test that key generation produces valid RSA keys."""
        public_key, private_key = RSA.generate_keypair(bits=512)
        
        # Verify key structure
        self.assertEqual(len(public_key), 2, "Public key should be a tuple of (e, n)")
        self.assertEqual(len(private_key), 2, "Private key should be a tuple of (d, n)")
        
        # Verify that both keys share the same modulus
        self.assertEqual(public_key[1], private_key[1], "Public and private keys should share the same modulus")
        
        # Verify key properties
        e, n = public_key
        d, _ = private_key
        
        self.assertGreater(n, 0, "Modulus should be positive")
        self.assertGreater(e, 0, "Public exponent should be positive")
        self.assertGreater(d, 0, "Private exponent should be positive")
        
        # Test that e and d are modular inverses of each other mod φ(n)
        # This is hard to test directly since we don't know φ(n), but we can test that e*d ≡ 1 (mod φ(n)) indirectly
        # by encrypting and decrypting a test message
        test_message = 42
        encrypted = RSA.encrypt(test_message, public_key)
        decrypted = RSA.decrypt(encrypted, private_key, output_as_string=False)
        self.assertEqual(test_message, decrypted[0], "Encryption followed by decryption should recover the original message")
    
    def test_encrypt_decrypt_string(self):
        """Test encrypting and decrypting string messages."""
        test_messages = [
            "Hello, World!",
            "RSA Encryption Test",
            "Special characters: !@#$%^&*()",
            "".join(random.choice(string.ascii_letters + string.digits) for _ in range(100)),  # Random string
            "Unicode characters: 你好, こんにちは, مرحبا"
        ]
        
        for message in test_messages:
            encrypted = RSA.encrypt(message, self.public_key)
            decrypted = RSA.decrypt(encrypted, self.private_key)
            self.assertEqual(message, decrypted, f"Failed to correctly encrypt and decrypt: {message}")
    
    def test_encrypt_decrypt_integer(self):
        """Test encrypting and decrypting integer values."""
        test_values = [0, 1, 42, 123456, random.randint(1, 10000)]
        
        for value in test_values:
            encrypted = RSA.encrypt(value, self.public_key)
            decrypted = RSA.decrypt(encrypted, self.private_key, output_as_string=False)
            self.assertEqual(value, decrypted[0], f"Failed to correctly encrypt and decrypt integer: {value}")
    
    def test_large_message(self):
        """Test handling of messages larger than the modulus."""
        # Generate a large random string (much larger than one block can hold)
        large_message = "".join(random.choice(string.ascii_letters) for _ in range(1000))
        
        encrypted = RSA.encrypt(large_message, self.public_key)
        decrypted = RSA.decrypt(encrypted, self.private_key)
        
        self.assertEqual(large_message, decrypted, "Failed to correctly handle a large message")
        
        # Verify that multiple blocks were used
        n_bits = self.public_key[1].bit_length()
        block_size = (n_bits - 1) // 8  # Same calculation as in RSA.encrypt
        expected_min_blocks = len(large_message.encode('utf-8')) // block_size
        
        self.assertGreater(len(encrypted), 1, "Large message should be split into multiple blocks")
        self.assertGreaterEqual(len(encrypted), expected_min_blocks, 
                             f"Expected at least {expected_min_blocks} blocks for message size")
    
    def test_empty_string(self):
        """Test handling of empty string."""
        encrypted = RSA.encrypt("", self.public_key)
        decrypted = RSA.decrypt(encrypted, self.private_key)
        self.assertEqual("", decrypted, "Failed to correctly handle empty string")
    
    def test_mod_inverse(self):
        """Test the modular inverse calculation."""
        # Test cases where gcd(a, m) = 1
        test_cases = [
            (3, 11, 4),     # 3 * 4 ≡ 1 (mod 11)
            (7, 20, 3),     # 7 * 3 ≡ 1 (mod 20)
            (17, 3120, 2753) # 17 * 2753 ≡ 1 (mod 3120)
        ]
        
        for a, m, expected in test_cases:
            result = RSA.mod_inverse(a, m)
            self.assertEqual(expected, result, f"Modular inverse of {a} mod {m} should be {expected}, got {result}")
            self.assertEqual(1, (a * result) % m, f"{a} * {result} ≡ {(a * result) % m} ≠ 1 (mod {m})")
        
        # Test case where gcd(a, m) != 1
        with self.assertRaises(ValueError):
            RSA.mod_inverse(4, 8)  # gcd(4, 8) = 4 != 1, so no modular inverse exists
    
    def test_extended_gcd(self):
        """Test the extended GCD implementation."""
        test_cases = [
            (35, 15, 5, 1, -2),  # gcd(35, 15) = 5 = 35*1 + 15*(-2)
            (101, 13, 1, 4, -31),  # gcd(101, 13) = 1 = 101*4 + 13*(-31)
            (12, 8, 4, 0, 1)  # gcd(12, 8) = 4 = 12*0 + 8*1
        ]
        
        for a, b, expected_gcd, expected_x, expected_y in test_cases:
            gcd, x, y = RSA.extended_gcd(a, b)
            self.assertEqual(expected_gcd, gcd, f"GCD of {a} and {b} should be {expected_gcd}")
            self.assertEqual(expected_x, x, f"Coefficient x for {a} should be {expected_x}")
            self.assertEqual(expected_y, y, f"Coefficient y for {b} should be {expected_y}")
            self.assertEqual(gcd, a*x + b*y, f"Bezout's identity not satisfied: {gcd} != {a}*{x} + {b}*{y}")


if __name__ == '__main__':
    unittest.main()

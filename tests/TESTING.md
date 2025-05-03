# Testing Guide for RSA Encrypted Client-Server Application

This document provides comprehensive instructions for running and extending the test suite for the RSA Encrypted Client-Server Application.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
  - [Running All Tests](#running-all-tests)
  - [Running Specific Test Files](#running-specific-test-files)
  - [Running Individual Test Cases](#running-individual-test-cases)
- [Test Coverage](#test-coverage)
- [Adding New Tests](#adding-new-tests)
- [Troubleshooting](#troubleshooting)

## Overview

The test suite for this application follows a layered testing approach:

1. **Unit Tests**: Testing individual components in isolation
2. **Integration Tests**: Testing the interaction between components
3. **End-to-End Tests**: Testing the entire system from the client's perspective

The tests are implemented using Python's built-in `unittest` framework and follow standard testing patterns and best practices.

## Test Structure

The test suite is organized into three main files:

- **`test_rsa.py`**: Unit tests for the RSA encryption implementation
- **`test_protocol.py`**: Unit tests for the SecureProtocol communication layer
- **`test_integration.py`**: Integration tests for the complete client-server application

Each test file focuses on a specific layer of the application to ensure thorough test coverage while maintaining clear separation of concerns.

## Running Tests

### Prerequisites

Before running the tests, ensure you have:

1. Cloned the repository
2. Installed all required dependencies (typically with `pip install -r requirements.txt`)
3. Verified that the main application modules are correctly installed or accessible

### Running All Tests

To run the complete test suite, navigate to the project root directory and execute:

```bash
python -m unittest discover -s tests
```

This command will discover and run all test files in the `tests` directory.

### Running Specific Test Files

To run tests from a specific file, use one of the following commands:

```bash
# To test the RSA implementation
python -m unittest tests.test_rsa

# To test the SecureProtocol implementation
python -m unittest tests.test_protocol

# To test the integration between components
python -m unittest tests.test_integration
```

### Running Individual Test Cases

To run a specific test case, use the following format:

```bash
python -m unittest tests.test_file.TestClass.test_method
```

For example:

```bash
python -m unittest tests.test_rsa.TestRSA.test_encrypt_decrypt_string
```

## Test Coverage

The test suite provides comprehensive coverage of the application's functionality:

### RSA Tests (`test_rsa.py`)

- Prime number detection
- Key generation
- Encryption and decryption of various data types
- Mathematical operations (GCD, modular inverse)
- Edge cases and error handling

### Protocol Tests (`test_protocol.py`)

- Message formatting
- Message encryption and decryption
- Socket-based message transmission
- Error handling during communication

### Integration Tests (`test_integration.py`)

- Server startup and shutdown
- Client connection and reconnection
- Key exchange between client and server
- Command execution and response handling
- Multiple client connections
- Server restart scenarios
- Error handling at the system level

## Adding New Tests

### Creating a New Test Case

To add a new test case to an existing test file:

1. Identify the appropriate test file for your test
2. Create a new test method inside the relevant test class
3. Name your method with a `test_` prefix followed by a descriptive name
4. Implement the test following the Arrange-Act-Assert pattern
5. Document the purpose of your test in a docstring

Example:

```python
def test_new_feature(self):
    """Test that the new feature behaves as expected."""
    # Arrange - set up test data
    input_data = "test_data"
    
    # Act - execute the functionality being tested
    result = your_function(input_data)
    
    # Assert - verify the results
    self.assertEqual(expected_result, result)
```

### Creating a New Test File

To add a new test file for a different component:

1. Create a new Python file in the `tests` directory with a `test_` prefix
2. Import the necessary unittest modules and application components
3. Create a test class that inherits from `unittest.TestCase`
4. Implement `setUp` and `tearDown` methods if needed
5. Add your test methods to the class
6. Include a main block to allow running the file directly

Example:

```python
import unittest
from your_module import YourClass

class TestYourComponent(unittest.TestCase):
    def setUp(self):
        # Setup code that runs before each test
        self.instance = YourClass()
    
    def tearDown(self):
        # Cleanup code that runs after each test
        pass
    
    def test_feature(self):
        # Test implementation
        pass

if __name__ == '__main__':
    unittest.main()
```

## Troubleshooting

### Common Issues

#### Port Already in Use

If you encounter a "Port already in use" error:

```python
# Modify the server port in the setUp method
cls.server_port = 45679  # Choose an unused port
```

#### Test Timeouts

If tests are timing out:

1. Increase the sleep duration in tests that involve network communication
2. Check for resource leaks in the setUp/tearDown methods
3. Verify that all server instances are properly terminated after tests

#### Key Generation Taking Too Long

If key generation is slowing down your tests:

```python
# Reduce the key size for faster tests
cls.key_size = 512  # Smaller keys (not secure for production)
```

### Debug Mode

To run tests with more detailed output:

```bash
python -m unittest -v tests.test_file
```

The `-v` flag enables verbose mode, showing the result of each individual test.

### Isolating Test Dependencies

If you're having trouble isolating what's causing a test failure:

1. Run single tests in isolation
2. Add print statements to track execution flow
3. Use the Python debugger:

```bash
python -m pdb -m unittest tests.test_file.TestClass.test_method
```

---

## Contributing to the Test Suite

When contributing new tests or modifying existing ones:

1. Follow the established naming conventions and code style
2. Ensure each test focuses on testing a single aspect or behavior
3. Keep tests independent - one test should not depend on another
4. Add clear docstrings explaining what each test verifies
5. Avoid testing implementation details - focus on behavior
6. Run the full test suite before submitting changes

---

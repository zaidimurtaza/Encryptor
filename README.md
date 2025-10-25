# Simple Encryptor

A secure and easy-to-use AES-GCM encryption/decryption package for Python.

## Why Use Simple Encryptor?

- **No Key Management Hassle**: Just provide any key of your choice - no strict length requirements
- **Military-Grade Security**: Uses AES-GCM encryption (same standard used by banks and governments)
- **Zero Configuration**: Works out of the box with minimal setup
- **Cross-Platform**: Works on Windows, Mac, and Linux

## Quick Start

### Installation
```bash
pip install simple-encryptor
```

### Basic Usage

```python
from simple_encryptor import Encryptor

# Create an encryptor with your chosen key
encryptor = Encryptor("my-secret-key-123")

# Encrypt your data
data = "Hello, World!"
encrypted = encryptor.encrypt(data)
print(f"Encrypted: {encrypted}")

# Decrypt your data
decrypted = encryptor.decrypt(encrypted)
print(f"Decrypted: {decrypted}")
```

### Advanced Usage

```python
from simple_encryptor import Encryptor

# Initialize with your key
encryptor = Encryptor("your-secret-key")

# Encrypt sensitive data
sensitive_data = "This is confidential information"
encrypted_data = encryptor.encrypt(sensitive_data)

# Store or transmit the encrypted data
print(f"Encrypted: {encrypted_data}")

# Later, decrypt the data
decrypted_data = encryptor.decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data}")
```

## Key Features

- **Any Key Length**: Use any key you want - short or long, it doesn't matter
- **Automatic Key Derivation**: Your key is securely hashed using SHA-256 to meet encryption standards
- **AES-256-GCM Encryption**: Military-grade encryption with built-in authentication
- **Tamper Detection**: Built-in integrity checking prevents data tampering
- **Base64 Encoded Output**: Encrypted data is base64 encoded for easy storage and transmission

## Error Handling

The package includes comprehensive error handling:

```python
from simple_encryptor import Encryptor

try:
    encryptor = Encryptor("my-key")
    encrypted = encryptor.encrypt("sensitive data")
    decrypted = encryptor.decrypt(encrypted)
except ValueError as e:
    print(f"Invalid input: {e}")
except Exception as e:
    print(f"Encryption error: {e}")
```

## Perfect For

- Protecting sensitive configuration data
- Encrypting user data in applications
- Securing API keys and credentials
- Adding encryption to existing Python projects
- Protecting data in transit or at rest

## Requirements

- Python 3.8 or higher
- cryptography library (automatically installed)

## Installation

```bash
pip install simple-encryptor
```

## Version

Current version: 0.2.1

## License

MIT License - Use it freely in your projects!

## Contributing

Feel free to submit issues and enhancement requests!

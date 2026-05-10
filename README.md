# SHA-256

A pure Python implementation of the SHA-256 cryptographic hash algorithm.

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-Hash-green.svg)

## About the Project

SHA-256 is a clean implementation of the SHA-256 cryptographic hash algorithm in Python for educational purposes, demonstrating the principles of hash functions, bitwise operations, and low-level data processing.

### Features

- Complete implementation of the SHA-256 algorithm without external libraries
- Support for both string and byte data input
- Step-by-step data processing with buffering
- Proper message padding according to the standard
- `update()`, `digest()`, and `hexdigest()` methods like in standard hashlib
- Quick hashing functions: `sha256()` and `sha256_hex()`
- Built-in initialization constants (H0) and round constants (K)
- Implementation of all bitwise operations: rotation, XOR, AND, NOT
- Simple and clean code structure with detailed comments

### Usage Example

```python
from sha256 import sha256_hex

# Hashing a string
hash_value = sha256_hex("Hello")
print(hash_value)  # 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969

#  ECC Secure Messenger

A Python-based secure messaging application demonstrating Elliptic Curve Cryptography (ECC) concepts for end-to-end encryption, digital signatures, and Perfect Forward Secrecy.

##  Educational Context

This project was developed as part of a personal learning journey in the **Data Privacy (CSD3005)** course at **VIT Bhopal University**. The implementation demonstrates core cryptographic concepts taught in the course under the guidance of **Dr. Sajjad Ahmed**.

### Learning Objectives Covered
- **Elliptic Curve Cryptography (ECC)** fundamentals
- **End-to-End Encryption** using ECDH key exchange
- **Digital Signatures** with ECDSA
- **Perfect Forward Secrecy** through ephemeral key pairs
- **Secure key derivation** using HKDF
- **Authenticated encryption** with AES-GCM

##  Features

- ** ECC Key Generation**: Automatic SECP256R1 key pair generation
- ** Secure Key Exchange**: ECDH-based shared secret derivation
- ** End-to-End Encryption**: AES-256-GCM encryption with ephemeral keys
- ** Digital Signatures**: ECDSA message authentication
- ** Perfect Forward Secrecy**: Each message uses a unique ephemeral key pair
- ** Contact Management**: Secure public key fingerprint verification
- ** Message History**: Local message tracking with timestamps
- ** Interactive & Demo Modes**: Both educational demo and hands-on usage

##  Technical Implementation

### Cryptographic Components
- **Curve**: SECP256R1 (NIST P-256)
- **Key Exchange**: Elliptic Curve Diffie-Hellman (ECDH)
- **Signatures**: Elliptic Curve Digital Signature Algorithm (ECDSA)
- **Symmetric Encryption**: AES-256 in GCM mode
- **Key Derivation**: HKDF with SHA-256
- **Hashing**: SHA-256 for fingerprints and signatures

### Security Features
- **Perfect Forward Secrecy**: Ephemeral key pairs for each message
- **Message Authentication**: ECDSA signatures prevent tampering
- **Key Fingerprints**: SHA-256 hashes for key verification
- **Authenticated Encryption**: AES-GCM provides confidentiality and integrity

##  Prerequisites

```bash
pip install cryptography
```

##  Usage

### Quick Demo
```bash
python3 ecc_messenger.py
# Choose option 1 for automated demo
```

### Interactive Mode
```bash
python3 ecc_messenger.py
# Choose option 2 for hands-on experience
```

### Interactive Commands
- `add <name>` - Add a contact's public key
- `send <name>` - Send encrypted message to contact
- `receive` - Decrypt received message package
- `contacts` - Show all contacts with key fingerprints
- `history` - Display message history
- `key` - Show your public key for sharing
- `demo` - Run the automated demonstration
- `quit` - Exit the application

##  Demo Walkthrough

The automated demo demonstrates:

1. **Key Generation**: Alice and Bob generate ECC key pairs
2. **Key Exchange**: Public keys are exchanged and verified
3. **Secure Messaging**: End-to-end encrypted message exchange
4. **Perfect Forward Secrecy**: Each message uses unique ephemeral keys
5. **Digital Signatures**: All messages are cryptographically signed

##  Code Structure

```
ecc_messenger.py
├── ECCMessenger Class
│   ├── Key Management
│   │   ├── _generate_key_pair()
│   │   ├── export_public_key()
│   │   └── import_contact_key()
│   ├── Cryptographic Operations
│   │   ├── _derive_shared_secret()
│   │   ├── _encrypt_message()
│   │   ├── _decrypt_message()
│   │   ├── _sign_message()
│   │   └── _verify_signature()
│   └── Messaging Interface
│       ├── send_message()
│       ├── receive_message()
│       └── show_contacts()
├── demo_conversation()
└── interactive_mode()
```

##  Security Analysis

### Strengths
- **Strong Cryptography**: Uses well-established NIST curves and algorithms
- **Perfect Forward Secrecy**: Compromise of long-term keys doesn't affect past messages
- **Message Authentication**: Digital signatures prevent message tampering
- **Key Verification**: Fingerprints help detect man-in-the-middle attacks

### Educational Limitations
- **No Network Layer**: Manual message package exchange (educational focus)
- **No Key Management**: Simplified contact-based key distribution
- **Local Storage**: Keys and messages stored in memory only
- **No Metadata Protection**: Message timing and participants are visible

##  Learning Outcomes

Through this project, I gained hands-on experience with:
- Implementing ECC-based cryptographic protocols
- Understanding the relationship between public/private key cryptography and symmetric encryption
- Applying Perfect Forward Secrecy in messaging applications
- Working with industry-standard cryptographic libraries
- Designing user-friendly security interfaces

##  References & Acknowledgments

- **Course**: Data Privacy (CSD3005), VIT Bhopal University
- **Mentor**: Dr. Sajjad Ahmed
- **Cryptographic Library**: Python `cryptography` package
- **Standards**: NIST FIPS 186-4 (ECDSA), RFC 5869 (HKDF), NIST SP 800-38D (GCM)

##  Disclaimer

This is an **educational project** designed to demonstrate cryptographic concepts. It should **not be used for production communication** without proper security auditing, network implementation, and additional security measures.

##  License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

---

**Developed by**: Ujjwal Kaul  
**Institution**: VIT Bhopal University  
**Course**: CSD3005 - Data Privacy   
**Under the guidance of**: Dr. Sajjad Ahmed

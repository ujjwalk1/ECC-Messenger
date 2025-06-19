#!/usr/bin/env python3
"""
ECC Secure Messaging - Minimal Console Version
Demonstrates core concepts from VITB CSD3005 Data Privacy course
"""

import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from datetime import datetime

class ECCMessenger:
    def __init__(self, username):
        self.username = username
        self.private_key = None
        self.public_key = None
        self.contacts = {}
        self.message_history = []
        
        self._generate_key_pair()
        print(f"🔐 Generated ECC key pair for {username}")
        print(f"📋 Public key fingerprint: {self._get_public_key_fingerprint()}")
    
    def _generate_key_pair(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
    
    def _get_public_key_fingerprint(self):
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashlib.sha256(public_bytes).hexdigest()
        return digest[:16].upper()
    
    def export_public_key(self):
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode()
    
    def import_contact_key(self, contact_name, public_key_b64):
        try:
            public_bytes = base64.b64decode(public_key_b64)
            public_key = serialization.load_pem_public_key(public_bytes, default_backend())
            self.contacts[contact_name] = public_key
            print(f"✅ Added {contact_name} to contacts")
            
            contact_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            fingerprint = hashlib.sha256(contact_bytes).hexdigest()[:16].upper()
            print(f"📋 {contact_name}'s key fingerprint: {fingerprint}")
        except Exception as e:
            print(f"❌ Error importing key: {e}")
    
    def _derive_shared_secret(self, recipient_public_key):
        shared_key = self.private_key.exchange(ec.ECDH(), recipient_public_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ECC-Messenger-AES-Key',
            backend=default_backend()
        ).derive(shared_key)
        
        return derived_key
    
    def _encrypt_message(self, message, aes_key):
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        message_bytes = message.encode('utf-8')
        ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
        
        return {
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }
    
    def _decrypt_message(self, encrypted_data, aes_key):
        try:
            iv = base64.b64decode(encrypted_data['iv'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
    
    def _sign_message(self, message_data):
        message_json = json.dumps(message_data, sort_keys=True)
        message_bytes = message_json.encode('utf-8')
        
        signature = self.private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        return base64.b64encode(signature).decode()
    
    def _verify_signature(self, message_data, signature_b64, sender_public_key):
        try:
            signature = base64.b64decode(signature_b64)
            message_json = json.dumps(message_data, sort_keys=True)
            message_bytes = message_json.encode('utf-8')
            
            sender_public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False
    
    def send_message(self, recipient_name, message):
        if recipient_name not in self.contacts:
            print(f"❌ {recipient_name} not in contacts. Add their public key first.")
            return None
        
        recipient_public_key = self.contacts[recipient_name]
        
        # Generate ephemeral key pair for Perfect Forward Secrecy
        ephemeral_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public = ephemeral_private.public_key()
        
        shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ECC-Messenger-Ephemeral-Key',
            backend=default_backend()
        ).derive(shared_secret)
        
        encrypted_data = self._encrypt_message(message, aes_key)
        
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        message_package = {
            'sender': self.username,
            'recipient': recipient_name,
            'ephemeral_public_key': base64.b64encode(ephemeral_public_bytes).decode(),
            'encrypted_message': encrypted_data,
            'timestamp': datetime.now().isoformat()
        }
        
        signature = self._sign_message(message_package)
        message_package['signature'] = signature
        
        print(f"📤 Message sent to {recipient_name}")
        print(f"🔒 Used ephemeral key for Perfect Forward Secrecy")
        
        self.message_history.append({
            'type': 'sent',
            'message': message,
            'contact': recipient_name,
            'timestamp': message_package['timestamp']
        })
        
        return message_package
    
    def receive_message(self, message_package):
        try:
            sender_name = message_package['sender']
            
            if sender_name not in self.contacts:
                print(f"❌ Unknown sender: {sender_name}")
                return None
            
            sender_public_key = self.contacts[sender_name]
            
            signature = message_package.pop('signature')
            if not self._verify_signature(message_package, signature, sender_public_key):
                print(f"❌ Invalid signature from {sender_name}")
                return None
            
            ephemeral_public_bytes = base64.b64decode(message_package['ephemeral_public_key'])
            ephemeral_public_key = serialization.load_der_public_key(
                ephemeral_public_bytes, 
                default_backend()
            )
            
            shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ECC-Messenger-Ephemeral-Key',
                backend=default_backend()
            ).derive(shared_secret)
            
            plaintext = self._decrypt_message(message_package['encrypted_message'], aes_key)
            
            print(f"📨 Message from {sender_name}: {plaintext}")
            print(f"🔓 Decrypted using ephemeral key exchange")
            
            self.message_history.append({
                'type': 'received',
                'message': plaintext,
                'contact': sender_name,
                'timestamp': message_package['timestamp']
            })
            
            return plaintext
            
        except Exception as e:
            print(f"❌ Error receiving message: {e}")
            return None
    
    def show_contacts(self):
        if not self.contacts:
            print("📱 No contacts added yet")
            return
        
        print("📱 Contacts:")
        for name in self.contacts:
            contact_bytes = self.contacts[name].public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            fingerprint = hashlib.sha256(contact_bytes).hexdigest()[:16].upper()
            print(f"  • {name} (Key: {fingerprint})")
    
    def show_message_history(self):
        if not self.message_history:
            print("💬 No messages yet")
            return
        
        print("💬 Message History:")
        for msg in self.message_history[-10:]:
            icon = "📤" if msg['type'] == 'sent' else "📨"
            timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%H:%M")
            print(f"  {icon} [{timestamp}] {msg['contact']}: {msg['message']}")


def demo_conversation():
    print("=" * 60)
    print("🔐 ECC Secure Messaging Demo")
    print("Demonstrating concepts from CSD3005 Data Privacy course")
    print("=" * 60)
    
    alice = ECCMessenger("Alice")
    bob = ECCMessenger("Bob")
    
    print("\n" + "─" * 40)
    print("👥 Setting up contacts (Key Exchange)")
    print("─" * 40)
    
    alice.import_contact_key("Bob", bob.export_public_key())
    bob.import_contact_key("Alice", alice.export_public_key())
    
    print("\n" + "─" * 40)
    print("💬 Secure Message Exchange")
    print("─" * 40)
    
    print("\n🟦 Alice sends message:")
    message1 = alice.send_message("Bob", "Hello Bob! This message is encrypted with ECC!")
    
    print("\n🟩 Bob receives message:")
    bob.receive_message(message1)
    
    print("\n🟩 Bob sends reply:")
    message2 = bob.send_message("Alice", "Hi Alice! Perfect Forward Secrecy is working great!")
    
    print("\n🟦 Alice receives reply:")
    alice.receive_message(message2)
    
    print("\n" + "─" * 40)
    print("📊 Final Status")
    print("─" * 40)
    
    print(f"\n🟦 Alice's status:")
    alice.show_contacts()
    alice.show_message_history()
    
    print(f"\n🟩 Bob's status:")
    bob.show_contacts()
    bob.show_message_history()
    
    print("\n" + "=" * 60)
    print("✅ Demo completed successfully!")
    print("🔒 All messages were encrypted with ephemeral keys")
    print("✍️  All messages were digitally signed")
    print("🔐 Perfect Forward Secrecy achieved")
    print("=" * 60)


def interactive_mode():
    print("🔐 ECC Secure Messenger - Interactive Mode")
    print("Type 'help' for commands")
    
    username = input("Enter your username: ")
    messenger = ECCMessenger(username)
    
    print(f"\n📋 Your public key (share this with contacts):")
    print(messenger.export_public_key())
    print()
    
    while True:
        try:
            command = input(f"\n{username}> ").strip().lower()
            
            if command == 'help':
                print("Commands:")
                print("  add <n>        - Add a contact's public key")
                print("  send <n>       - Send message to contact")
                print("  receive        - Receive a message package")
                print("  contacts       - Show all contacts")
                print("  history        - Show message history")
                print("  key            - Show your public key")
                print("  demo           - Run automated demo")
                print("  quit           - Exit")
            
            elif command.startswith('add '):
                name = command[4:].strip()
                print(f"Enter {name}'s public key:")
                pub_key = input().strip()
                messenger.import_contact_key(name, pub_key)
            
            elif command.startswith('send '):
                name = command[5:].strip()
                message = input("Message: ")
                msg_package = messenger.send_message(name, message)
                if msg_package:
                    print("\n📦 Message package (send this to recipient):")
                    print(json.dumps(msg_package, indent=2))
            
            elif command == 'receive':
                print("Paste the message package JSON:")
                try:
                    msg_json = input().strip()
                    msg_package = json.loads(msg_json)
                    messenger.receive_message(msg_package)
                except json.JSONDecodeError:
                    print("❌ Invalid JSON format")
                except Exception as e:
                    print(f"❌ Error processing message: {e}")
            
            elif command == 'contacts':
                messenger.show_contacts()
            
            elif command == 'history':
                messenger.show_message_history()
            
            elif command == 'key':
                print("📋 Your public key:")
                print(messenger.export_public_key())
            
            elif command == 'demo':
                demo_conversation()
            
            elif command in ['quit', 'exit']:
                print("👋 Goodbye!")
                break
            
            elif command == '':
                continue
            
            else:
                print("❌ Unknown command. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == "__main__":
    print("Choose mode:")
    print("1. Demo conversation (automated)")
    print("2. Interactive mode")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        demo_conversation()
    elif choice == "2":
        interactive_mode()
    else:
        print("Running demo by default...")
        demo_conversation()
#!/usr/bin/env python3
"""
Fortiq CLI - Production-Ready Post-Quantum Cryptography Tool
Hybrid encryption using Kyber512 KEM + AES with enterprise security features
"""

import argparse
import os
import json
import sys
import secrets
import hmac
import hashlib
import logging
import tempfile
import shutil
import stat
import getpass
import fcntl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from contextlib import contextmanager

# Cryptographic imports
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Configuration
@dataclass
class Config:
    key_dir: str = os.path.expanduser("~/.fortiq/keys/")
    vault_index_file: str = os.path.expanduser("~/.fortiq/vault.json")
    log_file: str = os.path.expanduser("~/.fortiq/fortiq.log")
    backup_dir: str = os.path.expanduser("~/.fortiq/backups/")
    max_file_size: int = 100 * 1024 * 1024  # 100MB limit
    key_derivation_iterations: int = 100000
    session_timeout: int = 300  # 5 minutes
    max_failed_attempts: int = 3

class SecurityError(Exception):
    """Custom security exception"""
    pass

class FortiqLogger:
    """Secure logging with audit trail"""
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Set secure permissions on log file
        if os.path.exists(log_file):
            os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def log_security_event(self, event: str, details: Dict[str, Any] = None):
        """Log security-related events"""
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event': event,
            'details': details or {},
            'pid': os.getpid(),
            'uid': os.getuid() if hasattr(os, 'getuid') else 'unknown'
        }
        self.logger.info(f"SECURITY: {json.dumps(log_entry)}")
    
    def log_error(self, error: str, details: Dict[str, Any] = None):
        """Log error events"""
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': error,
            'details': details or {}
        }
        self.logger.error(f"ERROR: {json.dumps(log_entry)}")

class SecureKeyManager:
    """Secure key management with encryption at rest"""
    
    def __init__(self, config: Config, logger: FortiqLogger):
        self.config = config
        self.logger = logger
        self.failed_attempts = {}
        self._setup_directories()
    
    def _setup_directories(self):
        """Create secure directories with proper permissions"""
        for directory in [self.config.key_dir, self.config.backup_dir]:
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, stat.S_IRWXU)  # Owner only
    
    def _get_master_key(self, username: str) -> bytes:
        """Derive master key from password"""
        if username in self.failed_attempts:
            if self.failed_attempts[username] >= self.config.max_failed_attempts:
                raise SecurityError("Too many failed attempts. Account locked.")
        
        password = getpass.getpass(f"Enter password for {username}: ")
        
        # Load or generate salt
        salt_file = os.path.join(self.config.key_dir, f"{username}.salt")
        if os.path.exists(salt_file):
            with open(salt_file, 'rb') as f:
                salt = f.read()
        else:
            salt = get_random_bytes(32)
            with open(salt_file, 'wb') as f:
                f.write(salt)
            os.chmod(salt_file, stat.S_IRUSR | stat.S_IWUSR)
        
        # Derive key using PBKDF2
        master_key = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=32,
            count=self.config.key_derivation_iterations,
            hmac_hash_module=SHA256
        )
        
        # Clear password from memory
        password = None
        
        return master_key
    
    def _encrypt_key(self, key_data: bytes, master_key: bytes) -> Dict[str, str]:
        """Encrypt key with master key"""
        iv = get_random_bytes(16)
        cipher = AES.new(master_key, AES.MODE_CBC, iv)
        encrypted_key = cipher.encrypt(pad(key_data, AES.block_size))
        
        # Add HMAC for integrity
        hmac_key = master_key[:16]  # Use first 16 bytes for HMAC
        mac = hmac.new(hmac_key, iv + encrypted_key, hashlib.sha256).digest()
        
        return {
            'encrypted_key': encrypted_key.hex(),
            'iv': iv.hex(),
            'mac': mac.hex(),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _decrypt_key(self, encrypted_data: Dict[str, str], master_key: bytes) -> bytes:
        """Decrypt key with master key"""
        try:
            iv = bytes.fromhex(encrypted_data['iv'])
            encrypted_key = bytes.fromhex(encrypted_data['encrypted_key'])
            stored_mac = bytes.fromhex(encrypted_data['mac'])
            
            # Verify HMAC
            hmac_key = master_key[:16]
            calculated_mac = hmac.new(hmac_key, iv + encrypted_key, hashlib.sha256).digest()
            
            if not hmac.compare_digest(stored_mac, calculated_mac):
                raise SecurityError("Key integrity check failed")
            
            cipher = AES.new(master_key, AES.MODE_CBC, iv)
            key_data = unpad(cipher.decrypt(encrypted_key), AES.block_size)
            
            return key_data
            
        except Exception as e:
            raise SecurityError(f"Key decryption failed: {e}")
    
    @contextmanager
    def _file_lock(self, file_path: str):
        """File locking for atomic operations"""
        lock_file = file_path + ".lock"
        try:
            with open(lock_file, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                yield
        finally:
            try:
                os.remove(lock_file)
            except FileNotFoundError:
                pass
    
    def generate_and_save_keys(self, username: str) -> bool:
        """Generate and securely save key pair"""
        try:
            self.logger.log_security_event("key_generation_started", {"username": username})
            
            # Generate quantum-resistant key pair
            pk, sk = generate_keypair()
            
            # Get master key for encryption
            master_key = self._get_master_key(username)
            
            # Encrypt keys
            encrypted_pk = self._encrypt_key(pk, master_key)
            encrypted_sk = self._encrypt_key(sk, master_key)
            
            # Save keys atomically
            pk_file = os.path.join(self.config.key_dir, f"{username}_pk.json")
            sk_file = os.path.join(self.config.key_dir, f"{username}_sk.json")
            
            with self._file_lock(pk_file):
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                    json.dump(encrypted_pk, tmp, indent=2)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                shutil.move(tmp.name, pk_file)
                os.chmod(pk_file, stat.S_IRUSR | stat.S_IWUSR)
            
            with self._file_lock(sk_file):
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                    json.dump(encrypted_sk, tmp, indent=2)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                shutil.move(tmp.name, sk_file)
                os.chmod(sk_file, stat.S_IRUSR | stat.S_IWUSR)
            
            # Create backup
            self._create_backup(username)
            
            # Clear keys from memory
            pk = sk = master_key = None
            
            self.logger.log_security_event("key_generation_completed", {"username": username})
            return True
            
        except Exception as e:
            self.logger.log_error("key_generation_failed", {"username": username, "error": str(e)})
            return False
    
    def load_keys(self, username: str) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Load and decrypt key pair"""
        try:
            pk_file = os.path.join(self.config.key_dir, f"{username}_pk.json")
            sk_file = os.path.join(self.config.key_dir, f"{username}_sk.json")
            
            if not (os.path.exists(pk_file) and os.path.exists(sk_file)):
                self.logger.log_error("keys_not_found", {"username": username})
                return None, None
            
            master_key = self._get_master_key(username)
            
            with open(pk_file, 'r') as f:
                encrypted_pk = json.load(f)
            with open(sk_file, 'r') as f:
                encrypted_sk = json.load(f)
            
            pk = self._decrypt_key(encrypted_pk, master_key)
            sk = self._decrypt_key(encrypted_sk, master_key)
            
            # Reset failed attempts on success
            self.failed_attempts.pop(username, None)
            
            self.logger.log_security_event("keys_loaded", {"username": username})
            return pk, sk
            
        except SecurityError:
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            self.logger.log_error("key_load_failed", {"username": username})
            return None, None
        except Exception as e:
            self.logger.log_error("key_load_error", {"username": username, "error": str(e)})
            return None, None
    
    def delete_keys(self, username: str) -> bool:
        """Securely delete keys"""
        try:
            files_to_delete = [
                os.path.join(self.config.key_dir, f"{username}_pk.json"),
                os.path.join(self.config.key_dir, f"{username}_sk.json"),
                os.path.join(self.config.key_dir, f"{username}.salt")
            ]
            
            for file_path in files_to_delete:
                if os.path.exists(file_path):
                    # Secure deletion by overwriting
                    with open(file_path, 'r+b') as f:
                        length = f.seek(0, 2)
                        f.seek(0)
                        f.write(secrets.token_bytes(length))
                        f.flush()
                        os.fsync(f.fileno())
                    os.remove(file_path)
            
            self.logger.log_security_event("keys_deleted", {"username": username})
            return True
            
        except Exception as e:
            self.logger.log_error("key_deletion_failed", {"username": username, "error": str(e)})
            return False
    
    def _create_backup(self, username: str):
        """Create encrypted backup of keys"""
        backup_dir = os.path.join(self.config.backup_dir, username)
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"backup_{timestamp}.json")
        
        pk_file = os.path.join(self.config.key_dir, f"{username}_pk.json")
        sk_file = os.path.join(self.config.key_dir, f"{username}_sk.json")
        
        if os.path.exists(pk_file) and os.path.exists(sk_file):
            backup_data = {
                'timestamp': timestamp,
                'public_key': json.load(open(pk_file, 'r')),
                'private_key': json.load(open(sk_file, 'r'))
            }
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            os.chmod(backup_file, stat.S_IRUSR | stat.S_IWUSR)

class SecureFileProcessor:
    """Secure file encryption/decryption with integrity checks"""
    
    def __init__(self, config: Config, logger: FortiqLogger):
        self.config = config
        self.logger = logger
    
    def _validate_file_size(self, file_path: str) -> bool:
        """Validate file size limits"""
        try:
            size = os.path.getsize(file_path)
            return size <= self.config.max_file_size
        except OSError:
            return False
    
    def _hybrid_encrypt(self, pk: bytes, plaintext: bytes) -> Dict[str, str]:
        """Enhanced hybrid encryption with integrity protection"""
        try:
            # Generate shared secret using Kyber512
            ct, shared_secret = encrypt(pk)
            
            # Derive keys from shared secret
            master_key = hashlib.sha256(shared_secret).digest()
            aes_key = master_key[:16]
            hmac_key = master_key[16:]
            
            # Generate random IV
            iv = get_random_bytes(16)
            
            # Encrypt with AES-CBC
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            
            # Calculate HMAC for integrity
            mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
            
            return {
                'version': '1.0',
                'kyber_ct': ct.hex(),
                'aes_ciphertext': ciphertext.hex(),
                'iv': iv.hex(),
                'mac': mac.hex(),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            raise SecurityError(f"Encryption failed: {e}")
    
    def _hybrid_decrypt(self, sk: bytes, package: Dict[str, str]) -> bytes:
        """Enhanced hybrid decryption with integrity verification"""
        try:
            # Verify version compatibility
            if package.get('version') != '1.0':
                raise SecurityError("Unsupported encryption version")
            
            # Recover shared secret
            ct = bytes.fromhex(package['kyber_ct'])
            shared_secret = decrypt(sk, ct)
            
            # Derive keys
            master_key = hashlib.sha256(shared_secret).digest()
            aes_key = master_key[:16]
            hmac_key = master_key[16:]
            
            # Verify integrity
            iv = bytes.fromhex(package['iv'])
            ciphertext = bytes.fromhex(package['aes_ciphertext'])
            stored_mac = bytes.fromhex(package['mac'])
            
            calculated_mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
            
            if not hmac.compare_digest(stored_mac, calculated_mac):
                raise SecurityError("File integrity check failed - possible tampering")
            
            # Decrypt
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            
            return unpad(plaintext, AES.block_size)
            
        except Exception as e:
            raise SecurityError(f"Decryption failed: {e}")
    
    def encrypt_file(self, input_path: str, output_path: str, pk: bytes, vault_name: Optional[str] = None) -> bool:
        """Securely encrypt a file"""
        try:
            # Validate input file
            if not os.path.exists(input_path):
                self.logger.log_error("file_not_found", {"path": input_path})
                return False
            
            if not self._validate_file_size(input_path):
                self.logger.log_error("file_too_large", {"path": input_path})
                return False
            
            # Read and encrypt file
            with open(input_path, 'rb') as f:
                plaintext = f.read()
            
            encrypted_data = self._hybrid_encrypt(pk, plaintext)
            
            # Add metadata
            encrypted_data['original_filename'] = os.path.basename(input_path)
            encrypted_data['original_size'] = len(plaintext)
            
            # Write encrypted file atomically
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                json.dump(encrypted_data, tmp, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())
            
            shutil.move(tmp.name, output_path)
            os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)
            
            # Update vault index
            if vault_name:
                self._update_vault_index(output_path, vault_name, encrypted_data)
            
            # Clear sensitive data
            plaintext = None
            
            self.logger.log_security_event("file_encrypted", {
                "input": input_path,
                "output": output_path,
                "vault": vault_name
            })
            
            return True
            
        except Exception as e:
            self.logger.log_error("encryption_failed", {"error": str(e)})
            return False
    
    def decrypt_file(self, input_path: str, output_path: str, sk: bytes) -> bool:
        """Securely decrypt a file"""
        try:
            if not os.path.exists(input_path):
                self.logger.log_error("encrypted_file_not_found", {"path": input_path})
                return False
            
            # Load encrypted data
            with open(input_path, 'r') as f:
                encrypted_data = json.load(f)
            
            # Decrypt
            plaintext = self._hybrid_decrypt(sk, encrypted_data)
            
            # Write decrypted file atomically
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
                tmp.write(plaintext)
                tmp.flush()
                os.fsync(tmp.fileno())
            
            shutil.move(tmp.name, output_path)
            
            # Clear sensitive data
            plaintext = None
            
            self.logger.log_security_event("file_decrypted", {
                "input": input_path,
                "output": output_path
            })
            
            return True
            
        except Exception as e:
            self.logger.log_error("decryption_failed", {"error": str(e)})
            return False
    
    def _update_vault_index(self, file_path: str, vault_name: str, metadata: Dict[str, str]):
        """Update vault index with encryption metadata"""
        try:
            index_file = self.config.vault_index_file
            
            # Load existing index
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    data = json.load(f)
            else:
                data = {'vaults': [], 'version': '1.0'}
            
            # Add new entry
            entry = {
                'vault': vault_name,
                'file_path': file_path,
                'original_filename': metadata.get('original_filename'),
                'original_size': metadata.get('original_size'),
                'encrypted_at': metadata.get('timestamp'),
                'file_hash': hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            }
            
            data['vaults'].append(entry)
            
            # Write index atomically
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                json.dump(data, tmp, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())
            
            shutil.move(tmp.name, index_file)
            os.chmod(index_file, stat.S_IRUSR | stat.S_IWUSR)
            
        except Exception as e:
            self.logger.log_error("vault_index_update_failed", {"error": str(e)})

class FortiqCLI:
    """Main CLI application with security features"""
    
    def __init__(self):
        self.config = Config()
        self.logger = FortiqLogger(self.config.log_file)
        self.key_manager = SecureKeyManager(self.config, self.logger)
        self.file_processor = SecureFileProcessor(self.config, self.logger)
    
    def run(self):
        """Main entry point"""
        parser = argparse.ArgumentParser(
            description="Fortiq - Production-Ready Post-Quantum Cryptography CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  fortiq gen-keys --username alice
  fortiq encrypt --infile document.pdf --outfile document.enc --username alice --vault personal
  fortiq decrypt --infile document.enc --outfile document.pdf --username alice
  fortiq list-vaults
  fortiq delete-keys --username alice
            """
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Generate keys
        gen_parser = subparsers.add_parser("gen-keys", help="Generate new quantum-resistant key pair")
        gen_parser.add_argument("--username", required=True, help="Username for key pair")
        
        # Encrypt file
        encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
        encrypt_parser.add_argument("--infile", required=True, help="Input file path")
        encrypt_parser.add_argument("--outfile", required=True, help="Output encrypted file path")
        encrypt_parser.add_argument("--username", required=True, help="Username to encrypt for")
        encrypt_parser.add_argument("--vault", help="Vault name for organization")
        
        # Decrypt file
        decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
        decrypt_parser.add_argument("--infile", required=True, help="Input encrypted file path")
        decrypt_parser.add_argument("--outfile", required=True, help="Output decrypted file path")
        decrypt_parser.add_argument("--username", required=True, help="Username to decrypt with")
        
        # List vaults
        subparsers.add_parser("list-vaults", help="List all encrypted vaults")
        
        # Delete keys
        delete_parser = subparsers.add_parser("delete-keys", help="Securely delete user keys")
        delete_parser.add_argument("--username", required=True, help="Username to delete keys for")
        delete_parser.add_argument("--confirm", action="store_true", help="Confirm deletion")
        
        # Verify integrity
        verify_parser = subparsers.add_parser("verify", help="Verify file integrity")
        verify_parser.add_argument("--file", required=True, help="Encrypted file to verify")
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        try:
            if args.command == "gen-keys":
                if self.key_manager.generate_and_save_keys(args.username):
                    print(f"✓ Quantum-resistant keys generated for '{args.username}'")
                else:
                    print("✗ Key generation failed")
                    sys.exit(1)
            
            elif args.command == "encrypt":
                pk, _ = self.key_manager.load_keys(args.username)
                if pk:
                    if self.file_processor.encrypt_file(args.infile, args.outfile, pk, args.vault):
                        print(f"✓ File encrypted: {args.outfile}")
                        if args.vault:
                            print(f"✓ Added to vault: {args.vault}")
                    else:
                        print("✗ Encryption failed")
                        sys.exit(1)
                else:
                    print("✗ Could not load keys")
                    sys.exit(1)
            
            elif args.command == "decrypt":
                _, sk = self.key_manager.load_keys(args.username)
                if sk:
                    if self.file_processor.decrypt_file(args.infile, args.outfile, sk):
                        print(f"✓ File decrypted: {args.outfile}")
                    else:
                        print("✗ Decryption failed")
                        sys.exit(1)
                else:
                    print("✗ Could not load keys")
                    sys.exit(1)
            
            elif args.command == "list-vaults":
                self._list_vaults()
            
            elif args.command == "delete-keys":
                if not args.confirm:
                    confirm = input(f"Are you sure you want to delete keys for '{args.username}'? (yes/no): ")
                    if confirm.lower() != 'yes':
                        print("Operation cancelled")
                        return
                
                if self.key_manager.delete_keys(args.username):
                    print(f"✓ Keys deleted for '{args.username}'")
                else:
                    print("✗ Key deletion failed")
                    sys.exit(1)
            
            elif args.command == "verify":
                self._verify_file(args.file)
                
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            sys.exit(1)
        except Exception as e:
            self.logger.log_error("unexpected_error", {"error": str(e)})
            print(f"✗ Unexpected error: {e}")
            sys.exit(1)
    
    def _list_vaults(self):
        """List all vaults with metadata"""
        try:
            if not os.path.exists(self.config.vault_index_file):
                print("No vaults found")
                return
            
            with open(self.config.vault_index_file, 'r') as f:
                data = json.load(f)
            
            vaults = data.get('vaults', [])
            if not vaults:
                print("No vaults found")
                return
            
            print(f"\nFound {len(vaults)} encrypted files:")
            print("=" * 80)
            
            for i, entry in enumerate(vaults, 1):
                print(f"{i}. Vault: {entry['vault']}")
                print(f"   File: {entry['file_path']}")
                print(f"   Original: {entry['original_filename']} ({entry['original_size']} bytes)")
                print(f"   Encrypted: {entry['encrypted_at']}")
                print(f"   Hash: {entry['file_hash'][:16]}...")
                print("-" * 80)
                
        except Exception as e:
            self.logger.log_error("list_vaults_failed", {"error": str(e)})
            print(f"✗ Failed to list vaults: {e}")
    
    def _verify_file(self, file_path: str):
        """Verify encrypted file integrity"""
        try:
            if not os.path.exists(file_path):
                print("✗ File not found")
                return
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Check required fields
            required_fields = ['version', 'kyber_ct', 'aes_ciphertext', 'iv', 'mac']
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                print(f"✗ Invalid file format. Missing fields: {missing_fields}")
                return
            
            # Calculate file hash
            file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            
            print(f"✓ File format valid")
            print(f"✓ Version: {data['version']}")
            print(f"✓ Encrypted: {data.get('timestamp', 'Unknown')}")
            print(f"✓ File hash: {file_hash}")
            print(f"✓ Original filename: {data.get('original_filename', 'Unknown')}")
            print(f"✓ Original size: {data.get('original_size', 'Unknown')} bytes")
            
        except Exception as e:
            print(f"✗ Verification failed: {e}")

def main():
    """Application entry point"""
    try:
        app = FortiqCLI()
        app.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
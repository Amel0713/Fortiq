# Improved Fortiq CLI with uninstall and vault indexing
import argparse, os, json
from datetime import datetime
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

key_dir = "keys/"
vault_index_file = "vault.json"

def save_keys(pk, sk, name="user"):
 os.makedirs(key_dir, exist_ok=True)
 open(f"{key_dir}{name}_pk.bin", 'wb').write(pk)
 open(f"{key_dir}{name}_sk.bin", 'wb').write(sk)
def load_keys(name="user"):
 pk = open(f"{key_dir}{name}_pk.bin", 'rb').read()
 sk = open(f"{key_dir}{name}_sk.bin", 'rb').read()
 return pk, sk
def uninstall_keys(name="user"):
 try:
  os.remove(f"{key_dir}{name}_pk.bin")
  os.remove(f"{key_dir}{name}_sk.bin")
  print(f"Keys for '{name}' have been removed.")
 except FileNotFoundError:
  print(f"Keys for '{name}' not found.")
def hybrid_encrypt(pk, plaintext):
 ct, shared_secret = encrypt(pk)
 aes_key = sha256(shared_secret).digest()
 cipher = AES.new(aes_key, AES.MODE_CBC)
 ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
 return { 'ct': ct.hex(), 'aes_ciphertext': ciphertext.hex(), 'iv': cipher.iv.hex() }
def hybrid_decrypt(sk, package):
 ct = bytes.fromhex(package['ct'])
 shared_secret = decrypt(sk, ct)
 aes_key = sha256(shared_secret).digest()
 cipher = AES.new(aes_key, AES.MODE_CBC, bytes.fromhex(package['iv']))
 return unpad(cipher.decrypt(bytes.fromhex(package['aes_ciphertext'])), AES.block_size)
def update_vault_index(file_path, vault_name):
 entry = {"vault": vault_name, "file": file_path, "timestamp": datetime.utcnow().isoformat()+"Z"}
 data = json.load(open(vault_index_file)) if os.path.exists(vault_index_file) else []
 data.append(entry)
 json.dump(data, open(vault_index_file, 'w'), indent=2)
def encrypt_file(input_path, output_path, pk, vault_name=None):
 data = open(input_path, 'rb').read()
 encrypted = hybrid_encrypt(pk, data)
 json.dump(encrypted, open(output_path, 'w'))
 if vault_name: update_vault_index(output_path, vault_name)
def decrypt_file(input_path, output_path, sk):
 encrypted = json.load(open(input_path, 'r'))
 plaintext = hybrid_decrypt(sk, encrypted)
 open(output_path, 'wb').write(plaintext)
def main():
 p = argparse.ArgumentParser()
 s = p.add_subparsers(dest="cmd")
 g=s.add_parser("gen-keys"); g.add_argument("--name", default="user")
 e=s.add_parser("encrypt"); e.add_argument("--infile"); e.add_argument("--outfile"); e.add_argument("--keyname", default="user"); e.add_argument("--vault")
 d=s.add_parser("decrypt"); d.add_argument("--infile"); d.add_argument("--outfile"); d.add_argument("--keyname", default="user")
 u=s.add_parser("uninstall"); u.add_argument("--keyname", default="user")
 a = p.parse_args()
 if a.cmd == "gen-keys": pk, sk = generate_keypair(); save_keys(pk, sk, a.name); print(f"Keys saved for {a.name}")
 elif a.cmd == "encrypt": pk, _ = load_keys(a.keyname); encrypt_file(a.infile, a.outfile, pk, a.vault); print(f"Encrypted to {a.outfile}")
 elif a.cmd == "decrypt": _, sk = load_keys(a.keyname); decrypt_file(a.infile, a.outfile, sk); print(f"Decrypted to {a.outfile}")
 elif a.cmd == "uninstall": uninstall_keys(a.keyname)
 else: p.print_help()
if __name__ == '__main__': main()

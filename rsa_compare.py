from rsa_core import encrypt_block, decrypt_block, generate_keypair
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random

# Przykładowa wiadomość
msg = b'Hello RSA!'

print("▶ Twoja implementacja:")
pub, priv = generate_keypair(128)

# Konwertuj bajty na int
m_int = int.from_bytes(msg, "big")
enc = encrypt_block(m_int, pub)
dec = decrypt_block(enc, priv)
dec_bytes = dec.to_bytes((dec.bit_length() + 7) // 8, "big")

print("Oryginał:", msg)
print("Zaszyfrowane (int):", enc)
print("Odszyfrowane:", dec_bytes)

print("\n▶ RSA z biblioteki PyCryptodome:")
key = RSA.generate(1024)
cipher = PKCS1_OAEP.new(key)
encrypted = cipher.encrypt(msg)
decrypted = cipher.decrypt(encrypted)

print("Zaszyfrowane (OAEP):", encrypted.hex()[:60], "...")
print("Odszyfrowane:", decrypted)

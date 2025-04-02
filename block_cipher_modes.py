from rsa_core import encrypt_block, decrypt_block
import os
from rsa_core import encrypt_block, decrypt_block

def ecb_encrypt(data: bytes, pubkey):
    block_size = (pubkey[1].bit_length() + 7) // 8
    encrypted = []
    for b in data:
        c = encrypt_block(b, pubkey)
        encrypted.append(c.to_bytes(block_size, "big"))
    return b"".join(encrypted)

def ecb_decrypt(data: bytes, privkey):
    block_size = (privkey[1].bit_length() + 7) // 8
    decrypted = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        m = decrypt_block(int.from_bytes(block, "big"), privkey)
        decrypted.append(m.to_bytes(1, "big"))
    return b"".join(decrypted)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def cbc_encrypt(data: bytes, pubkey, iv: bytes):
    block_size = (pubkey[1].bit_length() + 7) // 8
    encrypted = []
    prev = iv

    for b in data:
        block = bytes([b])
        block = xor_bytes(block, prev[:1])  # XOR tylko 1 bajt
        c = encrypt_block(int.from_bytes(block, "big"), pubkey)
        c_bytes = c.to_bytes(block_size, "big")
        encrypted.append(c_bytes)
        prev = c_bytes

    return b"".join(encrypted)

def cbc_decrypt(data: bytes, privkey, iv: bytes):
    block_size = (privkey[1].bit_length() + 7) // 8
    decrypted = []
    prev = iv

    for i in range(0, len(data), block_size):
        c_bytes = data[i:i+block_size]
        c = int.from_bytes(c_bytes, "big")
        m = decrypt_block(c, privkey)
        m_bytes = m.to_bytes(1, "big")
        plain = xor_bytes(m_bytes, prev[:1])  # XOR z poprzednim zaszyfrowanym
        decrypted.append(plain)
        prev = c_bytes

    return b"".join(decrypted)


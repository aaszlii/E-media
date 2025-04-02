from block_cipher_modes import ecb_encrypt, cbc_encrypt
import os
from block_cipher_modes import ecb_decrypt
from rsa_core import generate_keypair
from png_utils import read_png_chunks, write_png_chunks
from block_cipher_modes import cbc_decrypt

def decrypt_cbc_png(input_filename, output_filename, privkey, iv):
    sig, chunks = read_png_chunks(input_filename)
    decrypted_chunks = []

    for t, d in chunks:
        if t == b'IDAT':
            print(f"Odszyfrowuję IDAT z pliku {input_filename} (CBC)")
            decrypted = cbc_decrypt(d, privkey, iv)
            decrypted_chunks.append((t, decrypted))
        else:
            decrypted_chunks.append((t, d))

    write_png_chunks(output_filename, sig, decrypted_chunks)
    print(f"Odszyfrowany obraz zapisano jako {output_filename}")


def decrypt_ecb_png(input_filename, output_filename, privkey):
    sig, chunks = read_png_chunks(input_filename)
    decrypted_chunks = []

    for t, d in chunks:
        if t == b'IDAT':
            print(f"Odszyfrowuję IDAT z pliku {input_filename}")
            decrypted = ecb_decrypt(d, privkey)
            decrypted_chunks.append((t, decrypted))
        else:
            decrypted_chunks.append((t, d))

    write_png_chunks(output_filename, sig, decrypted_chunks)
    print(f"Odszyfrowany obraz zapisano jako {output_filename}")

if __name__ == "__main__":
    pubkey, privkey = generate_keypair(512)
    sig, chunks = read_png_chunks("test_image.png")

    # --- ECB ---
    ecb_chunks = []
    for t, d in chunks:
        if t == b'IDAT':
            print(f"[ECB] Szyfruję IDAT")
            encrypted = ecb_encrypt(d, pubkey)
            ecb_chunks.append((t, encrypted))
        else:
            ecb_chunks.append((t, d))

    write_png_chunks("encrypted_ecb.png", sig, ecb_chunks)
    print("Zapisano: encrypted_ecb.png")

    # --- CBC ---
    iv = os.urandom(16)
    saved_iv = iv
    cbc_chunks = []
    for t, d in chunks:
        if t == b'IDAT':
            print(f"[CBC] Szyfruję IDAT")
            encrypted = cbc_encrypt(d, pubkey, iv)
            cbc_chunks.append((t, encrypted))
        else:
            cbc_chunks.append((t, d))

    write_png_chunks("encrypted_cbc.png", sig, cbc_chunks)
    print("Zapisano: encrypted_cbc.png")

    # Deszyfrowanie ECB
    decrypt_ecb_png("encrypted_ecb.png", "decrypted_ecb.png", privkey)
    decrypt_cbc_png("encrypted_cbc.png", "decrypted_cbc.png", privkey, saved_iv)





import zlib
import os
from RSA import RSA
from png_utils import read_png_chunks, write_png_chunks

def extract_idat_data(chunks):
    return b''.join(d for t, d in chunks if t == b'IDAT')

def replace_idat_data(chunks, new_data):
    return [(t, d) if t != b'IDAT' else (b'IDAT', new_data) for t, d in chunks]

def compress(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress(data: bytes) -> bytes:
    return zlib.decompress(data)

def run_encrypt_decrypt(mode: str, image_in: str):
    print(f"\nTryb: {mode}")

    rsa = RSA(512)
    public_key = rsa.public_key
    private_key = rsa.private_key

    iv_bytes = os.urandom(64)
    iv_int = int.from_bytes(iv_bytes, 'big')
    print(f"[{mode}] Initialization Vector: {iv_int}")

    # Wczytanie oryginalnych danych PNG
    sig, chunks = read_png_chunks(image_in)
    original_compressed = extract_idat_data(chunks)
    original_data = decompress(original_compressed)

    # Szyfrowanie
    if mode == 'ECB':
        encrypted_raw = rsa.encrypt_ecb(original_data, public_key)
    elif mode == 'CBC':
        encrypted_raw = rsa.encrypt_cbc(original_data, public_key, iv_int)
    else:
        raise ValueError("Nieznany tryb")

    encrypted_compressed = compress(bytes(encrypted_raw))
    enc_chunks = replace_idat_data(chunks, encrypted_compressed)
    write_png_chunks(f'encrypted_{mode.lower()}.png', sig, enc_chunks)

    # Deszyfrowanie
    if mode == 'ECB':
        decrypted_raw = rsa.decrypt_ecb(encrypted_raw, private_key)
    elif mode == 'CBC':
        decrypted_raw = rsa.decrypt_cbc(encrypted_raw, private_key, iv_int)
    else:
        raise ValueError("Nieznany tryb")

    decrypted_raw = decrypted_raw[:len(original_data)]  # obetnij padding
    decrypted_compressed = compress(bytes(decrypted_raw))
    dec_chunks = replace_idat_data(chunks, decrypted_compressed)
    write_png_chunks(f'decrypted_{mode.lower()}.png', sig, dec_chunks)


if __name__ == "__main__":
    run_encrypt_decrypt('ECB', "test_image.png")
    run_encrypt_decrypt('CBC', "test_image.png")

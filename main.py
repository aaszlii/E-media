import zlib
import os
import math
from RSA import RSA
from png_utils import read_png_chunks, write_png_chunks, inflate_with_filters, deflate_with_filters

def extract_idat_data(chunks):
    return b''.join(d for t, d in chunks if t == b'IDAT')

def replace_idat_data(chunks, new_data):
    return [(t, d) if t != b'IDAT' else (b'IDAT', new_data) for t, d in chunks]

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
    decompressed = decompress(original_compressed)

    # Odczyt parametrów obrazu z chunku IHDR
    ihdr_data = chunks[0][1]
    width = int.from_bytes(ihdr_data[0:4], "big")
    height = int.from_bytes(ihdr_data[4:8], "big")
    bit_depth = ihdr_data[8]
    color_type = ihdr_data[9]

    # Rozdzielenie filtrów i pikseli
    filter_bytes, original_data, stride = inflate_with_filters(decompressed, width, height, color_type, bit_depth)

    if mode == 'ECB':
        # Zaszyfruj tylko bloki nieparzyste
        encrypted_raw, extra_raw = rsa.encrypt_ecb(original_data, public_key)

        # Złóż pełne dane: naprzemiennie extra (parzyste) i zaszyfrowane (nieparzyste)
        k = 63  # rozmiar bloku wejściowego (dla 512-bitowego RSA)
        n = 64  # rozmiar bloku szyfrogramu
        full_data = bytearray()
        i_idat = 0
        i_extra = 0
        block_index = 0

        while i_idat < len(encrypted_raw) or i_extra < len(extra_raw):
            if block_index % 2 == 0:
                full_data.extend(extra_raw[i_extra:i_extra + k])
                i_extra += k
            else:
                full_data.extend(encrypted_raw[i_idat:i_idat + n])
                i_idat += n
            block_index += 1

    elif mode == 'CBC':
        full_data = rsa.encrypt_cbc(original_data, public_key, iv_int)
    else:
        raise ValueError("Nieznany tryb")

    encrypted_compressed = deflate_with_filters(filter_bytes, bytes(full_data), stride)
    enc_chunks = replace_idat_data(chunks, encrypted_compressed)
    write_png_chunks(f'encrypted_{mode.lower()}.png', sig, enc_chunks)

    # Deszyfrowanie
    if mode == 'ECB':
        decrypted_raw = rsa.decrypt_ecb(encrypted_raw, extra_raw, private_key)
    elif mode == 'CBC':
        decrypted_raw = rsa.decrypt_cbc(full_data, private_key, iv_int)
    else:
        raise ValueError("Nieznany tryb")

    decrypted_compressed = deflate_with_filters(filter_bytes, bytes(decrypted_raw), stride)
    dec_chunks = replace_idat_data(chunks, decrypted_compressed)
    write_png_chunks(f'decrypted_{mode.lower()}.png', sig, dec_chunks)

if __name__ == "__main__":
    run_encrypt_decrypt('ECB', "test_image.png")
    run_encrypt_decrypt('CBC', "test_image.png")

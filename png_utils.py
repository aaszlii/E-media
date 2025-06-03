import zlib
import math

def inflate_with_filters(decompressed_data: bytes, width: int, height: int, color_type: int, bit_depth: int):

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    bytes_per_pixel = math.ceil(channels * bit_depth / 8)
    stride = bytes_per_pixel * width

    filter_bytes = []
    pixel_bytes = bytearray()

    for y in range(height):
        i = y * (stride + 1)
        filter_bytes.append(decompressed_data[i])
        pixel_bytes.extend(decompressed_data[i + 1:i + 1 + stride])

    return bytes(filter_bytes), bytes(pixel_bytes), stride

def deflate_with_filters(filter_bytes: bytes, pixel_bytes: bytes, stride: int):
    compressed = bytearray()
    i = 0
    for f in filter_bytes:
        compressed.append(f)
        compressed.extend(pixel_bytes[i:i + stride])
        i += stride
    return zlib.compress(bytes(compressed))

def read_png_chunks(filename):
    with open(filename, "rb") as f:
        signature = f.read(8)
        chunks = []

        while True:
            length = f.read(4)
            if not length:
                break
            length = int.from_bytes(length, "big")
            chunk_type = f.read(4)
            data = f.read(length)
            crc = f.read(4)
            chunks.append((chunk_type, data))

        return signature, chunks

def write_png_chunks(filename, signature, chunks):
    with open(filename, "wb") as f:
        f.write(signature)
        for chunk_type, data in chunks:
            f.write(len(data).to_bytes(4, "big"))
            f.write(chunk_type)
            f.write(data)
            # CRC can be recalculated but for now leave it as is:

            crc = zlib.crc32(chunk_type + data)
            f.write(crc.to_bytes(4, "big"))
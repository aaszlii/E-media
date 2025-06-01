import zlib
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
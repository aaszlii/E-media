import random
from KeyGenerator import KeyGenerator

class RSA():
    def __init__(self,key_size):
        self.key_size = key_size
        self.key = KeyGenerator(self.key_size)
        self.private_key = self.key.private_key
        self.public_key = self.key.public_key
        self.encrypted_chunk_size_in_bytes_sub = self.key_size//8 - 1
        self.encrypted_chunk_size_in_bytes = self.key_size//8

    def __str__(self):
        return f"Private:{self.private_key}    Public:{self.public_key}"

    @staticmethod
    def encrypt_ecb(data: bytes, public_key: tuple):
        k = public_key[1].bit_length() // 8 - 1
        n = k + 1
        padding_len = (k - (len(data) % k)) % k
        data += bytes([0] * padding_len)

        idat_data = bytearray()
        extra_data = bytearray()

        for i in range(0, len(data), k):
            block = data[i:i + k]
            if (i // k) % 2 == 1:
                # NIEPARZYSTE - zaszyfruj
                m = int.from_bytes(block, 'big')
                c = pow(m, public_key[0], public_key[1])
                idat_data.extend(c.to_bytes(n, 'big'))
            else:
                # PARZYSTE - zachowaj oryginał
                extra_data.extend(block)

        return idat_data, extra_data

    @staticmethod
    def decrypt_ecb(idat_data: bytes, extra_data: bytes, private_key: tuple):
        k = private_key[1].bit_length() // 8 - 1
        n = k + 1

        decrypted = bytearray()
        i_idat = 0
        i_extra = 0
        block_index = 0

        while i_idat < len(idat_data) or i_extra < len(extra_data):
            if block_index % 2 == 0:
                # PARZYSTY - oryginalny blok
                decrypted.extend(extra_data[i_extra:i_extra + k])
                i_extra += k
            else:
                # NIEPARZYSTY - deszyfrowany blok
                c_bytes = idat_data[i_idat:i_idat + n]
                c = int.from_bytes(c_bytes, 'big')
                m = pow(c, private_key[0], private_key[1])
                m_bytes = m.to_bytes(k, 'big')
                decrypted.extend(m_bytes)
                i_idat += n
            block_index += 1

        return decrypted

    @staticmethod
    def encrypt_cbc(data, public_key, iv):
        key_size = public_key[1].bit_length()
        encrypted_data = []
        step = key_size // 8 - 1
        previous = iv

        for i in range(0, len(data), step):
            raw_data_bytes = bytes(data[i:i + step])
            block_len = len(raw_data_bytes)

            prev_bytes = previous.to_bytes(step + 1, 'big')[:block_len]
            xor_int = int.from_bytes(raw_data_bytes, 'big') ^ int.from_bytes(prev_bytes, 'big')

            encrypted_data_int = pow(xor_int, public_key[0], public_key[1])
            encrypted_data_bytes = encrypted_data_int.to_bytes(step + 1, 'big')

            encrypted_data.extend(encrypted_data_bytes)
            previous = encrypted_data_int
        return encrypted_data

    @staticmethod
    def decrypt_cbc(data, private_key, iv):
        key_size = private_key[1].bit_length()
        decrypted_data = []
        step = key_size // 8
        previous = iv

        for i in range(0, len(data), step):
            encrypted_bytes = bytes(data[i:i + step])
            encrypted_data_int = int.from_bytes(encrypted_bytes, 'big')
            decrypted_data_int = pow(encrypted_data_int, private_key[0], private_key[1])

            prev_bytes = previous.to_bytes(step, 'big')[:step - 1]
            xor = decrypted_data_int ^ int.from_bytes(prev_bytes, 'big')

            needed_len = (xor.bit_length() + 7) // 8 or 1
            decrypted_bytes = xor.to_bytes(needed_len, 'big')
            decrypted_bytes = decrypted_bytes.rjust(step - 1, b'\x00')

            decrypted_data.extend(decrypted_bytes)
            previous = int.from_bytes(encrypted_bytes, 'big')
        return decrypted_data
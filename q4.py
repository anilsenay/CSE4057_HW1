from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode
from Crypto.Random import get_random_bytes
import timeit

from utils import printColored, printHeader

FOLDER = "files/"


def encrpyt_file(cipher, data, output_file="encrypted", mode="CBC"):
    ct_bytes = b''
    if(mode == "CTR"):
        ct_bytes = cipher.encrypt(data)
    else:
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))

    ct = b64encode(ct_bytes).decode('utf-8')

    if(output_file):
        printColored(("Ciphertext " +
                      (output_file if output_file else "") + ":"), ct[:50] + "...")
        file_out = open(FOLDER + output_file, "wb")
        file_out.write(ct_bytes)
        file_out.close()
    return ct


def decrpyt_file(cipher, input_file, output_file, mode="CBC"):
    f = open(FOLDER + input_file, "rb")
    bytes = f.read()

    pt = b''
    if(mode == "CTR"):
        pt = cipher.decrypt(bytes)
    else:
        pt = unpad(cipher.decrypt(bytes), AES.block_size)

    output_data = pt.decode("utf-8")
    file_out = open(FOLDER + output_file, "w")
    file_out.write(output_data)
    file_out.close()
    return output_data


def AES_Encryption(symmetric_keys):
    printHeader("=== AES ENCRYPTION === ")
    [key_1, key_2] = symmetric_keys

    # iv will be generated randomly
    CBC_128_cipher = AES.new(key_1, AES.MODE_CBC)

    # iv will be generated randomly
    CBC_256_cipher = AES.new(key_2, AES.MODE_CBC)

    # nonce will be generated randomly
    CTR_cipher = AES.new(key_2, AES.MODE_CTR)

    f = open(FOLDER + "1mb_file", "r")
    input_file_data = f.read()
    file_as_bytes = input_file_data.encode('utf-8')

    start = timeit.default_timer()
    CBC_128_ciphertext = encrpyt_file(
        CBC_128_cipher, file_as_bytes, "CBC_128_cipher_encrypted")
    stop = timeit.default_timer()
    print('Encyption with CBC 128 Bit execution takes: ',
          str(round((stop - start)*1000, 2)) + " ms")

    start = timeit.default_timer()
    CBC_256_ciphertext = encrpyt_file(
        CBC_256_cipher, file_as_bytes, "CBC_256_cipher_encrypted")
    stop = timeit.default_timer()
    print('Encyption with CBC 256 Bit execution takes: ',
          str(round((stop - start)*1000, 2)) + " ms")

    start = timeit.default_timer()
    CTR_ciphertext = encrpyt_file(
        CTR_cipher, file_as_bytes, "CTR_cipher_encrypted", mode="CTR")
    stop = timeit.default_timer()
    print('Encyption with CTR 256 Bit execution takes: ',
          str(round((stop - start)*1000, 2)) + " ms")

    printHeader("=== AES DECRYPTION === ")
    CBC_128_cipher_decrypted = decrpyt_file(AES.new(key_1, AES.MODE_CBC, CBC_128_cipher.iv),
                                            "CBC_128_cipher_encrypted", "CBC_128_cipher_decrypted")
    CBC_256_cipher_decrypted = decrpyt_file(AES.new(key_2, AES.MODE_CBC, CBC_256_cipher.iv),
                                            "CBC_256_cipher_encrypted", "CBC_256_cipher_decrypted")
    CTR_cipher_decrypted = decrpyt_file(AES.new(key_2, AES.MODE_CTR, nonce=CTR_cipher.nonce),
                                        "CTR_cipher_encrypted", "CTR_cipher_decrypted", mode="CTR")

    printColored("Decrypted file is same with original file (CBC 128 Bit):",
                 CBC_128_cipher_decrypted == input_file_data)
    printColored("Decrypted file is same with original file (CBC 256 Bit):",
                 CBC_256_cipher_decrypted == input_file_data)
    printColored("Decrypted file is same with original file (CTR 256 Bit):",
                 CTR_cipher_decrypted == input_file_data)

    printHeader("=== CHANGE IV FOR CBC 128 === ")
    printColored("Before change IV:", CBC_128_ciphertext[0:50] + "...")
    CBC_128_ciphertext_2 = encrpyt_file(
        AES.new(key_1, AES.MODE_CBC, iv=get_random_bytes(16)), file_as_bytes, output_file=None)
    printColored("After change IV:", CBC_128_ciphertext_2[0:50] + "...")

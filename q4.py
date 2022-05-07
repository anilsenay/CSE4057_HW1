from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode
from Crypto.Random import get_random_bytes
import timeit

from utils import printColored, printHeader

FOLDER = "files/"

# Encrypting file based on encryption mode
def encrpyt_file(cipher, data, output_file="encrypted", mode="CBC"):
    ct_bytes = b''
    if(mode == "CTR"):
        ct_bytes = cipher.encrypt(data) # Encrypt data with CTR mode.
    else:
        ct_bytes = cipher.encrypt(pad(data, AES.block_size)) # Encrypt data with CBC mode.

    ct = b64encode(ct_bytes).decode('utf-8') # Encode ciphertext to base64.

    # Write ciphertext to file.
    if(output_file):
        printColored(("Ciphertext " +
                      (output_file if output_file else "") + ":"), ct[:50] + "...")
        file_out = open(FOLDER + output_file, "wb")
        file_out.write(ct_bytes)
        file_out.close()
    return ct

# Decrypting file based on encryption mode
def decrpyt_file(cipher, input_file, output_file, mode="CBC"):
    f = open(FOLDER + input_file, "rb")
    bytes = f.read()

    pt = b''
    if(mode == "CTR"):
        pt = cipher.decrypt(bytes) # Decrypt data with CTR mode.
    else:
        pt = unpad(cipher.decrypt(bytes), AES.block_size) # Decrypt data with CBC mode.

    # Write decrypted plaintext to file.
    output_data = pt.decode("utf-8")
    file_out = open(FOLDER + output_file, "w")
    file_out.write(output_data)
    file_out.close()
    return output_data

# AES encryption with CBC and CTR modes.
def AES_Encryption(symmetric_keys):
    printHeader("=== AES ENCRYPTION === ")
    [key_1, key_2] = symmetric_keys

    # Create AES cipher object with CBC mode (128 bit).
    CBC_128_cipher = AES.new(key_1, AES.MODE_CBC) # iv will be generated randomly

    # Create AES cipher object with CBC mode (256 bit).
    CBC_256_cipher = AES.new(key_2, AES.MODE_CBC) # iv will be generated randomly
    
    # Create AES cipher object with CTR mode.
    CTR_cipher = AES.new(key_2, AES.MODE_CTR) # nonce will be generated randomly

    # Get the data from the file.
    f = open(FOLDER + "1mb_file", "r")
    input_file_data = f.read()
    file_as_bytes = input_file_data.encode('utf-8') # Convert file to bytes.

    # Encrypt file with CBC mode (128 bit) with using timer.
    start = timeit.default_timer()
    CBC_128_ciphertext = encrpyt_file(
        CBC_128_cipher, file_as_bytes, "CBC_128_cipher_encrypted")
    stop = timeit.default_timer()
    print('Encyption with CBC 128 Bit execution takes: ',
          str(round((stop - start)*1000, 2)) + " ms")

    # Encrypt file with CBC mode (256 bit) with using timer.
    start = timeit.default_timer()
    CBC_256_ciphertext = encrpyt_file(
        CBC_256_cipher, file_as_bytes, "CBC_256_cipher_encrypted")
    stop = timeit.default_timer()
    print('Encyption with CBC 256 Bit execution takes: ',
          str(round((stop - start)*1000, 2)) + " ms")

    # Encrypt file with CTR mode with using timer.
    start = timeit.default_timer()
    CTR_ciphertext = encrpyt_file(
        CTR_cipher, file_as_bytes, "CTR_cipher_encrypted", mode="CTR")
    stop = timeit.default_timer()
    print('Encyption with CTR 256 Bit execution takes: ',
          str(round((stop - start)*1000, 2)) + " ms")

    printHeader("=== AES DECRYPTION === ")
    # Decrypt file with CBC mode (128 bit, 256 bit) and CTR mode
    CBC_128_cipher_decrypted = decrpyt_file(AES.new(key_1, AES.MODE_CBC, CBC_128_cipher.iv),
                                            "CBC_128_cipher_encrypted", "CBC_128_cipher_decrypted")
    CBC_256_cipher_decrypted = decrpyt_file(AES.new(key_2, AES.MODE_CBC, CBC_256_cipher.iv),
                                            "CBC_256_cipher_encrypted", "CBC_256_cipher_decrypted")
    CTR_cipher_decrypted = decrpyt_file(AES.new(key_2, AES.MODE_CTR, nonce=CTR_cipher.nonce),
                                        "CTR_cipher_encrypted", "CTR_cipher_decrypted", mode="CTR")

    # Compare decrypted files with original file
    printColored("Decrypted file is same with original file (CBC 128 Bit):",
                 CBC_128_cipher_decrypted == input_file_data)
    printColored("Decrypted file is same with original file (CBC 256 Bit):",
                 CBC_256_cipher_decrypted == input_file_data)
    printColored("Decrypted file is same with original file (CTR 256 Bit):",
                 CTR_cipher_decrypted == input_file_data)

    printHeader("=== CHANGE IV FOR CBC 128 === ")
    printColored("Before change IV:", CBC_128_ciphertext[0:50] + "...")
    # Change IV for CBC mode (128 bit)
    CBC_128_ciphertext_2 = encrpyt_file(
        AES.new(key_1, AES.MODE_CBC, iv=get_random_bytes(16)), file_as_bytes, output_file=None)
    printColored("After change IV:", CBC_128_ciphertext_2[0:50] + "...")

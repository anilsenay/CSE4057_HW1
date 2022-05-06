from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generateSymmetricKey():
    password = b'my super secret'
    salt = get_random_bytes(16)
    keys = PBKDF2(password, salt, 48, count=1000000, hmac_hash_module=SHA512)
    key1 = keys[:16]  # 128 bit
    key2 = keys[16:]  # 256 bit
    print("Symmetric Key 1:", key1.hex())
    print("Symmetric Key 2:", key2.hex())
    return [key1, key2]


def q2a(rsa_key):
    print("\n\n === GENERATING SYMMETRIC KEYS === ")

    [key1, key2] = generateSymmetricKey()

    print("\n === ENCRPYTION SYMMETRIC KEYS === ")
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrpyted_key1 = cipher_rsa.encrypt(key1)
    encrpyted_key2 = cipher_rsa.encrypt(key2)
    print("Encrypted Key1: ", encrpyted_key1.hex())
    print("Encrypted Key2: ", encrpyted_key2.hex())

    print("\n === DECRPYTION SYMMETRIC KEYS === ")
    decrpyted_key1 = cipher_rsa.decrypt(encrpyted_key1)
    decrpyted_key2 = cipher_rsa.decrypt(encrpyted_key2)
    print("Decrypted Key1: ", decrpyted_key1.hex())
    print("Decrypted Key2: ", decrpyted_key2.hex())

    return [key1, key2]


def q2b(K_B, K_C):
    print("\n\n === GENERATING SYMMETRIC KEY FROM KB + KC === ")

    shared_key = K_B.exchange(
        ec.ECDH(), K_C.public_key())

    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bit
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    print("Derived key from (KB-) and (KC+) :", derived_key.hex())

    shared_key_2 = K_C.exchange(
        ec.ECDH(), K_B.public_key())

    # Perform key derivation.
    derived_key_2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bit
        salt=None,
        info=b'handshake data',
    ).derive(shared_key_2)

    print("Derived key from (KB+) and (KC-) :", derived_key_2.hex())

    print("Is both keys are same?", derived_key.hex() == derived_key_2.hex())

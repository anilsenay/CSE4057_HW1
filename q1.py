from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from q3 import printColored


def generate_rsa():
    keyPair = RSA.generate(1024)
    pubKey = keyPair.publickey()

    return {
        "keyPair": keyPair,
        "public": {"n": pubKey.n, "e": pubKey.e},
        "private": {"n": pubKey.n, "d": keyPair.d}
    }


def generate_ECDH():
    key1 = ec.generate_private_key(ec.SECP384R1())
    key2 = ec.generate_private_key(ec.SECP384R1())

    return [key1, key2]


def printECDH(key):
    print(printColored("public key:"), key.public_key().public_bytes(format=PublicFormat.SubjectPublicKeyInfo,
          encoding=Encoding.DER).hex())
    print(printColored("private key:"), key.private_bytes(format=PrivateFormat.TraditionalOpenSSL,
          encoding=Encoding.DER, encryption_algorithm=NoEncryption()).hex())

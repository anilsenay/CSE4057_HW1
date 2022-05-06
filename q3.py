import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES, PKCS1_OAEP

random_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed in condimentum justo, vitae suscipit tellus. Phasellus maximus odio dolor, et gravida leo congue vitae. Nam eget metus placerat, semper sem non, ultrices massa. Nullam facilisis lacinia magna vitae blandit. Vivamus varius, ante ut pretium posuere, sapien ligula dignissim mauris, non fermentum leo leo nec est. Nullam ac lectus ultrices, faucibus sapien a, maximus neque. Curabitur augue nunc, fringilla at turpis sit amet, venenatis rhoncus ante. Proin placerat odio dignissim nibh suscipit malesuada. Suspendisse a dui sit amet urna aliquet bibendum ut euismod urna. Cras ac dignissim nisl. Maecenas metus quam, placerat faucibus nulla nec, mattis tempor mauris. Fusce ac volutpat quam. Integer neque metus, dapibus porta justo ut, tempor sagittis diam. Pellentesque nibh libero, tincidunt id leo at, faucibus porttitor turpis. Nullam volutpat a erat et varius. Nullam sit amet purus vitae ex convallis suscipit at in nibh. In congue at."


def printColored(string):
    return "\033[1;32m"+string+'\033[0m'


def generate_digital_sign(rsa_key):
    print("\n === PLAINTEXT === \n", random_text[0:20] + "...")
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    print("\n === HASHING WITH SHA256 === ")
    hashed_text = hashlib.sha256(str.encode(random_text))
    print("Hashed with SHA256: ", hashed_text.hexdigest())

    # TODO
    print("\n === ENCRPYTION WITH PRIVATE KEY === ")
    encrpyted_with_rsa = cipher_rsa.encrypt(hashed_text.digest())
    print("Signed with RSA: ", encrpyted_with_rsa.hex())

    print("\n === DECRYPTION WITH PUBLIC KEY === ")
    decrpyted_with_rsa = cipher_rsa.decrypt(encrpyted_with_rsa)
    print("Decrypted with RSA: ", decrpyted_with_rsa.hex())
    print("Is same with hashed text? ",
          decrpyted_with_rsa.hex() == hashed_text.hexdigest())

    print("\n === COMPARE HASHES === ")
    print(printColored("Message(m): "), random_text[0:20] + "...")
    print(printColored("Digital Signature: "), encrpyted_with_rsa.hex())
    print(printColored("Decrypt Digital Signature and get message digest (H(m)): "),
          decrpyted_with_rsa.hex())
    hashed_text = hashlib.sha256(str.encode(random_text))
    print(printColored("Apply SHA256 to message(m): "), hashed_text.hexdigest())
    print(printColored("Is hashed message is equal to received hash?"),
          hashed_text.hexdigest() == decrpyted_with_rsa.hex())

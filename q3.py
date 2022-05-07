from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from utils import printColored, printHeader

random_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed in condimentum justo, vitae suscipit tellus. Phasellus maximus odio dolor, et gravida leo congue vitae. Nam eget metus placerat, semper sem non, ultrices massa. Nullam facilisis lacinia magna vitae blandit. Vivamus varius, ante ut pretium posuere, sapien ligula dignissim mauris, non fermentum leo leo nec est. Nullam ac lectus ultrices, faucibus sapien a, maximus neque. Curabitur augue nunc, fringilla at turpis sit amet, venenatis rhoncus ante. Proin placerat odio dignissim nibh suscipit malesuada. Suspendisse a dui sit amet urna aliquet bibendum ut euismod urna. Cras ac dignissim nisl. Maecenas metus quam, placerat faucibus nulla nec, mattis tempor mauris. Fusce ac volutpat quam. Integer neque metus, dapibus porta justo ut, tempor sagittis diam. Pellentesque nibh libero, tincidunt id leo at, faucibus porttitor turpis. Nullam volutpat a erat et varius. Nullam sit amet purus vitae ex convallis suscipit at in nibh. In congue at."

# Generate digital signature


def generate_digital_sign(rsa_key):
    printHeader("=== PLAINTEXT ===")
    print(random_text[0:20] + "...")

    printHeader("=== HASHING WITH SHA256 === ")
    hashed_text = SHA256.new(str.encode(random_text))
    printColored("Hashed with SHA256: ", hashed_text.hexdigest())

    printHeader("=== SIGN WITH PRIVATE KEY === ")
    digital_signature = pkcs1_15.new(rsa_key).sign(hashed_text)
    printColored("Signed with RSA (Digital Signature): ",
                 digital_signature.hex())

    printHeader("=== VERIFY WITH PUBLIC KEY === ")
    try:
        pkcs1_15.new(rsa_key).verify(
            hashed_text, digital_signature)
        printColored("The signature is valid.")
        printColored("Message(m): ", random_text[0:20] + "...")
        printColored("Message Digest H(m): ", hashed_text.hexdigest())
        printColored("Digital Signature: ", digital_signature.hex())

    except (ValueError, TypeError):
        print("The signature is not valid.")

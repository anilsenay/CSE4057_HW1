from Crypto.Hash import HMAC, SHA256

from utils import printColored, printHeader

# Generate Message Authentication Code
def generateMsgAuthCode(keys):
    # Question 5.a
    [key1, key2] = keys  # Use symmetric keys (K1, K2) from question 2.
    printHeader("===  Message Authentication Codes === ")
    secret = key1  #  Use key1 as secret.
    printColored("Key used for HMAC-SHA256: ", key1.hex())
    #  Apply message authentication code.
    h = HMAC.new(secret, digestmod=SHA256)

    # Question 5.b
    h.update(key2)  #  Hash and authenticate key2.
    printColored("Generated message authentication code:", h.hexdigest())

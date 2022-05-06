from Crypto.Hash import HMAC, SHA256


def generateMsgAuthCode(keys):
    [key1, key2] = keys
    print("\n\n ===  Message Authentication Codes === ")
    secret = key1
    print("Key used for HMAC-SHA256: ", key1.hex())
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(key2)
    print("Generated message authentication code:", h.hexdigest())

from q1 import generate_ECDH, generate_rsa, printECDH
from q2 import q2a, q2b
from q3 import generate_digital_sign
from q4 import AES_Encryption
from q5 import generateMsgAuthCode

# Question 1
K_A = generate_rsa()
print("public key:", K_A["public"])
print("private key:", K_A["private"])

[K_B, K_C] = generate_ECDH()
print("\n === Elliptic-Curve Diffie Helman Key Pair 1 (KB) === ")
printECDH(K_B)
print("\n === Elliptic-Curve Diffie Helman Key Pair 2 (KC) === ")
printECDH(K_C)

# Question 2
symmetric_keys = q2a(K_A["keyPair"])
q2b(K_B, K_C)

# Question 3
generate_digital_sign(K_A["keyPair"])

# Question 4
AES_Encryption(symmetric_keys)

# Question 5
generateMsgAuthCode(symmetric_keys)

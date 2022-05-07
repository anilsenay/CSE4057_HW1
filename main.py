from q1 import generate_ECDH, generate_rsa, printECDH
from q2 import q2a, q2b
from q3 import generate_digital_sign
from q4 import AES_Encryption
from q5 import generateMsgAuthCode
from utils import printColored, printHeader

# Question 1
printHeader(" === QUESTION 1.a ===", color="Magenta")
K_A = generate_rsa()
printColored("public key:", K_A["public"])
printColored("private key:", K_A["private"])

printHeader(" === QUESTION 1.b ===", color="Magenta")
[K_B, K_C] = generate_ECDH()
printHeader("=== Elliptic-Curve Diffie Helman Key Pair 1 (KB) === ")
printECDH(K_B)
printHeader("=== Elliptic-Curve Diffie Helman Key Pair 2 (KC) === ")
printECDH(K_C)

# Question 2
printHeader(" === QUESTION 2.a ===", color="Magenta")
symmetric_keys = q2a(K_A["keyPair"])

printHeader(" === QUESTION 2.b ===", color="Magenta")
q2b(K_B, K_C)

# Question 3
printHeader(" === QUESTION 3 ===", color="Magenta")
generate_digital_sign(K_A["keyPair"])

# Question 4
printHeader(" === QUESTION 4 ===", color="Magenta")
AES_Encryption(symmetric_keys)

# Question 5
printHeader(" === QUESTION 5 ===", color="Magenta")
generateMsgAuthCode(symmetric_keys)

# CSE4057 Spring 2022 - Homework 1

In this homework, we've imlemented following:

### **1) Generation of public-private key pairs.**

- a. Generate an RSA public-private key pair. 𝐾𝐴+ and 𝐾𝐴−. The length of the keys should be at least 1024 bits (the number of bits in the modulus). Provide a screenshot to show the generated keys.
- b. Generate two Elliptic-Curve Diffie Helman public-private key pairs. (𝐾𝐵+, 𝐾𝐵−) and (𝐾𝐶+, 𝐾𝐶−).

### 2) **Generation of Symmetric keys**
- a. Generate two symmetric keys using a secure key derivation function: 128 bit 𝐾1 and 256 bit 𝐾2. Print values of the keys on the screen. Encypt them with 𝐾𝐴+, print the results, and then decrypt them with 𝐾𝐴−. Again print the results. Provide a screenshot showing your results.
- b. Generate a 256 bit symmetric key using Elliptic key Diffie Helman using 𝐾𝐶+ and 𝐾𝐵−. This is 𝐾3. Generate a symmetric key using 𝐾𝐵+ and 𝐾𝐶− and show that the generated key is the same. Print value of the generated keys and provide a screenshot.

### 3) **Generation and Verification of Digital Signature**

Consider any text of at least 1000 characters. Apply SHA256 Hash algorithm (Obtain the message digest, 𝐻(𝑚)). Then encrypt it with 𝐾𝐴−. (Thus generate a digital signature.) Then verify the digital signature. (Decrypt it with 𝐾𝐴+ , apply Hash algorithm to the message, compare). Print 𝑚, 𝐻(𝑚) and digital signature on the screen. Provide a screenshot. (Or you may print in a file and provide the file). 

### 4) **AES Encryption**

Generate or find a text or image file of size at least 1MB. Now consider the following three algorithms:
- i) AES (128 bit key) in CBC mode.
- ii) AES (256 bit key) in CBC mode.
- iii) AES (256 bit key) in CTR mode.

For each of the above algorithms, do the following:
- a) Encrypt the file. Store the results (and submit it with the homework) (Note: Initialization Vector (IV) in CBC mode and nonce in CTR mode should be generated randomly, For 128 bit use 𝐾1 as the symmetric key. For 256 bit you may use either 𝐾2 or 𝐾3).
- b) Decrypt the ciphertexts and store the results. Show that they are the same as the original files.
- c) Measure the time elapsed for encryption. Write it in your report. Comment on the result. 
- d) For the first algorithm, change Initialization Vector (IV) and show that the corresponding ciphertext changes for the same plaintext (Give the result for both). 

### 5) **Message Authentication Codes**

- a) Generate a message authentication code (HMAC-SHA256) using any of the symmetric keys.
- b) Apply HMAC-SHA256 to 𝐾2 in order to generate a new 256 bit key.

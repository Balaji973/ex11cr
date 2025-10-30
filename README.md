# EX-NO-11-ELLIPTIC-CURVE-CRYPTOGRAPHY-ECC

## Aim:
To Implement ELLIPTIC CURVE CRYPTOGRAPHY(ECC)


## ALGORITHM:

1. Elliptic Curve Cryptography (ECC) is a public-key cryptography technique based on the algebraic structure of elliptic curves over finite fields.

2. Initialization:
   - Select an elliptic curve equation \( y^2 = x^3 + ax + b \) with parameters \( a \) and \( b \), along with a large prime \( p \) (defining the finite field).
   - Choose a base point \( G \) on the curve, which will be used for generating public keys.

3. Key Generation:
   - Each party selects a private key \( d \) (a random integer).
   - Calculate the public key as \( Q = d \times G \) (using elliptic curve point multiplication).

4. Encryption and Decryption:
   - Encryption: The sender uses the recipient’s public key and the base point \( G \) to encode the message.
   - Decryption: The recipient uses their private key to decode the message and retrieve the original plaintext.

5. Security: ECC’s security relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP), making it highly secure with shorter key lengths compared to traditional methods like RSA.

## Program:
```
import hashlib
import secrets

# --- Elliptic Curve Parameters (secp256k1) ---
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ---------- Helper Functions ----------
def inv_mod(x, p_mod=p):
    return pow(x, p_mod - 2, p_mod)

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        s = (3 * x1 * x1 + a) * inv_mod(2 * y1) % p
    else:
        s = (y2 - y1) * inv_mod(x2 - x1) % p
    xr = (s * s - x1 - x2) % p
    yr = (s * (x1 - xr) - y1) % p
    return (xr, yr)

def scalar_mult(k, P):
    result = None
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def derive_keystream(shared_x, length):
    out = b''
    counter = 0
    shared_bytes = int_to_bytes(shared_x)
    while len(out) < length:
        ctr_b = counter.to_bytes(4, 'big')
        out += hashlib.sha256(shared_bytes + ctr_b).digest()
        counter += 1
    return out[:length]

def ecdh_shared_secret(priv_d, pub_Q):
    S = scalar_mult(priv_d, pub_Q)
    xS, _ = S
    return xS

# ---------- Key Generation ----------
def generate_keypair():
    d = secrets.randbelow(n - 1) + 1
    Q = scalar_mult(d, G)
    return d, Q

# ---------- Encryption & Decryption ----------
def encrypt(pub_Q, plaintext: bytes):
    k = secrets.randbelow(n - 1) + 1
    R = scalar_mult(k, G)
    shared_x = ecdh_shared_secret(k, pub_Q)
    keystream = derive_keystream(shared_x, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    return R, ciphertext

def decrypt(priv_d, R, ciphertext):
    shared_x = ecdh_shared_secret(priv_d, R)
    keystream = derive_keystream(shared_x, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    return plaintext

# ---------- MAIN PROGRAM ----------
if __name__ == "__main__":
    print("=== ECC ENCRYPTION & DECRYPTION DEMO ===")

    # Generate keys
    d_A, Q_A = generate_keypair()

    # Get data from user
    user_input = input("\nEnter data to encrypt: ").encode()

    # Encrypt
    R, encrypted_data = encrypt(Q_A, user_input)

    # Decrypt
    decrypted_data = decrypt(d_A, R, encrypted_data)

    # Show results
    print("\n----------------------------------------")
    print(" Encrypted Data (hex):", encrypted_data.hex())
    print(" Decrypted Data:", decrypted_data.decode())
    print("----------------------------------------")

    if decrypted_data == user_input:
        print(" Decryption successful! Original data restored.")
    else:
        print("Decryption failed!")

```




## Output:
<img width="817" height="360" alt="image" src="https://github.com/user-attachments/assets/ef80ef2f-665f-4ccc-988d-2ab63a6e038a" />



## Result:
The program is executed successfully


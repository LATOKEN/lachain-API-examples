from pycoin.ecdsa import generator_secp256k1, sign, verify
import hashlib, secrets
from pycoin.ecdsa import possible_public_pairs_for_signature

def sha3_256Hash(msg):
    hashBytes = hashlib.sha3_256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")

def signECDSAsecp256k1(msg, privKey):
    msgHash = sha3_256Hash(msg)
    signature = sign(generator_secp256k1, privKey, msgHash)
    return signature

def verifyECDSAsecp256k1(msg, signature, pubKey):
    msgHash = sha3_256Hash(msg)
    valid = verify(generator_secp256k1, pubKey, msgHash, signature)
    return valid

def recoverPubKeyFromSignature(msg, signature):
    msgHash = sha3_256Hash(msg)
    recoveredPubKeys = possible_public_pairs_for_signature(
        generator_secp256k1, msgHash, signature)
    return recoveredPubKeys

# ECDSA sign message (using the curve secp256k1 + SHA3-256)
msg = "Message for ECDSA signing"
# privKey = secrets.randbelow(generator_secp256k1.order())
privKey = int("0xf51c2102b2fdb679425addea24dc03750b208dd9e60b8cc9bedbdd003ebd3c05", 16)
signature = signECDSAsecp256k1(msg, privKey)

print("privKey original: ", privKey)
print("Message:", msg)
print("Private key:", hex(privKey))
print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))

# ECDSA verify signature (using the curve secp256k1 + SHA3-256)
pubKey = (generator_secp256k1 * privKey).pair()
valid = verifyECDSAsecp256k1(msg, signature, pubKey)
print("\nMessage:", msg)
print("Public key: (" + hex(pubKey[0]) + ", " + hex(pubKey[1]) + ")")
print("Signature valid?", valid)

# ECDSA verify tampered signature (using the curve secp256k1 + SHA3-256)
msg = "Tampered message"
valid = verifyECDSAsecp256k1(msg, signature, pubKey)
print("\nMessage:", msg)
print("Signature (tampered msg) valid?", valid)

# public key recovery 
msg = "Message for ECDSA signing"
recoveredPubKeys = recoverPubKeyFromSignature(msg, signature)
print("\nMessage:", msg)
print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))
for pk in recoveredPubKeys:
    print("Recovered public key from signature: (" +
          hex(pk[0]) + ", " + hex(pk[1]) + ")")
import eth_keys, os
from base64 import b64encode
from eth_account.messages import encode_defunct
from eth_utils import decode_hex, encode_hex

# Generate the private + public key pair (using the secp256k1 curve)

priv = "0xf51c2102b2fdb679425addea24dc03750b208dd9e60b8cc9bedbdd003ebd3c05"
privateBytes = decode_hex(priv)
print("priv: ", priv)

signerPrivKey = eth_keys.keys.PrivateKey(privateBytes)
signerPubKey = signerPrivKey.public_key
print('Private key (64 hex digits):', signerPrivKey)
print('Public key (uncompressed, 128 hex digits):', signerPubKey)

# ECDSA sign message (using the curve secp256k1 + Keccak-256)
msg = b'Message for signing'
signature = signerPrivKey.sign_msg(msg)
print('Message:', msg)
print("signature: ", str(signature))
print('Signature: [r = {0}, s = {1}, v = {2}]'.format(
    hex(signature.r), hex(signature.s), hex(signature.v)))

# ECDSA public key recovery from signature + verify signature
# (using the curve secp256k1 + Keccak-256 hash)
msg = b'Message for signing'
recoveredPubKey = signature.recover_public_key_from_msg(msg)
print('Recovered public key (128 hex digits):', recoveredPubKey)
print('Public key correct?', recoveredPubKey == signerPubKey)
valid = signerPubKey.verify_msg(msg, signature)
print("Signature valid?", valid)
import ecdsa
from hashlib import sha256

message = "083867478cb0d1d8bb864175bbc49728cffcc114bc2e762c6df64f2c965a9a66"
public_key = '042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabb'
sig = '30450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e'

vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1, hashfunc=sha256) # the default is sha1
vk.verify(bytes.fromhex(sig), bytes.fromhex(message), sha256) # True
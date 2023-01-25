from eth_utils import decode_hex
from eth_utils import encode_hex
import random
from eth_keys import keys

def random_private_key():
    key = ""
    for _ in range(64):
        digit = hex(random.randint(0,15))
        key = key + digit[2]

    return key
        


if __name__ == "__main__":
    private_key = random_private_key()
    print("private key: " + format(private_key))
    private_key_bytes = decode_hex(private_key)
    public_key_compressed = encode_hex(keys.PrivateKey(private_key_bytes).public_key.to_compressed_bytes())
    print("public key: " + format(public_key_compressed))
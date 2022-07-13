from time import time
import web3
from eth_utils import decode_hex
import requests
import json
import random
from eth_keys import keys
from eth_account.messages import encode_defunct
import hashlib

from pycoin.ecdsa import generator_secp256k1, sign, verify

url = 'http://localhost:7070'

def transaction_builder():
    transaction = {
                "jsonrpc": "2.0" ,
                "method": "eth_sendTransaction" ,
                "params":{
                            "from" : "0x84c5ede5846efd970ea777c1122ef130b4af2bdd",
                            "to": "0xDA9B931dAA5c211004240C0aCEFE8363176E99B4",
                            "value": "0x17487",
                            "data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
                            "gas":"0x2e1a62",
                            "gasPrice": "0x9184e72a000"
                        },
                 "id": 1,
            };
    return transaction

def generate_private_key():
    private_key_str = "0xf6dc8354461516787436f03dbf70d61fd9662316dc6a39191baab7814459edf2"
    key_bytes = decode_hex(private_key_str)
    return keys.PrivateKey(key_bytes)

def sign_random_message(msg):
    signable = encode_defunct(text = msg)
    # print(signable)
    private_key = generate_private_key()
    signed = web3.eth.Account.sign_message(signable , private_key.to_hex())
    return signed.signature.hex()

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

def sign_message(tx, timestamp):
    serializedParams = ""
    
    for tx_param in tx['params']:
        serializedParams += tx_param + tx['params'][tx_param]

    serializedParams = tx['method'] + serializedParams + timestamp
    
    print("serialized params: ", serializedParams)

    private_key_str = "0xf6dc8354461516787436f03dbf70d61fd9662316dc6a39191baab7814459edf2"
    signature = signECDSAsecp256k1(serializedParams, int(private_key_str, 16))
    
    print("signature: ", signature)
    
    return signature
    
tx = transaction_builder()

# tx_str = json.dumps(tx)
# signature = sign_random_message(tx_str)

timestamp = str(int(time()))
signature = sign_message(tx, timestamp)

headers = {'Content-type': 'application/json',
           'Signature': str(signature),
           'Timestamp': timestamp}

response = requests.post(url, json=tx, headers = headers)

print(response.json())

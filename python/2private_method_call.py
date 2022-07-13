from time import time
import web3
from eth_utils import decode_hex
import requests
from eth_keys import keys
from eth_account.messages import encode_defunct
from eth_utils import decode_hex
import eth_keys, os

URL = 'http://localhost:7070'
PRIVATE_KEY = "0xf51c2102b2fdb679425addea24dc03750b208dd9e60b8cc9bedbdd003ebd3c05"
PRIVATE_KEY_BYTES = decode_hex(PRIVATE_KEY)

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

def serializedTx(tx, timestamp):
    serializedParams = ""
    
    for tx_param in tx['params']:
        serializedParams += tx_param + tx['params'][tx_param]

    serializedParams = tx['method'] + serializedParams + timestamp
    
    return serializedParams


# Main
tx = transaction_builder()
timestamp = str(int(time()))

messageToSign = serializedTx(tx, timestamp)
print("messageToSign: ", messageToSign)
messageToSignBytes = str.encode(messageToSign)

# Signing
signerPrivKey = eth_keys.keys.PrivateKey(PRIVATE_KEY_BYTES)
signerPubKey = signerPrivKey.public_key
print('Private key (64 hex digits):', signerPrivKey)
print('Public key (uncompressed, 128 hex digits):', signerPubKey)

signature = signerPrivKey.sign_msg(messageToSignBytes)

print("signature: ", signature)
print('Signature: [r = {0}, s = {1}, v = {2}]'.format(
    hex(signature.r), hex(signature.s), hex(signature.v)))


headers = {'Content-type': 'application/json',
           'Signature': str(signature),
           'Timestamp': timestamp}

response = requests.post(URL, json=tx, headers = headers)

# print(response.json())

from time import time
from numpy import sign
#from sqlalchemy import null
import web3
from eth_utils import decode_hex
import requests
import json
import random
from eth_keys import keys
from eth_account.messages import encode_defunct

url = 'http://localhost:7070'

def transaction_builder():
    transaction = {
                "jsonrpc": "2.0" ,
                "method": "eth_sendTransaction" ,
                "params": 
                    [{
                        "from" : "0x73ba7dd59432eb32cb99db02e339f679eacb4514",
                        "to": "0xDA9B931dAA5c211004240C0aCEFE8363176E99B4",
                        "value": "0x174876",
                        "data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
                        "gas":"0x2e1a62",
                        "gasPrice": "0x9184e72a000"
                    } ],
                 "id": 1,
            };
    return transaction

def get_random_hex_message(len):
    len = len * 2
    msg = "0x"
    for x in range(len):
        digit = hex(random.randint(0,15))
        msg = msg + digit[2]
    return msg

def generate_private_key():
    private_key_str = "0xa427dff0b296ab52adce3ba144f6646096dce9b24a035e008b25ac04e516c32a"
    key_bytes = decode_hex(private_key_str)
    return keys.PrivateKey(key_bytes)

def sign_random_message(msg):
    signable = encode_defunct(text = msg)
    # print(signable)
    private_key = generate_private_key()
    signed = web3.eth.Account.sign_message(signable , private_key.to_hex())
    return signed.signature.hex()

tx = transaction_builder()
tx_str = json.dumps(tx)

signature = sign_random_message(tx_str)
timestamp = str(int(time()))

print(signature)
print(timestamp)

headers = {'Content-type': 'application/json',
           'Signature': signature,
           'Timestamp': timestamp}

response = requests.post(url, json=tx, headers = headers)

print(response.json())

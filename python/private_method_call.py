from time import time
import web3
import requests
import json
import random
import hashlib
from eth_account.messages import encode_defunct

url = 'http://localhost:7070'

def transaction_builder():
    transaction = {
                "jsonrpc": "2.0" ,
                "method": "clearInMemoryPool" ,
                "params":{
                        },
                 "id": 1,
            };
    return transaction


def sign_message(tx, timestamp):
    serializedParams = ""
    
    for tx_param in tx['params']:
        serializedParams += tx_param + tx['params'][tx_param]

    serializedParams = tx['method'] + serializedParams + timestamp
    
    print("serialized params: ", serializedParams)
    
    signed = web3.eth.Account.sign_message(encode_defunct(text=serializedParams), "c68a57399035e8ec8c7d7d3944c2d708b6d788dd6ac93628092afefb8cdc43f4")
    
    print("signed: ", signed)
    
    return signed.signature.hex()
    
tx = transaction_builder()
timestamp = str(int(time()))
signature = sign_message(tx, timestamp)

print(signature)
print(timestamp)

headers = {'Content-type': 'application/json',
           'Signature': signature,
           'Timestamp': timestamp}

response = requests.post(url, json=tx, headers = headers)

print(response.json())

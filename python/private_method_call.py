import web3
from eth_utils import decode_hex
import requests
import json

url = 'http://localhost:7070'

def transaction_builder():
    transaction = {
                "jsonrpc": "2.0" ,
                "method": "eth_sendTransaction" ,
                "params": 
                    [{
                        "from" : "0x87b74be043eba0ae3f0fef0758e8cd1388cf928a",
                        "to": "0xDA9B931dAA5c211004240C0aCEFE8363176E99B4",
                        "value": "0x9184e72a",
                        "data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
                        "gas":"0x2e1a62",
                        "gasPrice": "0x9184e72a000"
                    } ],
                 "id": 1,
            };
    return transaction

tx = transaction_builder()
# private_key_bytes = decode_hex('0xd95d6db65f3e2223703c5d8e205d98e3e6b470f067b0f94f6c6bf73d4301ce48')
# signed_tx = web3.eth.Account.signTransaction(tx, private_key_bytes)

# print(signed_tx)

response = requests.post(url, json=tx)

print(response.json())

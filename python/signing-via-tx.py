from inspect import signature
from itertools import chain
from sys import byteorder
from time import time
import web3
from eth_utils import decode_hex, encode_hex
import requests
import json
import random
from eth_keys import keys
from eth_account.messages import encode_defunct
import hashlib

url = 'http://localhost:7070'

session = requests.Session()
def send_api_request_to_address(address, params , method):
    payload= {"jsonrpc":"2.0",
           "method":method,
           "params":params,
           "id":0}
    
    headers = {'Content-type': 'application/json'}
    response = session.post(address, json=payload, headers=headers)
    try:
        res = response.json()['result']
        return res
    except Exception as eer:
        print(response.json())
        print("exception: " + format(eer))
        return eer

def send_api_request(params , method):
    return send_api_request_to_address(url, params, method)

def get_chain_id():
    return int(send_api_request([], "eth_chainId"), 16)

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
    private_key_str = "0x9d46152bc41c5f429946236befa7a1e5bc11036987d290790f4d8afdc7663162"
    key_bytes = decode_hex(private_key_str)
    return key_bytes

def sign_message(tx, timestamp):
    serializedParams = ""
    
    for tx_param in tx['params']:
        serializedParams += tx_param + tx['params'][tx_param]

    serializedParams = tx['method'] + serializedParams + timestamp
    
    print("serialized params: ", serializedParams)
    
    
    encoded = serializedParams.encode('utf-8')
    print("bytes: " + format(encoded))
    hex_msg = encode_hex(encoded)
    print("hex: " + hex_msg)
    transaction = {
        "chainId": chain_id,
        "data": hex_msg,
        "gas": 0,
        "gasPrice": 0,
        "nonce": 0
    }
    private_key_bytes = generate_private_key()
    signed_tx = web3.eth.Account.signTransaction(transaction, private_key_bytes)
    print(signed_tx)
    r = signed_tx.r
    s = signed_tx.s
    v = signed_tx.v
    r_bytes = r.to_bytes(length=32,byteorder='big')
    s_bytes = s.to_bytes(length=32,byteorder='big')
    v_bytes = v.to_bytes(length=2,byteorder='big')
    if (chain_id <= 109):
        v_bytes = v.to_bytes(length=1,byteorder='big')
    signature = r_bytes + s_bytes + v_bytes
    print("signature bytes: " + format(signature) + " " + format(len(signature)))
    print("signature hex: " + encode_hex(signature))
    return encode_hex(signature)

chain_id = get_chain_id()
    
tx = transaction_builder()

timestamp = str(int(time()))
signature = sign_message(tx, timestamp)

headers = {'Content-type': 'application/json',
           'Signature': signature,
           'Timestamp': timestamp}

response = requests.post(url, json=tx, headers = headers)

print(response.json())

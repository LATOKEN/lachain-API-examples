from collections.abc import Iterable, Mapping
from time import time
import eth_keys
import requests

# change the url to the node address
# don't use rpc-mainnet.lachain.io because this will target a random node
url = 'http://localhost:7070'

# put private key here
api_private_key = ""
# "deleteTransactionPoolRepository"
# "clearInMemoryPool"

def clearInMemoryPool():
    return {
            "jsonrpc": "2.0",
            "method": "clearInMemoryPool",
            "params": [],
                # {
                #     # "rawTxs": [
                #     #     "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
                #     #     "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
                #     # ]
                # },
             "id": 1,
        }

def deleteTransactionPoolRepository():
    return {
            "jsonrpc": "2.0",
            "method": "deleteTransactionPoolRepository",
            "params": [],
                # {
                #     # "rawTxs": [
                #     #     "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
                #     #     "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
                #     # ]
                # },
             "id": 1,
        }

# this serialization may not work for other methods
def serialize(params):
    serialized = ""
    if (params is None):
        return ""
    elif isinstance(params, str):
        return params
    elif isinstance(params, Mapping):
        for key, value in params.items():
            serialized += serialize(key)
            serialized += serialize(value)
    elif isinstance(params, Iterable):
        for item in params:
            serialized += serialize(item)
    else:
        serialized += str(params)
    return serialized


def sign_request(request, timestamp):
    serializedParams = request['method'] + serialize(request['params']) + timestamp
    print("serialized params: ", serializedParams)

    signerPrivKey = eth_keys.keys.PrivateKey(bytes.fromhex(api_private_key))
    signature = signerPrivKey.sign_msg(serializedParams.encode('ascii'))
    return signature.to_hex()


tx = deleteTransactionPoolRepository()
timestamp = str(int(time()))
signature = sign_request(tx, timestamp)
print("Signature:", signature)

headers = {'Content-type': 'application/json',
           'Signature': signature,
           'Timestamp': timestamp}

response = requests.post(url, json=tx, headers = headers)

print(response.json())

tx = clearInMemoryPool()
timestamp = str(int(time()))
signature = sign_request(tx, timestamp)
print("Signature:", signature)

headers = {'Content-type': 'application/json',
           'Signature': signature,
           'Timestamp': timestamp}

response = requests.post(url, json=tx, headers = headers)

print(response.json())

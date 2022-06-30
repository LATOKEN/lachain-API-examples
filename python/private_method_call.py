from time import time
import ecdsa
import hashlib
import sha3
import requests

url = 'http://88.99.86.166:7070'

api_private_key = "c68a57399035e8ec8c7d7d3944c2d708b6d788dd6ac93628092afefb8cdc43f4"


def request_builder():
    return {
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params":
                {
                    "opts": {
                        "from": "0x87b74be043eba0ae3f0fef0758e8cd1388cf928a",
                        "to": "0xDA9B931dAA5c211004240C0aCEFE8363176E99B4",
                        "value": "0x9184e72a",
                        "data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
                        "gas": "0x2e1a62",
                        "gasPrice": "0x9184e72a000"
                    }
                },
             "id": 1,
        }


def serialize_json(params):
    if isinstance(params, str) or isinstance(params, int):
        return str(params)
    result = ""
    for field in params:
        result += field + serialize_json(params[field])
    return result


def sign_request(request, timestamp):
    serializedParams = request['method'] + serialize_json(request['params']) + timestamp
    print("serialized params: ", serializedParams)

    keccak_obj = sha3.keccak_256()
    keccak_obj.update(serializedParams.encode('ascii'))
    h = keccak_obj.digest()
    print("Hash:",  h.hex())
    sk = ecdsa.SigningKey.from_string( bytes.fromhex(api_private_key), curve=ecdsa.SECP256k1)
    signature = sk.sign_digest(h)
    return signature.hex()


tx = request_builder()
timestamp = str(int(time()))
signature = sign_request(tx, timestamp)

print(signature)
print(timestamp)

headers = {'Content-type': 'application/json',
           'Signature': signature,
           'Timestamp': timestamp}

response = requests.post(url, json=tx, headers = headers)

print(response.json())

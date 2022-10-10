from time import time
import eth_keys
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

# this serialization may not work for other methods
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

    signerPrivKey = eth_keys.keys.PrivateKey(bytes.fromhex(api_private_key))
    signature = signerPrivKey.sign_msg(serializedParams.encode('ascii'))
    return signature.to_hex()


tx = request_builder()
timestamp = str(int(time()))
signature = sign_request(tx, timestamp)
print("Signature:", signature)

headers = {'Content-type': 'application/json',
           'Signature': signature,
           'Timestamp': timestamp}

response = requests.post(url, json=tx, headers = headers)

print(response.json())

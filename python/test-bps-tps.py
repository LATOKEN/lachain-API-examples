import web3
from eth_keys import keys
import eth_utils
from eth_utils import decode_hex
from jsonrpcclient import request
import requests
import time
import ethereum
import random

# Local
LOCALNET_NODE = "http://localhost:7070"
# LOCALNET_NODE = "http://localhost:7071"
# LOCALNET_NODE = "http://localhost:7072"
# LOCALNET_NODE = "http://localhost:7073"
# Local


NODE = web3.Web3(web3.Web3.HTTPProvider(LOCALNET_NODE))
SESSION = requests.Session()
def send_api_request_to_address(address, params , method):
    payload= {"jsonrpc":"2.0",
           "method":method,
           "params":params,
           "id":0}
    
    headers = {'Content-type': 'application/json'}
    print(payload)
    response = SESSION.post(address, json=payload, headers=headers)
    try:
        res = response.json()['result']
        return res
    except Exception as eer:
        print(response.json())
        print("exception: " + format(eer))
        return eer

def send_api_request(params , method):
    return send_api_request_to_address(LOCALNET_NODE, params, method)

def block_by_number(block, full_tx):
    return send_api_request([ block, full_tx ] , "eth_getBlockByNumber")

def block_by_hash(block, full_tx):
    return send_api_request([ block, full_tx ] , "eth_getBlockByHash")

def block_number():
    return send_api_request([] , "eth_blockNumber")

def tx_receipt(tx_hash):
    return send_api_request([ tx_hash ] , "eth_getTransactionReceipt")

def tx_by_hash(tx_hash):
    return send_api_request([ tx_hash ] , "eth_getTransactionByHash")

def fe_get_balance(address):
    return send_api_request([ address ] , "fe_getBalance")

def get_validators():
    return send_api_request([] , "bcn_validators")

def test(block):
    return send_api_request([ block ] , "testing")

def get_validators():
    return send_api_request([] , "bcn_validators")

def la_validator_info(pubkey):
    return send_api_request([ pubkey ] , "la_validator_info")

def get_balance(address):
    return send_api_request([address , "latest"] , "eth_getBalance")

def update_nonce(address):
    method = "eth_getTransactionCount"
    params = [
        address,
        "latest"
    ]
    nonce = send_api_request(params , method)
    int_nonce = nonce
    params = [
        address,
        "pending"
    ]
    nonce = send_api_request(params , method)
    int_nonce = max(int_nonce , nonce)
    return int_nonce

def get_chain_id():
    return int(send_api_request([], "eth_chainId"), 16)


if __name__ == "__main__":
    last_block_number = block_number()
    last_block = block_by_number(last_block_number, False)
    last_timestamp = int(last_block['timestamp'], 16)

    import json, datetime
    print(json.dumps(last_block, indent = 4))
    print(last_timestamp)
    print(datetime.datetime.fromtimestamp(last_timestamp))
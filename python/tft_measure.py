#! /usr/bin/env python

from ast import arg
import web3
from eth_keys import keys
import eth_utils
from eth_utils import decode_hex
from jsonrpcclient import request
import requests
import time
import ethereum
import random

LOCALNET_NODES = [
    "http://localhost:7070",
    "http://localhost:7071",
    "http://localhost:7072",
    "http://localhost:7073"
]

class API:
    def __init__(self, LOCALNET_NODE):
        self.LOCALNET_NODE = LOCALNET_NODE
        self.NODE = web3.Web3(web3.Web3.HTTPProvider(self.LOCALNET_NODE))
        self.SESSION = requests.Session()
    
    def send_api_request_to_address(self, address, params , method):
        payload= {"jsonrpc":"2.0",
            "method":method,
            "params":params,
            "id":0}
        
        headers = {'Content-type': 'application/json'}
        response = self.SESSION.post(address, json=payload, headers=headers)
        try:
            res = response.json()['result']
            return res
        except Exception as eer:
            print(response.json())
            print("exception: " + format(eer))
            return eer

    def send_api_request(self, params , method):
        return self.send_api_request_to_address(self.LOCALNET_NODE, params, method)

    def block_by_number(self, block, full_tx):
        return self.send_api_request([ block, full_tx ] , "eth_getBlockByNumber")

    def block_by_hash(self, block, full_tx):
        return self.send_api_request([ block, full_tx ] , "eth_getBlockByHash")

    def block_number(self, ):
        return self.send_api_request([] , "eth_blockNumber")

    def tx_receipt(self, tx_hash):
        return self.send_api_request([ tx_hash ] , "eth_getTransactionReceipt")

    def tx_by_hash(self, tx_hash):
        return self.send_api_request([ tx_hash ] , "eth_getTransactionByHash")

    def fe_get_balance(self, address):
        return self.send_api_request([ address ] , "fe_getBalance")

    def test(self, block):
        return self.send_api_request([ block ] , "testing")

    def get_validators(self):
        return self.send_api_request([] , "bcn_validators")

    def la_validator_info(self, pubkey):
        return self.send_api_request([ pubkey ] , "la_validator_info")

    def get_balance(self, address):
        return self.send_api_request([address , "latest"] , "eth_getBalance")

    def update_nonce(self, address):
        method = "eth_getTransactionCount"
        params = [
            address,
            "latest"
        ]
        nonce = self.send_api_request(params , method)
        int_nonce = nonce
        params = [
            address,
            "pending"
        ]
        nonce = self.send_api_request(params , method)
        int_nonce = max(int_nonce , nonce)
        return int_nonce

    def get_chain_id(self):
        return int(self.send_api_request([], "eth_chainId"), 16)



def get_address_from_private_key(private_key_byte_or_hex):
    acct = web3.eth.Account.from_key(private_key_byte_or_hex)
    return acct.address



LOCALNET_NODE = LOCALNET_NODES[0]
api = API(LOCALNET_NODE)

staker_private_key_bytes = decode_hex('0xd95d6db65f3e2223703c5d8e205d98e3e6b470f067b0f94f6c6bf73d4301ce48')
private_keys = [
    decode_hex('0xa9cc22d218158125135bd8cc3bac305fa19f488c4eaab5a42ff3d7836bf67e1c'),
    decode_hex('0xaa13e71bbfd2604fc2fce35c63fa623dcf3449077cb74dfa50a452773b2bac1e'),
    decode_hex('0x9a3654fb8293a2c9c6bfce3621222b17c2c40a378140c2a898f9c0cfaa10c785'),
    decode_hex('0xcc451b88529a34524a9a0aa2e544571fbcaafb3167553f6e1821601d1b9f9857')
]

staker_address = get_address_from_private_key(staker_private_key_bytes)
addresses = [get_address_from_private_key(private_key) for private_key  in private_keys]
chain_id = api.get_chain_id()


def transaction_builder(from_address, to_address, amount, gas_price, nonce):
    transaction = {
        "from": from_address,
        "to": to_address,
        "value": amount,
        "gas": 100000000,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": chain_id
    }
    return transaction

def send_coins(private_key_bytes, to_address, amount, tx_count = 1):
    staker_private_key = keys.PrivateKey(private_key_bytes)    
    staker_address = staker_private_key.public_key.to_checksum_address()
    
    print("\n===============================================================================================================")
    print("Sending amount %d from %s to %s using %s"%(amount, staker_address, to_address, LOCALNET_NODE))
    print("Repeat %d times"%(tx_count))
    
    int_nonce = int(api.update_nonce(staker_address), 16)

    for count in range(0, tx_count):
        cur_nonce = count + int_nonce
        transaction = transaction_builder(staker_address, to_address, amount, 1, cur_nonce)
        print("Transaction ", count+1, ": ", transaction)
        signed_tx = web3.eth.Account.signTransaction(transaction, private_key_bytes)
        raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)

        try:
            tx_hash = api.send_api_request([raw_tx] , "eth_sendRawTransaction")
            print("Sent Request! tx hash: " + format(tx_hash) + "\n")
        except Exception as eer:
            print(eer)
            return False
        
        if (count == tx_count - 1):
            try:
                connection = web3.Web3(web3.Web3.HTTPProvider(LOCALNET_NODE))
                tx_receipt = connection.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
                # print(tx_receipt)
                print("Successfully sent all transactions")
                print("===============================================================================================================\n")

                return True
            except Exception as eer:
                print(eer)
                return False

def get_args():
    import argparse
    parser = argparse.ArgumentParser(description='Script for measuring txn finality time')

    # Required positional argument
    parser.add_argument('command', type=str,
                        help='should be one of check, send_all')

    # Optional argument
    parser.add_argument('--node', type=str,
                        help='Address of the node to use')
    
    # Optional argument
    parser.add_argument('--amount', type=int,
                        help='Amount to send (for send_all)')
    
    # Optional argument
    parser.add_argument('--id', type=int,
                        help='Node Id')
    
    # Optional argument
    parser.add_argument('--cnt', type=int,
                        help='Number of transactions')

    return parser.parse_args()



args = get_args()
if args.id:
    api = API(LOCALNET_NODES[args.id])
if (args.command == "check"):
    print("Staker (%s) has balance = %s"%(staker_address, int(api.get_balance(staker_address), 16)))
    for i in range(len(private_keys)):
        print("Address %d(%s) has balance = %s"%(i, addresses[i], int(api.get_balance(addresses[i]), 16)))
    

elif (args.command == "send_all"):
    assert(args.amount is not None)
    amount = args.amount
    for i in range(len(private_keys)):
        send_coins(staker_private_key_bytes, addresses[i], amount)
    
    print("Staker (%s) has balance = %s"%(staker_address, int(api.get_balance(staker_address), 16)))
    for i in range(len(private_keys)):
        print("Address %d(%s) has balance = %s"%(i, addresses[i], int(api.get_balance(addresses[i]), 16)))
    
elif (args.command == "flood"):
    assert(args.id is not None and args.amount is not None and args.cnt is not None)
    id = args.id
    amount = args.amount
    count = args.cnt
    private_key = private_keys[id]
    send_coins(private_key, staker_address, amount, count)

elif (args.command == "measure"):
    last_block = int(api.block_number(),16)
    for i in range(10):
        print(api.block_by_number(last_block))    

else:
    print("Invalid command")




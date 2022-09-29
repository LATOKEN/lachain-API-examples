import web3
from eth_keys import keys
import eth_utils
from eth_utils import decode_hex
from jsonrpcclient import request
import requests
import time
import ethereum
import random

LOCALNET_NODE = "http://localhost:7070"


NODE = web3.Web3(web3.Web3.HTTPProvider(LOCALNET_NODE))
SESSION = requests.Session()
def send_api_request_to_address(address, params , method):
    payload= {"jsonrpc":"2.0",
           "method":method,
           "params":params,
           "id":0}
    
    headers = {'Content-type': 'application/json'}
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


def get_address_from_private_key(private_key_byte_or_hex):
    acct = web3.eth.Account.from_key(private_key_byte_or_hex)
    return acct.address


def transaction_builder(from_address, to_address, amount, gas_price, nonce, chain_id):
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
    
    print("\n===========================================================================================")
    print("Sending amount %d from %s to %s using %s"%(amount, staker_address, to_address, LOCALNET_NODE))
    
    int_nonce = int(update_nonce(staker_address), 16)
    chain_id = get_chain_id()

    for count in range(0, tx_count):
        cur_nonce = count + int_nonce
        transaction = transaction_builder(staker_address, to_address, amount, 1, cur_nonce, chain_id)
        print("Transaction ", count+1, ": ", transaction)
        signed_tx = web3.eth.Account.signTransaction(transaction, private_key_bytes)
        raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)

        try:
            tx_hash = send_api_request([raw_tx] , "eth_sendRawTransaction")
            print("Successful! tx hash: " + format(tx_hash) + "\n")
        except Exception as eer:
            print(eer)
            return False
        
        if (count == tx_count - 1):
            try:
                connection = web3.Web3(web3.Web3.HTTPProvider(LOCALNET_NODE))
                tx_receipt = connection.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
                # print(tx_receipt)
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

    return parser.parse_args()





staker_private_key_bytes = decode_hex('0xd95d6db65f3e2223703c5d8e205d98e3e6b470f067b0f94f6c6bf73d4301ce48')
private_key_1 = decode_hex('0xa9cc22d218158125135bd8cc3bac305fa19f488c4eaab5a42ff3d7836bf67e1c')
private_key_2 = decode_hex('0xaa13e71bbfd2604fc2fce35c63fa623dcf3449077cb74dfa50a452773b2bac1e')
private_key_3 = decode_hex('0x9a3654fb8293a2c9c6bfce3621222b17c2c40a378140c2a898f9c0cfaa10c785')
private_key_4 = decode_hex('0xcc451b88529a34524a9a0aa2e544571fbcaafb3167553f6e1821601d1b9f9857')

staker_address = get_address_from_private_key(staker_private_key_bytes)
address_1 = get_address_from_private_key(private_key_1)
address_2 = get_address_from_private_key(private_key_2)
address_3 = get_address_from_private_key(private_key_3)
address_4 = get_address_from_private_key(private_key_4)


args = get_args()
if (args.command == "check"):
    print("Staker (%s) has balance = %s"%(staker_address, int(get_balance(staker_address), 16)))
    print("Address 1(%s) has balance = %s"%(address_1, int(get_balance(address_1), 16)))
    print("Address 2(%s) has balance = %s"%(address_2, int(get_balance(address_2), 16)))
    print("Address 3(%s) has balance = %s"%(address_3, int(get_balance(address_3), 16)))
    print("Address 4(%s) has balance = %s"%(address_4, int(get_balance(address_4), 16)))
    

elif (args.command == "send_all"):
    amount = args.amount
    send_coins(staker_private_key_bytes, address_1, amount)
    send_coins(staker_private_key_bytes, address_2, amount)
    send_coins(staker_private_key_bytes, address_3, amount)
    send_coins(staker_private_key_bytes, address_4, amount)


    print("Staker (%s) has balance = %s"%(staker_address, int(get_balance(staker_address), 16)))
    print("Address 1(%s) has balance = %s"%(address_1, int(get_balance(address_1), 16)))
    print("Address 2(%s) has balance = %s"%(address_2, int(get_balance(address_2), 16)))
    print("Address 3(%s) has balance = %s"%(address_3, int(get_balance(address_3), 16)))
    print("Address 4(%s) has balance = %s"%(address_4, int(get_balance(address_4), 16)))
    
elif (args.command == "send_all"):
    last_block_number = block_number()
    last_block = block_by_number(last_block_number, False)
    last_timestamp = int(last_block['timestamp'], 16)

    import json, datetime
    print(json.dumps(last_block, indent = 4))
    print(last_timestamp)
    print(datetime.datetime.fromtimestamp(last_timestamp))
else:
    print("Invalid command")




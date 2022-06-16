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
#LOCALNET_NODE = "http://localhost:7071"
LOCALNET_NODE = "http://localhost:7070"
#LOCALNET_NODE = "http://localhost:7072"
#LOCALNET_NODE = "http://localhost:7073"
# Local

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

def send_raw_tx(raw_tx):
    return send_api_request([raw_tx], "eth_sendRawTransaction")

def tx_by_hash(tx_hash):
    return send_api_request([ tx_hash ] , "eth_getTransactionByHash")

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

def get_address_from_private_key(private_key_byte):
    return ethereum.utils.checksum_encode(ethereum.utils.privtoaddr(private_key_byte))

def generate_random_key(byte_len):
    hex_len = byte_len * 2
    key = "0x"
    for _ in range(hex_len):
        digit = hex(random.randint(0,15))
        key = key + digit[2]
    return key

def get_chain_id():
    return int(send_api_request([], "eth_chainId"), 16)

def transaction_builder(from_address, to_address, amount, gas_price, nonce):
    transaction = {
        "from": from_address,
        "to": to_address,
        "value": amount,
        "gas": 100000000,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": CHAIN_ID
    }
    return transaction

def generate_random_private_key():
    return generate_random_key(32)

def generate_random_address():
    private_key = generate_random_private_key()
    return get_address_from_private_key(decode_hex(private_key))

def give_me_some_money(my_address, amount):
    private_key_bytes = decode_hex('0xd95d6db65f3e2223703c5d8e205d98e3e6b470f067b0f94f6c6bf73d4301ce48')
    address = ethereum.utils.checksum_encode(ethereum.utils.privtoaddr(private_key_bytes))
    tx = transaction_builder(address, my_address, amount, 1, update_nonce(address))
    signed_tx = web3.eth.Account.signTransaction(tx, private_key_bytes)
    raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)
    tx_hash = send_raw_tx(raw_tx)
    print("requested for money transfer, tx hash: " + tx_hash)
    tx_receipt = NODE.eth.wait_for_transaction_receipt(tx_hash)
    print("Money transfer complete. Tx receipt:")
    print(tx_receipt)

saved_txes = []
def send_txes(private_key_hex, tx_count, gas_price, nonce, save_txes = False):
    private_key = decode_hex(private_key_hex)
    address = get_address_from_private_key(private_key)
    del saved_txes[:]
    for _ in range(tx_count):
        tx = transaction_builder(address, generate_random_address(), 0, gas_price, nonce)
        signed_tx = web3.eth.Account.signTransaction(tx, private_key)
        raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)
        tx_hash = send_api_request([raw_tx] , "eth_sendRawTransaction")
        actual_tx_hash = web3.Web3.toHex(signed_tx.hash)

        if actual_tx_hash == tx_hash:
            if save_txes == True:
                saved_txes.append((tx_hash, tx))
            print("transaction added to pool, tx hash: " + tx_hash)
            nonce = nonce + 1
        else:
            print("could not add to pool, result: " + format(tx_hash))

    print("Printing saved txes, total: " + format(len(saved_txes)))
    for tx in saved_txes:
        print(tx)

    return nonce

def send_given_txes(private_key_hex, tx_list, gas_price, save_txes = False):
    private_key = decode_hex(private_key_hex)
    del saved_txes[:]
    count = 0
    print("trying to replace old txes")
    for item in tx_list:
        tx = item[1]
        print("old tx: " + format(tx))
        tx["gasPrice"] = gas_price
        print("new tx: " + format(tx))
        signed_tx = web3.eth.Account.signTransaction(tx, private_key)
        raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)
        tx_hash = send_api_request([raw_tx] , "eth_sendRawTransaction")
        actual_tx_hash = web3.Web3.toHex(signed_tx.hash)

        if actual_tx_hash == tx_hash:
            if save_txes == True:
                saved_txes.append((tx_hash,tx))
            print("transaction added to pool, tx hash: " + tx_hash)
            count = count + 1
        else:
            print("could not add to pool, result: " + format(tx_hash))
            
    print("Printing saved txes, total: " + format(len(saved_txes)))
    for tx in saved_txes:
        print(tx)
    
    return count


CHAIN_ID = get_chain_id()

if __name__ == "__main__":
    print(CHAIN_ID)
    random_private_keys = []
    nonces = []
    total_key = 10
    for _ in range(total_key):
        random_private_keys.append(generate_random_private_key())
        nonces.append(0)
    testing_key = generate_random_private_key()
    my_nonce = 0
    
    for private_key in random_private_keys:
        address = get_address_from_private_key(decode_hex(private_key))
        give_me_some_money(address, 2*pow(10, 9))
    
    testing_address = get_address_from_private_key(decode_hex(testing_key))
    give_me_some_money(testing_address, 3*pow(10, 9))
    high_gas_price = 3
    low_gas_price = 2

    # first send some txes with high gas price from random addresses
    # then send some txes with low gas price from testing address
    # so that if txes are taken, most likely txes with high gas prices will be taken
    # now try to replace txes with low gas price with high gas price txes from testing address
    tx_count = 10
    for iter in range(total_key - 1):
        successful_txes = send_txes(random_private_keys[iter], tx_count, high_gas_price, nonces[iter])
        print("successfully sent: " + format(successful_txes))
        print("failed: " + format(tx_count - successful_txes))

    #sending low_gas_price tx
    successful_txes = send_txes(testing_key, tx_count, low_gas_price, my_nonce, True)
    print("successfully sent: " + format(successful_txes))
    print("failed: " + format(tx_count - successful_txes))
    if len(saved_txes) != successful_txes:
        print("txes are not saved properly, got " + format(len(saved_txes)) + " txes saved")
    old_txes = []
    for tx in saved_txes:
        old_txes.append(tx)

    # trying to replace txes, but it should fail as gas price is equal or lower, gas price must be higher
    successful_txes = send_txes(testing_key, tx_count, low_gas_price, 0)
    print("successfully sent: " + format(successful_txes))
    print("failed: " + format(tx_count - successful_txes))
    
    successful_txes = send_txes(testing_key, tx_count, low_gas_price - 1, 0)
    print("successfully sent: " + format(successful_txes))
    print("failed: " + format(tx_count - successful_txes))
    
    # trying to replace txes, but it should fail other fields do not match
    successful_txes = send_txes(testing_key, tx_count, high_gas_price, 0)
    print("successfully sent: " + format(successful_txes))
    print("failed: " + format(tx_count - successful_txes))

    # this identical txes should replace the old ones because of high gas price
    successful_txes = send_given_txes(testing_key, old_txes, high_gas_price, True)
    print("successfully sent: " + format(successful_txes))
    print("failed: " + format(tx_count - successful_txes))
    
    if len(saved_txes) != successful_txes:
        print("txes are not saved properly, got " + format(len(saved_txes)) + " txes saved")
    new_txes = []
    for tx in saved_txes:
        new_txes.append(tx)
    if len(new_txes) != len(old_txes):
        print("old tx count: " + format(len(old_txes)) + ", new tx count: " + format(len(new_txes)))

    print("printing old txes")
    for tx in old_txes:
        print("hash: " + tx[0])
        print("full tx " + format(tx[1]))
        print("tx by hash " + format(tx_by_hash(tx[0])))

    print("printing new txes")
    for tx in new_txes:
        print("hash: " + tx[0])
        print("full tx " + format(tx[1]))
        print("tx by hash " + format(tx_by_hash(tx[0])))

    time.sleep(6)
    # this identical txes should not replace the old ones
    successful_txes = send_given_txes(testing_key, old_txes, high_gas_price + 1, True)
    print("successfully sent: " + format(successful_txes))
    print("failed: " + format(tx_count - successful_txes))

    if len(saved_txes) != successful_txes:
        print("txes are not saved properly, got " + format(len(saved_txes)) + " txes saved")
    new_abnormal_txes = []
    for tx in saved_txes:
        new_abnormal_txes.append(tx)
    print("printing abnormal txes")
    for tx in new_abnormal_txes:
        print("hash: " + tx[0])
        print("full tx " + format(tx[1]))
        print("tx by hash " + format(tx_by_hash(tx[0])))

    
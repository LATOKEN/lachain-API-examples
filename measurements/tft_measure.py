#! /usr/bin/env python

import json
import time

import requests
import web3
from eth_account.messages import encode_defunct
from eth_keys import keys
from eth_utils import decode_hex
from collections.abc import Iterable, Mapping

class API:
    def __init__(self, node):
        self.rpc_url = node['rpc']
        self.private_key = node['api_private_key']
        self.public_key = node['api_public_key']
        self.NODE = web3.Web3(web3.Web3.HTTPProvider(self.rpc_url))
        self.SESSION = requests.Session()
    

    def serialize(self, params):
        serialized = ""
        if (params is None):
            return ""
        elif isinstance(params, str):
            return params
        elif isinstance(params, Iterable):
            for item in params:
                serialized += self.serialize(item)
        elif isinstance(params, Mapping):
            for key, value in params.items():
                serialized += self.serialize(key)
                serialized += self.serialize(value)
        else:
            serialized += str(params)
        return serialized
        
    def __sign_message(self, tx, timestamp):
        print(json.dumps(tx, indent=4), timestamp)
        serializedParams = tx['method'] + self.serialize(tx['params']) + timestamp
        print(self.private_key, serializedParams)
        signed = web3.eth.Account.sign_message(encode_defunct(text=serializedParams), self.private_key)
        return signed.signature.hex()
    
        
        
    def __send_api_request_to_address(self, address, params, method, private=False):
        payload= {
            "jsonrpc":"2.0",
            "method":method,
            "params":params,
            "id":0
        }

        if private:
            timestamp = str(int(time.time()))
            signature = self.__sign_message(payload, timestamp)
        
            headers = {
                'Content-type': 'application/json',
                'Signature': signature,
                'Timestamp': timestamp
            }
        else:
            headers = {'Content-type': 'application/json'}

        response = self.SESSION.post(address, json=payload, headers=headers)
        try:
            res = response.json()['result']
            return res
        except Exception as eer:
            print(response.json())
            print("exception: " + format(eer))
            return eer

    def send_api_request(self, params , method, private=False):
        if private:
            return self.__send_api_request_to_address(self.rpc_url, params, method, private)
        return self.__send_api_request_to_address(self.rpc_url, params, method)

    def block_by_number(self, block, full_tx):
        return self.send_api_request([ block, full_tx ] , "eth_getBlockByNumber")

    def block_by_hash(self, block, full_tx):
        return self.send_api_request([ block, full_tx ] , "eth_getBlockByHash")

    def block_number(self):
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

def send_coins(api, private_key_bytes, to_address, amount, tx_count = 1):
    staker_private_key = keys.PrivateKey(private_key_bytes)    
    staker_address = staker_private_key.public_key.to_checksum_address()
    
    print("Sending amount %d from %s to %s using %s"%(amount, staker_address, to_address, api.rpc_url))
    print("Repeat %d times"%(tx_count))
    
    int_nonce = int(api.update_nonce(staker_address), 16)
    chain_id = api.get_chain_id()

    for count in range(0, tx_count):
        cur_nonce = count + int_nonce
        transaction = transaction_builder(staker_address, to_address, amount, 1, cur_nonce, chain_id)
        signed_tx = web3.eth.Account.signTransaction(transaction, private_key_bytes)
        raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)
        tx_hash = api.send_api_request([raw_tx] , "eth_sendRawTransaction")
        print("Transaction %d Processed: hash = %s\n"%(count+1, str(tx_hash)), flush=True)

        
        if (count == tx_count - 1):
            connection = web3.Web3(web3.Web3.HTTPProvider(api.rpc_url))
            tx_receipt = connection.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
            # print(tx_receipt)
            print("Successfully sent all transactions")

def send_coins_batch(api, private_key_bytes, to_address, amount, tx_count):
    staker_private_key = keys.PrivateKey(private_key_bytes)    
    staker_address = staker_private_key.public_key.to_checksum_address()
    
    print("Sending amount %d from %s to %s using %s"%(amount, staker_address, to_address, api.rpc_url))
    print("Repeat %d times"%(tx_count))
    
    int_nonce = int(api.update_nonce(staker_address), 16)
    chain_id = api.get_chain_id()

    tx_list = []
    for count in range(0, tx_count):
        cur_nonce = count + int_nonce
        transaction = transaction_builder(staker_address, to_address, amount, 1, cur_nonce, chain_id)
        signed_tx = web3.eth.Account.signTransaction(transaction, private_key_bytes)
        raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)
        tx_list.append(raw_tx)

    tx_hash = api.send_api_request([tx_list] , "la_sendRawTransactionBatch", private=True)
    print("Transaction %d Processed: hash = %s\n"%(count+1, str(tx_hash)), flush=True)

    
    if (count == tx_count - 1):
        connection = web3.Web3(web3.Web3.HTTPProvider(api.rpc_url))
        tx_receipt = connection.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
        # print(tx_receipt)
        print("Successfully sent all transactions")


def get_args():
    import argparse
    parser = argparse.ArgumentParser(description='Script for measuring txn finality time')

    # Required positional argument
    parser.add_argument('command', type=str,
                        help='should be one of check, send_all, flood or measure')

    
    # Optional argument
    parser.add_argument('--amount', type=int,
                        help='Amount to send (for send_all)')
    
    
    # Optional argument
    parser.add_argument('--id', type=int, default=0,
                        help='Node Id (for flood), defaults to 0')
    
    # Optional argument
    parser.add_argument('--cnt', type=int,
                        help='Number of transactions (for flood)')

    # Optional argument
    parser.add_argument('--interval', type=float,
                        help='Interval between Requests in sec (for measure) default: 1')
    
    parser.add_argument('--repeat', action='store_true',
                        help='Flood indefinitely')
    
    parser.add_argument('--tx', type=str,
                        help='txn hash')

    parser.add_argument('--config', type=str, default='config.json',
                        help='config file path, defaults to config.json')

    return parser.parse_args()



def main():
    args = get_args()

    with open(args.config) as configfile:
        config = json.load(configfile)
    
    staker_private_key_bytes = decode_hex(config['staker_address'])
    private_keys = [decode_hex(key) for key in config['addresses']]

    staker_address = get_address_from_private_key(staker_private_key_bytes)
    addresses = [get_address_from_private_key(private_key) for private_key  in private_keys]

    api = API(config['nodes'][args.id])

    print("Using: " + api.rpc_url)

    if (args.command == "check"):
        print("Staker (%s) has balance = %s"%(staker_address, int(api.get_balance(staker_address), 16)))
        for i in range(len(private_keys)):
            print("Address %d(%s) has balance = %s"%(i, addresses[i], int(api.get_balance(addresses[i]), 16)))
    elif (args.command == "send_all"):
        assert(args.amount is not None)
        amount = args.amount
        for i in range(len(private_keys)):
            send_coins(api, staker_private_key_bytes, addresses[i], amount)
        
        print("Staker (%s) has balance = %s"%(staker_address, int(api.get_balance(staker_address), 16)))
        for i in range(len(private_keys)):
            print("Address %d(%s) has balance = %s"%(i, addresses[i], int(api.get_balance(addresses[i]), 16)))

    elif (args.command == "send_back"):
        assert(args.amount is not None)
        amount = args.amount
        for i in range(len(private_keys)):
            send_coins(api, private_keys[i], staker_address, amount)
        
        print("Staker (%s) has balance = %s"%(staker_address, int(api.get_balance(staker_address), 16)))
        for i in range(len(private_keys)):
            print("Address %d(%s) has balance = %s"%(i, addresses[i], int(api.get_balance(addresses[i]), 16)))
        
    elif (args.command == "flood"):
        id = args.id if args.id is not None else 0
        count = args.cnt if args.cnt is not None else 1000
        private_key = private_keys[id]

        id = 0
        while (True):
            id += 1
            print("\nBatch %d Starting..."%(id))
            send_coins_batch(api, private_key, staker_address, 1, count)
            print("Batch %d Finished...\n"%(id))
            if not args.repeat: break

        

    elif (args.command == "measure"):

        last_block = int(api.block_number(),16)
        interval = args.interval or 1
        start = timer()
        last = start
        block_count = 0
        tx_count = 0

        print("Initially at block %d"%(last_block))

        while (True):
            elapsed_time = timer()-start
            abt = elapsed_time/block_count if block_count > 0 else float("inf")
            tps = tx_count/elapsed_time
            tpb = 0 if block_count == 0 else tx_count/block_count
            print( ('Processed %d blocks in %f sec, ' + 
                    '\tavg block time = %f, ' +
                    '\ttxn per sec = %f, ' +
                    '\ttxn_per_block = %f\r')
                    %(block_count, elapsed_time, abt, tps, tpb), end='')


            block = api.block_by_number(hex(last_block+1), False)
            if block:
                block_count+=1
                last_block+=1
                tx_count += len(block['transactions'])
                elapsed_time = timer()-start
                abt = elapsed_time/block_count if block_count > 0 else float("inf")
                tps = tx_count/elapsed_time
                tpb = 0 if block_count == 0 else tx_count/block_count
                print( ('Processed %d blocks in %f sec, ' + 
                    '\tavg block time = %f, ' +
                    '\ttxn per sec = %f, ' +
                    '\ttxn_per_block = %f\r')
                    %(block_count, elapsed_time, abt, tps, tpb), end='')
                
                cur_time = timer()
                print("\nBlock %d processed, %d transactions found, block time %f: "%(block_count, len(block['transactions']), cur_time-last))
                last = cur_time
                
            else:
                time.sleep(interval)
        
    elif args.command == 'receipt':
        print(api.tx_receipt(args.tx))    

    else:
        print("Invalid command")


if __name__ == "__main__":
    main()

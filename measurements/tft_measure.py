#! /usr/bin/env python
import json
import time
import os
from turtle import back
import requests
import web3
from eth_account.messages import encode_defunct
from eth_keys import keys
from eth_utils import decode_hex
from collections.abc import Iterable, Mapping
from timeit import default_timer as timer

class API:
    def __init__(self, node):
        self.rpc_url = node['rpc']
        self.private_key = node['api_private_key']
        if self.private_key.startswith("0x"):
            self.private_key = self.private_key[2:]

        self.NODE = web3.Web3(web3.Web3.HTTPProvider(self.rpc_url))
        self.SESSION = requests.Session()
    

    def serialize(self, params):
        serialized = ""
        if (params is None):
            return ""
        elif isinstance(params, str):
            return params
        elif isinstance(params, Mapping):
            for key, value in params.items():
                serialized += self.serialize(key)
                serialized += self.serialize(value)
        elif isinstance(params, Iterable):
            for item in params:
                serialized += self.serialize(item)
        else:
            serialized += str(params)
        return serialized
        

    def __sign_request(self, request, timestamp):
        serializedParams = request['method'] + self.serialize(request['params']) + timestamp

        signerPrivKey = keys.PrivateKey(bytes.fromhex(self.private_key))
        signature = signerPrivKey.sign_msg(serializedParams.encode('ascii'))
        return signature.to_hex()
    
        
        
    def __send_api_request_to_address(self, address, params, method, private=False):
        payload= {
            "jsonrpc":"2.0",
            "method":method,
            "params":params,
            "id":0
        }

        if private:
            timestamp = str(int(time.time()))

            signature = self.__sign_request(payload, timestamp)
        
            headers = {
                'Content-type': 'application/json',
                'Signature': signature,
                'Timestamp': timestamp
            }
        else:
            headers = {
                'Content-type': 'application/json'
            }

        response = self.SESSION.post(address, json=payload, headers=headers)
        try:
            res = response.json()['result']
            return res
        except Exception as eer:
            raise Exception("Error sending API request. Response:\n %s"%{str(response.json())})
        
    def send_api_request(self, params , method, private=False):
        return self.__send_api_request_to_address(self.rpc_url, params, method, private)
        
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
        print("Transaction %d Processed: hash = %s"%(count+1, str(tx_hash)), flush=True)

        
        if (count == tx_count - 1):
            connection = web3.Web3(web3.Web3.HTTPProvider(api.rpc_url))
            tx_receipt = connection.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
            print(tx_receipt)
            print("Successfully sent all transactions")

def send_coins_batch(api, private_key_bytes, to_address, amount, batch_size, batches):
    staker_private_key = keys.PrivateKey(private_key_bytes)    
    staker_address = staker_private_key.public_key.to_checksum_address()

    total_time = 0

    for _ in range(batches):
        print("Batch %d, batch size %d"%(_+1, batch_size))
        print("Sending amount %d from %s to %s using %s"%(amount, staker_address, to_address, api.rpc_url))
        
        int_nonce = int(api.update_nonce(staker_address), 16)
        chain_id = api.get_chain_id()

        tx_list = []
        start_time = {}
        end_time = {}
        for count in range(0, batch_size):
            cur_nonce = count + int_nonce
            transaction = transaction_builder(staker_address, to_address, amount, 1, cur_nonce, chain_id)
            signed_tx = web3.eth.Account.signTransaction(transaction, private_key_bytes)
            raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)
            tx_list.append(raw_tx)

        
        tx_hashes = api.send_api_request({"rawTxs": tx_list} , "la_sendRawTransactionBatch", private=True)
        
        print("Transaction %d Processed: last_hash = %s"%(count+1, tx_hashes[-1]))
        start = timer()
        
        connection = web3.Web3(web3.Web3.HTTPProvider(api.rpc_url))
        tx_receipt = connection.eth.wait_for_transaction_receipt(tx_hashes[-1], timeout=600)
        # print(tx_receipt)
        taken = timer() - start
        total_time += taken
        print("All transactions confirmed. Time: %f\n"%(taken))

    tft = total_time/batches
    print("Average TFT: %f"%(tft))

def get_args():
    import argparse
    parser = argparse.ArgumentParser(description='Script for measuring txn finality time')

    # Required positional argument
    parser.add_argument('command', type=str,
                        help='should be one of check, send_all, send_back, flood or monitor')

    
    # Optional argument
    parser.add_argument('--amount', type=int, default=0,
                        help='Amount to send (for send_all and send_back), defaults to 0')
    
    
    # Optional argument
    parser.add_argument('--id', type=int, default=0,
                        help='Node Id (for flood), defaults to 0')
    
    # Optional argument
    parser.add_argument('--batch_size', type=int, default=100,
                        help='Batch Size (for flood), defaults to 100')
    
    # Optional argument
    parser.add_argument('--batches', type=int, default=10,
                        help='no of batches (for flood), defaults to 10')

    # Optional argument
    parser.add_argument('--interval', type=float, default=1,
                        help='Interval between Requests in sec (for monitor) default: 1')

    parser.add_argument('--config', type=str, default=os.path.join(os.path.dirname(__file__), 'config.json'),
                        help='config file path, defaults to config.json')

    return parser.parse_args()



def main():
    args = get_args()
    print("Reading config from: ", args.config)
    with open(args.config) as configfile:
        config = json.load(configfile)
    
    staker_private_key_bytes = decode_hex(config['staker_address'])
    private_keys = [decode_hex(key) for key in config['addresses']]

    staker_address = get_address_from_private_key(staker_private_key_bytes)
    addresses = [get_address_from_private_key(private_key) for private_key  in private_keys]

    api = API(config['nodes'][args.id])

    print("Using url: " + api.rpc_url)

    if (args.command == "check"):
        print("Staker (%s) has balance = %s"%(staker_address, int(api.get_balance(staker_address), 16)))
        for i in range(len(private_keys)):
            print("Address %d(%s) has balance = %s"%(i, addresses[i], int(api.get_balance(addresses[i]), 16)))
            
    elif (args.command == "send_all"):
        for i in range(len(private_keys)):
            send_coins(api, staker_private_key_bytes, addresses[i], args.amount)
        
        print("Staker (%s) has balance = %s"%(staker_address, int(api.get_balance(staker_address), 16)))
        for i in range(len(private_keys)):
            print("Address %d(%s) has balance = %s"%(i, addresses[i], int(api.get_balance(addresses[i]), 16)))

    elif (args.command == "send_back"):
        for i in range(len(private_keys)):
            send_coins(api, private_keys[i], staker_address, args.amount)
        
        print("Staker (%s) has balance = %s"%(staker_address, int(api.get_balance(staker_address), 16)))
        for i in range(len(private_keys)):
            print("Address %d(%s) has balance = %s"%(i, addresses[i], int(api.get_balance(addresses[i]), 16)))
        
    elif (args.command == "flood"):
        private_key = private_keys[args.id]
        send_coins_batch(api, private_key, staker_address, 1, args.batch_size, args.batches)

    elif (args.command == "monitor"):
        last_block = int(api.block_number(),16)
        interval = args.interval
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

    else:
        print("Invalid command")


if __name__ == "__main__":
    main()

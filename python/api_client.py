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

    def is_locked(self):
        return int(self.send_api_request([], "fe_isLocked"), 16)

    def unlock(self, password, time_ms):
        payload = {
            "password": password,
            "s": time_ms
        }
        return self.send_api_request(payload , "fe_unlock", private=True)

    def changePassword(self, old, new):
        payload = {
            "currentPassword": old,
            "newPassword": new
        }
        return self.send_api_request(payload , "fe_changePassword", private=True)

    def get_chain_id(self):
        return int(self.send_api_request([], "eth_chainId"), 16)

from eth_utils.address import to_checksum_address
from eth_utils import decode_hex
import web3
import requests
from eth_keys import keys
from eth_utils import encode_hex

# the private key which owns the LA to be staked
STAKER = decode_hex('0x')

RPC_ADDRESS = "https://rpc-mainnet.lachain.io"


session = requests.Session()
def send_api_request_to_address(address, params , method):
    payload = {
        "jsonrpc":"2.0",
        "method":method,
        "params":params,
        "id":0
    }
    
    headers = {'Content-type': 'application/json'}
    response = session.post(address, json=payload, headers=headers)
    try:
        res = response.json()['result']
        return res
    except Exception as eer:
        print(response.json())
        print("exception: " + format(eer))
        return eer

def send_api_request(params , method):
    return send_api_request_to_address(RPC_ADDRESS, params, method)

def get_chain_id():
    return int(send_api_request([], "eth_chainId"), 16)

CHAIN_ID = get_chain_id()

def get_address_from_private_key(private_key_bytes):
    private_key = keys.PrivateKey(private_key_bytes)
    return private_key.public_key.to_checksum_address()

def get_public_key_from_private_key(private_key_bytes):
    private_key = keys.PrivateKey(private_key_bytes)
    return encode_hex(private_key.public_key.to_compressed_bytes())

def get_stake_tx(staker, validator_pubkey, stake):
    tx = {
        "stakerAddress": staker,
        "validatorPublicKey": validator_pubkey,
        "stakeAmount": stake
    }
    return send_api_request([tx], "la_getStakeTransaction")

def transaction_builder(from_address, to_address, amount, gas_limit, gas_price, nonce, data):
    transaction = {
        "from": from_address,
        "to": to_address,
        "value": amount,
        "gas": gas_limit,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": CHAIN_ID,
        "data": data
    }
    return transaction

def stake_from_staker(validator_public_key, stake_amount, staker_private_key):
    staker = get_address_from_private_key(staker_private_key)
    # transaction to stake from staker to validator
    tx = get_stake_tx(staker, validator_public_key, stake_amount)
    from_address = to_checksum_address(tx['from'])
    to_address = to_checksum_address(tx['to'])
    gas = int(tx['gas'], 16)
    gas_price = int(tx['gasPrice'], 16)
    data = tx['data']
    amount = int(tx['value'], 16)
    nonce = int(tx['nonce'], 16)
    transaction = transaction_builder(from_address, to_address, amount, gas, gas_price, nonce, data)
    print("transaction:")
    print(transaction)
    signed_tx = web3.eth.Account.signTransaction(transaction, STAKER)
    raw_tx = web3.Web3.toHex(signed_tx.rawTransaction)
    tx_hash = send_api_request([raw_tx] , "eth_sendRawTransaction")
    print("tx hash: " + format(tx_hash))
    connection = web3.Web3(web3.Web3.HTTPProvider(RPC_ADDRESS))
    tx_receipt = connection.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    print("receipt:")
    print(tx_receipt)

if __name__ == "__main__":
    # validator private key can be recovered running node with decrypt option
    validator_private_key_bytes = decode_hex("0x")
    address = get_address_from_private_key(validator_private_key_bytes)
    validator_public_key = get_public_key_from_private_key(validator_private_key_bytes)
    stake_amount = 0
    # this method will stake 'stake_amount' from STAKER to validator_public_key
    stake_from_staker(validator_public_key, stake_amount, STAKER)
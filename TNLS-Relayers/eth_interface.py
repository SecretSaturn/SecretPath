import base64
import json
import os
from logging import getLogger, basicConfig, INFO, StreamHandler
from pprint import pprint
from typing import List, Mapping, Sequence

from web3 import Web3
from eth_abi import abi
import eth_abi


from base_interface import BaseChainInterface, BaseContractInterface, Task


class EthInterface(BaseChainInterface):
    """
    Implementaion of BaseChainInterface for eth.
    """


    def __init__(self, private_key="", address="", provider=None, contract_address = "", **_kwargs):
        if provider is None:
            """
            If we don't have a set provider, read it from config.
            """
            infura_endpoint = os.environ.get('INFURA_ENDPOINT')

            API_MODE = "dev"
            """API_URL = infura_endpoint.replace("{ENDPOINT}",
                                              "mainnet") if API_MODE != "dev" else infura_endpoint.replace(
                "{ENDPOINT}", "goerli")"""
            API_URL= "https://sepolia.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"

            provider = Web3(Web3.HTTPProvider(API_URL))
        self.private_key = private_key
        self.provider = provider
        self.address = address
        self.contract_address = contract_address
        basicConfig(
            level=INFO,
            format="%(asctime)s [Eth Interface: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
        pass

    def create_transaction(self, contract_function, *args, **kwargs):
        """
        See base_interface.py for documentation
        """
        print("create TX")
        # create task
        nonce = self.provider.eth.get_transaction_count(self.address)
        if kwargs is {}:
            tx = contract_function(*args).build_transaction({
                'from': self.address,
                'gas': 300000,
                'nonce': nonce,
                #'maxFeePerGas': self.provider.eth.max_priority_fee
                #'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
            })
        elif len(args) == 0:
            tx = contract_function(**kwargs).build_transaction({
                'from': self.address,
                'gas': 300000,
                'nonce': nonce,
                #'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
            })
        else:
            tx = contract_function(*args, **kwargs).build_transaction({
                'from': self.address,
                'gas': 300000,
                'nonce': nonce,
                #'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
            })

        return tx

    def sign_and_send_transaction(self, tx):
        """
        See base_interface.py for documentation
        """
        # sign task
        signed_tx = self.provider.eth.account.sign_transaction(tx, self.private_key)
        # send task
        tx_hash = self.provider.eth.send_raw_transaction(signed_tx.rawTransaction)
        print('Tx Hash:', tx_hash.hex())
        return tx_hash

    def get_transactions(self, address, height=None):
        """
        See base_interface.py for documentation
        """
        return self.get_last_txs(address=address, block_number=height)

    def get_last_block(self):
        """
        Gets the number of the most recent block
        """
        return self.provider.eth.get_block('latest').number

    def get_last_txs(self, block_number=None, address=None):
        """
        Gets the transactions from a particular block for a particular address.
        Args:
            block_number:  Which block to get
            address: Which address to get transactions for

        Returns: a list of transaction receipts

        """
        if block_number is None:
            block_number = self.get_last_block()
        if address is None:
            address = self.address
        # get last txs for address
        try:
            transactions: Sequence[Mapping] = self.provider.eth.get_block(block_number, full_transactions=True)[
                'transactions']
        except Exception as e:
            self.logger.warning(e)
            return []
        correct_transactions = []
        for transaction in transactions:
            try:
                if transaction.to == self.contract_address or self.contract_address == "":
                    tx_receipt = self.provider.eth.get_transaction_receipt(transaction['hash'])
                    correct_transactions.append(tx_receipt)
            except Exception as e:
                self.logger.warning(e)
                continue

        return correct_transactions


class EthContract(BaseContractInterface):
    """
    Implementation of BaseContractInterface for eth.
    """

    def __init__(self, interface, address, abi, **_kwargs):
        self.address = address
        self.abi = abi
        self.interface = interface
        self.contract = interface.provider.eth.contract(address=self.address, abi=self.abi)
        basicConfig(
            level=INFO,
            format="%(asctime)s [Eth Contract: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
        self.logger.info("Initialized Eth contract with address: %s", self.address)
        pass

    def get_function(self, function_name):
        """
        Gets a particular function from the contract.
        Args:
            function_name: The name of the function to get.
        """
        return self.contract.functions[function_name]

    def call_function(self, function_name, *args):
        """
        See base_interface.py for documentation
        """
        kwargs = None
        function = self.get_function(function_name)
        if len(args) == 1:
            args = json.loads(args[0])
            if isinstance(args, dict):
                kwargs = args
                args = []
            else:
                for i, value in enumerate(args):
                    if isinstance(value, list):
                        args[i] = tuple(value)
                kwargs = None
        if kwargs is None:
            txn = self.interface.create_transaction(function, *args)
        elif args is None:
            txn = self.interface.create_transaction(function, **kwargs)
        else:
            txn = self.interface.create_transaction(function, *args, **kwargs)
        return self.interface.sign_and_send_transaction(txn)

    """def parse_event_from_txn(self, event_name, txn) -> List[Task]:

        try:

            data = txn.logs[0].data
            task_id = int.from_bytes(txn.logs[0].topics[1], 'big')
            print(task_id)

            types = ['string', 'address', 'string', 'string', 'bytes', 'bytes32', 'bytes', 'bytes', 'bytes',
                     'string', 'bytes12']

            ## With array inputs
            decodedABI = eth_abi.decode(types,data,strict=False)

            task_list = []
            args = {'task_id': task_id, 'task_destination_network': 'secret',
                    'source_network': decodedABI[0],
                    'user_address': decodedABI[1],
                    'routing_info': decodedABI[2],
                    'routing_code_hash':decodedABI[3],
                    'payload':base64.b64encode(decodedABI[4]).decode('ASCII'),
                    'payload_hash':base64.b64encode(decodedABI[5]).decode('ASCII'),
                    'payload_signature':base64.b64encode(decodedABI[6][:-1]).decode('ASCII'),
                    'user_key': base64.b64encode(decodedABI[7]).decode('ASCII'),
                    'user_pubkey': base64.b64encode(decodedABI[8]).decode('ASCII'),
                    'handle': decodedABI[9],
                    'nonce': base64.b64encode(decodedABI[10]).decode('ASCII')}
            task_list.append(Task(args))

            return task_list

        except Exception as e:
            self.logger.warning(e)
            return []"""
    def parse_event_from_txn(self, event_name, txn) -> List[Task]:

            event = self.contract.events[event_name]()
            try:
                tasks = event.process_receipt(txn)
            except Exception as e:
                self.logger.warning(e)
                return []
            task_list = []
            for task in tasks:
                args = task['args']
                task_list.append(Task(args))
            return task_list


if __name__ == "__main__":
    """interface = EthInterface(address='0xEB7D94Cefa561E83901aD87cB91eFcA73a1Fc812')"""
    interface = EthInterface(private_key="a9afa5cda00e31eae3883f847f4e5dee78e66086786e656124eef2380433c580", address="0x50FcF0c327Ee4341313Dd5Cb987f0Cd289Be6D4D")
    txs = interface.get_last_txs()
    pprint(txs)


import json
import os
from logging import getLogger, basicConfig, INFO, StreamHandler
from pprint import pprint
from typing import List, Mapping, Sequence

from web3 import Web3

from base_interface import BaseChainInterface, BaseContractInterface, Task


class EthInterface(BaseChainInterface):
    """
    Implementaion of BaseChainInterface for eth.
    """

    def __init__(self, private_key="", address="", provider=None, **_kwargs):
        if provider is None:
            """
            If we don't have a set provider, read it from config.
            """
            with open(f"{os.getcwd()}/infura_api_endpoint.txt") as file:
                infura_endpoint = file.read()

            API_MODE = "dev"
            if address == "":
                address = "0xce1dfc3F67B028Ed19a97974F8cD2bAF6fba1672" \
                    if API_MODE != "dev" else "0xae050f76654B1Cf264A203545371F1575119530C"
            API_URL = infura_endpoint.replace("{ENDPOINT}",
                                              "mainnet") if API_MODE != "dev" else infura_endpoint.replace(
                "{ENDPOINT}", "ropsten")

            provider = Web3(Web3.HTTPProvider(API_URL))
        self.private_key = private_key
        self.provider = provider
        self.address = address
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
        # create task
        nonce = self.provider.eth.get_transaction_count(self.address)
        if kwargs is {}:
            tx = contract_function(*args).buildTransaction({
                'from': self.address,
                'gas': 200000,
                'nonce': nonce,
                'gasPrice': self.provider.eth.gasPrice,
            })
        elif len(args) == 0:
            tx = contract_function(**kwargs).buildTransaction({
                'from': self.address,
                'gas': 200000,
                'nonce': nonce,
                'gasPrice': self.provider.eth.gasPrice,
            })
        else:
            tx = contract_function(*args, **kwargs).buildTransaction({
                'from': self.address,
                'gas': 200000,
                'nonce': nonce,
                'gasPrice': self.provider.eth.gasPrice,
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
        return tx_hash

    def get_transactions(self, address):
        """
        See base_interface.py for documentation
        """
        return self.get_last_txs(address=address)

    def get_last_block(self):
        """
        Gets the number of the most recent block
        """
        return self.provider.eth.blockNumber

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
        transactions: Sequence[Mapping] = self.provider.eth.get_block(block_number, full_transactions=True)[
            'transactions']
        correct_transactions = [transaction for transaction in transactions if transaction['from'] == address]
        correct_transactions = list(
            map(lambda tx: self.provider.eth.get_transaction_receipt(tx['hash']), correct_transactions))

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

    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        """
        See base_interface.py for documentation
        """
        event = self.contract.events[event_name]()
        try:
            tasks = event.processReceipt(txn)
        except Exception as e:
            self.logger.warning(e)
            return []
        task_list = []
        for task in tasks:
            args = task['args']
            task_list.append(Task(args))
        return task_list


if __name__ == "__main__":
    interface = EthInterface(address='0xEB7D94Cefa561E83901aD87cB91eFcA73a1Fc812')
    txs = interface.get_last_txs()
    pprint(txs)

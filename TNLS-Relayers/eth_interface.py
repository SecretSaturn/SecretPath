import json
import os
from copy import deepcopy
from logging import getLogger, basicConfig, INFO, StreamHandler
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from web3 import Web3
from web3.datastructures import AttributeDict
from web3.middleware import geth_poa_middleware

from base_interface import BaseChainInterface, BaseContractInterface, Task


class EthInterface(BaseChainInterface):
    """
    Implementaion of BaseChainInterface for eth.
    """

    def __init__(self, private_key="", address="", provider=None, contract_address = "", chain_id="", api_endpoint="", **_kwargs):
        if provider is None:
            """
            If we don't have a set provider, read it from config.
            """

            provider = Web3(Web3.HTTPProvider(api_endpoint, request_kwargs={'timeout': 5}))
            provider.middleware_onion.inject(geth_poa_middleware, layer=0)

        self.private_key = private_key
        self.provider = provider
        self.address = address
        self.contract_address = contract_address
        self.chain_id = chain_id
        self.nonce = self.provider.eth.get_transaction_count(self.address, 'pending');

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
        #structure is from eth_task_keys_to_msg
        #callback_gas_limit is on the 5th position on eth_task_keys_to_msgs
        print(args[2][4])
        if kwargs is {}:
            callback_gas_limit = int(args[2][4], 16)
            tx = contract_function(*args).build_transaction({
                'from': self.address,
                'gas': callback_gas_limit,
                'nonce': deepcopy(self.nonce)
                #'maxFeePerGas': self.provider.eth.max_base
                #'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
            })
        elif len(args) == 0:
            tx = contract_function(**kwargs).build_transaction({
                'from': self.address,
                'gas': 2000000,
                'nonce': deepcopy(self.nonce)
                #'maxFeePerGas': self.provider.eth.max_priority_fee
                #'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
            })
        else:
            callback_gas_limit = int(args[2][4], 16)
            tx = contract_function(*args, **kwargs).build_transaction({
                'from': self.address,
                'gas': callback_gas_limit,
                'nonce': deepcopy(self.nonce)
                #'maxFeePerGas': self.provider.eth.max_priority_fee
                #'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
            })

        self.nonce = self.nonce + 1
        return tx

    def sign_and_send_transaction(self, tx):
        """
        See base_interface.py for documentation
        """
        # sign task
        signed_tx = self.provider.eth.account.sign_transaction(tx, self.private_key)
        # send task
        tx_hash = self.provider.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.logger.info('Tx Hash: %s', tx_hash.hex())
        return tx_hash

    def get_transactions(self, contract_interface, height=None):
        """
        See base_interface.py for documentation
        """
        return self.get_last_txs(contract_interface=contract_interface, block_number=height)

    def get_last_block(self):
        """
        Gets the number of the most recent block
        """
        return self.provider.eth.get_block('latest').number

    def get_last_txs(self, block_number=None, contract_interface=None):
        """
        Gets the transactions from a particular block for a particular address.
        Args:
            block_number:  Which block to get
            address: Which address to get transactions for

        Returns: a list of transaction receipts

        """
        if block_number is None:
            block_number = self.get_last_block()

        valid_transactions = contract_interface.contract.events.logNewTask().get_logs(
            fromBlock=block_number,
        )
        transaction_hashes = [event['transactionHash'].hex() for event in valid_transactions]
        try:
            block_transactions = self.provider.eth.get_block(block_number, full_transactions=True)['transactions']
            filtered_transactions = [tx for tx in block_transactions if tx['hash'].hex() in transaction_hashes]
        except Exception as e:
            self.logger.warning(e)
            return []

        correct_transactions = []
        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                # Create a future for each transaction
                future_to_transaction = {executor.submit(self.process_transaction, tx): tx for tx in filtered_transactions}
                for future in as_completed(future_to_transaction):
                    result = future.result()
                    if result is not None:
                        correct_transactions.append(result)
        except Exception as e:
            self.logger.warning(e)

        return correct_transactions

    def process_transaction(self, transaction):
        try:
            if str(transaction['chainId']) == str(self.chain_id):
                tx_receipt = self.provider.eth.get_transaction_receipt(transaction['hash'])
                return tx_receipt
            else:
                raise Exception("Chain_ID of TX and API don't match. Api chain_id: "+str(self.chain_id) + " TX chain_id: "+ str(transaction['chainId']))
        except Exception as e:
            self.logger.warning(e)
            return None


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
        self.lock = Lock()
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
        with self.lock:
            if kwargs is None:
                txn = self.interface.create_transaction(function, *args)
            elif args is None:
                txn = self.interface.create_transaction(function, **kwargs)
            else:
                txn = self.interface.create_transaction(function, *args, **kwargs)
            submitted_txn = self.interface.sign_and_send_transaction(txn)
        return submitted_txn

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
            # Convert to a regular dictionary
            args_dict = dict(args)

            # Convert ExecutionInfo into single arguments
            info_part = args_dict.pop('info')
            args_dict.update(info_part)
            args = AttributeDict(args_dict)
            task_list.append(Task(args))

        return task_list


if __name__ == "__main__":
    interface = EthInterface(address='')


import json
from copy import deepcopy
from logging import getLogger, basicConfig, INFO, StreamHandler
import logging
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Timer

from web3.middleware import ExtraDataToPOAMiddleware
from web3 import Web3
from web3.datastructures import AttributeDict

from base_interface import BaseChainInterface, BaseContractInterface, Task


class EthInterface(BaseChainInterface):
    """
    Implementation of BaseChainInterface for Ethereum.
    """

    def __init__(self, private_key="", provider=None, contract_address="", chain_id="", api_endpoint="", timeout=1, sync_interval=30, **_kwargs):
        if provider is None:
            # If no provider, set a default with middleware for various blockchain scenarios
            provider = Web3(Web3.HTTPProvider(api_endpoint, request_kwargs={'timeout': timeout}))
            provider.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        self.private_key = private_key
        self.provider = provider
        self.address = self.provider.eth.account.from_key(private_key).address
        self.contract_address = contract_address
        self.chain_id = chain_id
        self.nonce = self.provider.eth.get_transaction_count(self.address, 'pending')

        # Set up logging
        self.logger = getLogger("ETH Interface")
        self.logger.setLevel(INFO)
        handler = StreamHandler()
        formatter = logging.Formatter("%(asctime)s [ETH Interface: %(levelname)4.8s] %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.propagate = False

        # Initialize lock, executor, and sync interval
        self.nonce_lock = Lock()
        self.timer = None
        self.sync_interval = sync_interval

        self.executor = ThreadPoolExecutor(max_workers=1)
        self.schedule_sync()

    def schedule_sync(self):
        """
        Schedule the sync task with the executor and restart the timer
        """
        try:
            self.executor.submit(self.sync_nonce)
        except Exception as e:
            self.logger.error(f"Error during nonce sync: {e}")
        finally:
            self.timer = Timer(self.sync_interval, self.schedule_sync)
            self.timer.start()

    def sync_nonce(self):
        """
        Sync the nonce with the latest data from the provider.
        """
        try:
            with self.nonce_lock:
                self.logger.info(f"Starting Chain-id {self.chain_id} nonce sync")
                new_nonce = self.provider.eth.get_transaction_count(self.address, 'pending')
                if self.nonce is None or new_nonce >= self.nonce:
                    self.nonce = new_nonce
                    self.logger.info(f"Chain-id {self.chain_id} nonce synced")
                else:
                    self.logger.warning(
                        f"New nonce {new_nonce} is not greater than or equal to the old nonce {self.nonce}.")
        except Exception as e:
            self.logger.error(f"Error syncing nonce: {e}")

    def create_transaction(self, contract_function, *args, **kwargs):
        """
        See base_interface.py for documentation
        """
        try:
            if not kwargs:
                callback_gas_limit = int(args[2][4], 16)
                tx = contract_function(*args).build_transaction({
                    'from': self.address,
                    'gas': callback_gas_limit,
                    'nonce': deepcopy(self.nonce),
                    'maxFeePerGas': self.provider.eth.max_priority_fee + 2 * self.provider.eth.get_block('latest')[
                        'baseFeePerGas'],
                    'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
                })
            elif len(args) == 0:
                tx = contract_function(**kwargs).build_transaction({
                    'from': self.address,
                    'gas': 2000000,
                    'nonce': deepcopy(self.nonce),
                    'maxFeePerGas': self.provider.eth.max_priority_fee + 2 * self.provider.eth.get_block('latest')[
                        'baseFeePerGas'],
                    'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
                })
            else:
                callback_gas_limit = int(args[2][4], 16)
                tx = contract_function(*args, **kwargs).build_transaction({
                    'from': self.address,
                    'gas': callback_gas_limit,
                    'nonce': deepcopy(self.nonce),
                    'maxFeePerGas': self.provider.eth.max_priority_fee + 2 * self.provider.eth.get_block('latest')[
                        'baseFeePerGas'],
                    'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
                })

        except Exception as e:
            self.logger.warning(e)
        finally:
            self.nonce += 1
            return tx


    def sign_and_send_transaction(self, tx):
        """
        See base_interface.py for documentation
        """
        try:
            # Sign transaction
            signed_tx = self.provider.eth.account.sign_transaction(tx, self.private_key)
            # Send transaction
            tx_hash = self.provider.eth.send_raw_transaction(signed_tx.raw_transaction)
            self.logger.info('Tx Hash: %s', tx_hash.hex())
            return tx_hash
        except Exception as e:
            self.logger.warning(e)

    def get_transactions(self, contract_interface, height=None):
        """
        See base_interface.py for documentation
        """
        try:
            return self.get_last_txs(contract_interface=contract_interface, block_number=height)
        except Exception as e:
            self.logger.warning(e)

    def get_last_block(self):
        """
        Gets the number of the most recent block
        """
        try:
            return self.provider.eth.get_block('latest')['number']
        except Exception as e:
            self.logger.warning(e)

    def get_last_txs(self, block_number=None, contract_interface=None):
        """
        Gets the transactions from a particular block for a particular address.
        Args:
            block_number:  Which block to get
            contract_interface: Which contract to get transactions for

        Returns: a list of transaction receipts

        """
        try:
            if block_number is None:
                block_number = self.provider.eth.get_block('latest')['number']
            valid_transactions = contract_interface.contract.events.logNewTask().get_logs(
                from_block=block_number,
                to_block=block_number
            )
        except Exception as e:
            self.logger.warning(e)
            return []

        if len(valid_transactions) == 0:
            return []

        transaction_hashes = [event['transactionHash'].hex() for event in valid_transactions]

        correct_transactions = []

        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                # Create a future for each transaction
                future_to_transaction = {executor.submit(self.process_transaction, tx_hash): tx_hash for tx_hash in transaction_hashes}
                for future in as_completed(future_to_transaction):
                    result = future.result()
                    if result is not None:
                        correct_transactions.append(result)
        except Exception as e:
            self.logger.warning(e)
            return []

        return correct_transactions

    def process_transaction(self, transaction_hash):
        try:
            tx_receipt = self.provider.eth.get_transaction_receipt(transaction_hash)
            return tx_receipt
        except Exception as e:
            self.logger.warning(e)
            return None


class EthContract(BaseContractInterface):
    """
    Implementation of BaseContractInterface for Ethereum.
    """

    def __init__(self, interface, address, abi, **_kwargs):
        self.address = address
        self.abi = abi
        self.interface = interface
        self.contract = interface.provider.eth.contract(address=self.address, abi=self.abi)
        
        # Set up logging
        self.logger = getLogger("ETH Interface")
        self.logger.setLevel(INFO)
        handler = StreamHandler()
        formatter = logging.Formatter("%(asctime)s [ETH Interface: %(levelname)4.8s] %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.propagate = False


        self.lock = Lock()
        self.logger.info("Initialized Eth contract with address: %s", self.address)

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
        with self.lock, self.interface.nonce_lock:
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
            try:
                args = task['args']

                # Convert to a regular dictionary
                args_dict = dict(args)

                # Convert ExecutionInfo into single arguments
                info_part = args_dict.pop('info')
                args_dict.update(info_part)
                args = AttributeDict(args_dict)
                task_list.append(Task(args))

            except Exception as e:
                self.logger.warning(e)

        return task_list


if __name__ == "__main__":
    interface = EthInterface(address='')

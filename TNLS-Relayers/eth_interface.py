import json
from copy import deepcopy
from logging import getLogger, basicConfig, INFO, StreamHandler
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Timer
from time import sleep

from web3 import Web3, middleware
from web3.datastructures import AttributeDict
from web3.middleware import geth_poa_middleware

from base_interface import BaseChainInterface, BaseContractInterface, Task


class EthInterface(BaseChainInterface):
    """
    Implementaion of BaseChainInterface for eth.
    """

    def __init__(self, private_key="", address="", provider=None, contract_address="", chain_id="", api_endpoint="", timeout=1, sync_interval=30, **_kwargs):
        if provider is None:
            # If no provider, set a default with middleware for various blockchain scenarios
            provider = Web3(Web3.HTTPProvider(api_endpoint, request_kwargs={'timeout': timeout}))
            provider.middleware_onion.inject(geth_poa_middleware, layer=0)
            provider.middleware_onion.add(middleware.time_based_cache_middleware)
            provider.middleware_onion.add(middleware.latest_block_based_cache_middleware)
            provider.middleware_onion.add(middleware.simple_cache_middleware)

        self.private_key = private_key
        self.provider = provider
        self.address = address
        self.contract_address = contract_address
        self.chain_id = chain_id
        self.nonce = self.provider.eth.get_transaction_count(self.address, 'pending')

        # Set up logging
        basicConfig(
            level=INFO,
            format="%(asctime)s [Eth Interface: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()

        # Initialize lock, executor, and sync interval
        self.nonce_lock = Lock()
        self.timer = None
        self.sync_interval = sync_interval
        self.executor = ThreadPoolExecutor(max_workers=1)

        # Schedule nonce synchronization
        self.schedule_sync()

    def schedule_sync(self):
        """
        Schedule nonce sync task with the executor and restart the timer
        """
        try:
            self.executor.submit(self.sync_nonce)
        except Exception as e:
            self.logger.error(f"Error during Ethereum nonce sync: {e}")
        finally:
            # Re-run the sync at specified intervals
            self.timer = Timer(self.sync_interval, self.schedule_sync)
            self.timer.start()

    def sync_nonce(self):
        """
        Sync the nonce with the latest data from the provider
        """
        try:
            with self.nonce_lock:
                self.logger.info(f"Starting Chain-id {self.chain_id} nonce sync")
                sleep(1)  # Introduce a delay if needed to reduce frequency of sync errors
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
        # create task
        #structure is from eth_task_keys_to_msg
        #callback_gas_limit is on the 5th position on eth_task_keys_to_msgs
        if kwargs is {}:
            callback_gas_limit = int(args[2][4], 16)
            tx = contract_function(*args).build_transaction({
                'from': self.address,
                'gas': callback_gas_limit,
                'nonce': deepcopy(self.nonce),
                'gasPrice': self.provider.eth.gas_price
                #'maxFeePerGas': self.provider.eth.max_base
                #'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
            })
        elif len(args) == 0:
            tx = contract_function(**kwargs).build_transaction({
                'from': self.address,
                'gas': 2000000,
                'nonce': deepcopy(self.nonce),
                'gasPrice': self.provider.eth.gas_price
                #'maxFeePerGas': self.provider.eth.max_priority_fee
                #'maxPriorityFeePerGas': self.provider.eth.max_priority_fee,
            })
        else:
            callback_gas_limit = int(args[2][4], 16)
            tx = contract_function(*args, **kwargs).build_transaction({
                'from': self.address,
                'gas': callback_gas_limit,
                'nonce': deepcopy(self.nonce),
                'gasPrice': self.provider.eth.gas_price
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
        """
                Gets the transactions from a particular block for a particular address.
                Args:
                    block_number:  Which block to get
                    contract_interface: Which contract to get transactions for

                Returns: a list of transaction receipts

                """

        def process_transaction(transaction_hash):
            try:
                tx_receipt = self.provider.eth.get_transaction_receipt(transaction_hash)
                return tx_receipt
            except Exception as e:
                self.logger.error(f"Error processing transaction: {e}")
                return None

        if height is None:
            height = self.get_last_block()

        try:
            valid_transactions = contract_interface.contract.events.logNewTask().get_logs(
                fromBlock=height,
                toBlock=height
            )
        except Exception as e:
            self.logger.warning(e)

        if len(valid_transactions) == 0:
            return []

        transaction_hashes = [event['transactionHash'].hex() for event in valid_transactions]

        correct_transactions = []

        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                # Create a future for each transaction
                future_to_transaction = {executor.submit(process_transaction, tx_hash): tx_hash for tx_hash in
                                         transaction_hashes}
                for future in as_completed(future_to_transaction):
                    result = future.result()
                    if result is not None:
                        correct_transactions.append(result)
        except Exception as e:
            self.logger.error(f"Error fetching transactions: {e}")
            return []

        return correct_transactions

    def get_last_block(self):
        """
        Gets the number of the most recent block
        """
        return self.provider.eth.get_block('latest').number


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

    def call_function(self, function_name, *args):
        """
        See base_interface.py for documentation
        """
        kwargs = None
        function = self.contract.functions[function_name]
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
        with self.lock and self.interface.nonce_lock:
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


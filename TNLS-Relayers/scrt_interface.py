import json
from copy import deepcopy
from logging import getLogger, basicConfig, DEBUG, StreamHandler
from threading import Lock, Timer
from concurrent.futures import ThreadPoolExecutor
from typing import List
from time import sleep, time

from secret_sdk.client.lcd import LCDClient
from secret_sdk.client.lcd.api.tx import CreateTxOptions, BroadcastMode
from secret_sdk.core import TxLog
from secret_sdk.exceptions import LCDResponseError
from secret_sdk.key.raw import RawKey

from base_interface import BaseChainInterface, BaseContractInterface, Task

class SCRTInterface(BaseChainInterface):
    """
    Implementation of the BaseChainInterface standard for the Secret Network

    NOTE: the below default private key is for testing only, and does not correspond to any real account/wallet
    """

    def __init__(self, private_key="", api_url="", chain_id="", provider=None, feegrant_address=None, sync_interval=30, **kwargs):
        if isinstance(private_key, str):
            self.private_key = RawKey.from_hex(private_key)
        else:
            self.private_key = RawKey(private_key)
        if provider is None:
            self.provider = LCDClient(url=api_url, chain_id=chain_id, **kwargs)
        else:
            self.provider = provider
        self.feegrant_address = feegrant_address
        self.address = str(self.private_key.acc_address)
        self.wallet = self.provider.wallet(self.private_key)
        self.logger = getLogger()

        # Initialize account number and sequence
        self.account_number = None
        self.sequence = None

        self.timer = None

        self.sequence_lock = Lock()

        self.sync_interval = sync_interval
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.schedule_sync()

    def schedule_sync(self):
        """
        Schedule the sync task with the executor and restart the timer
        """
        try:
            self.executor.submit(self.sync_account_number_and_sequence)
        except Exception as e:
            self.logger.error(f"Error during Secret sequence sync: {e}")
        finally:
            self.timer = Timer(self.sync_interval, self.schedule_sync)
            self.timer.start()


    def sync_account_number_and_sequence(self):
        """
        Syncs the account number and sequence with the latest data from the provider
        """
        try:
            with self.sequence_lock:
                self.logger.info("Starting Secret sequence sync")
                account_info = self.wallet.account_number_and_sequence()
                self.account_number = account_info['account_number']
                new_sequence = int(account_info['sequence'])
                if self.sequence is None or new_sequence >= self.sequence:
                    self.sequence = new_sequence
                    self.logger.info("Secret sequence synced")
                else:
                    self.logger.warning(
                        f"New sequence {new_sequence} is not greater than the old sequence {self.sequence}.")
        except Exception as e:
            self.logger.error(f"Error syncing account number and sequence: {e}")

    def sign_and_send_transaction(self, tx):
        """
        Signs and broadcasts a transaction to the network, returns the broadcast receipt
        Args:
            tx[StdTx]: transaction to be signed and sent

        Returns:
                the receipt of the broadcast transaction

        """
        max_retries = 20
        try:
            # Broadcast the transaction in SYNC mode
            final_tx = self.provider.tx.broadcast_adapter(tx, mode=BroadcastMode.BROADCAST_MODE_ASYNC)
            print(final_tx)
            tx_hash = final_tx.txhash
            self.logger.info(f"Transaction broadcasted with hash: {tx_hash}")

            # Repeatedly fetch the transaction result until it's included in a block
            for attempt in range(max_retries):
                try:
                    tx_result = self.provider.tx.tx_info(tx_hash)
                    print(tx_result)
                    if tx_result:
                        self.logger.info(f"Transaction included in block: {tx_result.height}")
                        return tx_result
                except LCDResponseError as e:
                    if 'not found' in str(e).lower():
                        # Transaction not yet found, wait and retry
                        self.logger.info(f"Transaction not found, retrying... ({attempt+1}/{max_retries})")
                        sleep(3)
                        continue
                    else:
                        self.logger.error(f"LCDResponseError while fetching tx result: {e}")
                        raise e
                except Exception as e:
                    self.logger.error(f"Unexpected error while fetching tx result: {e}")
                    raise e
            raise Exception(f"Transaction {tx_hash} not included in a block after {max_retries} retries")
        except LCDResponseError as e:
            self.logger.error(f"LCDResponseError during transaction broadcast: {e}")
            raise e
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during transaction broadcast: {e}")
            raise e

    def get_last_block(self):
        """
        Returns the most recent block height
        Returns:  the height of the current block

        """
        block_info = self.provider.tendermint.block_info()
        return int(block_info['block']['header']['height'])

    def get_transactions(self, address, height=None):
        """
        Returns all txn logs from the given height for the given address
        Args:
            address: the address to get the txn logs for
            height: which height to get the txn logs from, if None, get all txn logs from the current height

        Returns:
            a list of txn logs for the given address/height

        """
        block_info = self.provider.tendermint.block_info()
        if height is None:
            height = block_info['block']['header']['height']
        try:
            txns = self.provider.tx.search(options={'message.sender': address, 'tx.minheight': height}).txs
        except KeyError:
            return []
        logs_list = [txn.logs for txn in txns]
        flattened_log_list = [item for sublist in logs_list for item in sublist]
        return flattened_log_list


class SCRTContract(BaseContractInterface):
    """
    Implements the BaseContractInterface standard for the Secret Network
    """

    def __init__(self, interface, address, abi, code_hash):
        self.address = address
        self.code_hash = code_hash
        self.abi = json.loads(abi)
        self.interface = interface
        basicConfig(
            level=DEBUG,
            format="%(asctime)s [SCRT interface: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
        self.lock = Lock()
        self.logger.info(f"Initialized SCRT interface for contract {self.address}")
        pass

    def get_function(self, function_name):
        """
        Returns the function schema for the given function name
        Args:
            function_name: which function to get a list of args for

        Returns:
            the schema for the specific function

        """
        return self.abi[function_name]
        pass

    def construct_txn(self, function_schema, function_name, args):
        """
        Constructs a transaction for the given function_schema, function name and args
        Args:
            function_schema: Dict[str, List[str]], the schema for the function
            function_name: str, the name of the function to be called
            args: Union[List[str], Dict[str, str]], the args to be passed to the function

        Examples shown in relayer_tests/interface_tests/test_scrt_interface.py,
        under the test_basic_txn_construction and test_dict_txn_construction tests

        Returns:
                a StdSignMsg (unsigned) transaction for
                the given function_schema, function name and args

        """
        arg_keys = function_schema['args']
        if isinstance(args, tuple) and len(args) == 1:
            args = args[0]
        if isinstance(args, str):
            args = json.loads(args)
        if isinstance(args, list):
            arg_values = [arg for arg in args]
            if len(arg_keys) != len(arg_values):
                self.logger.warning(f"Arguments do not match schema."
                                    f"  Expected {len(arg_keys)} arguments but got {len(arg_values)}")
                if len(arg_keys) > len(arg_values):
                    arg_values += [""] * (len(arg_keys) - len(arg_values))
                else:
                    arg_values = arg_values[:len(arg_keys)]
            arg_dict = dict(zip(arg_keys, arg_values))
        elif isinstance(args, dict):
            if 'task_destination_network' in args:
                args.pop('task_destination_network')
            arg_dict = args
            if set(arg_keys) != set(args.keys()):
                self.logger.info(f"Arguments do not match schema."
                                 f"  Expected {sorted(list(arg_keys))} arguments but got {sorted(list(args.keys()))}")
                self.logger.warning(f"Arguments do not match schema."
                                    f"  Expected {sorted(list(arg_keys))} arguments but got {sorted(list(args.keys()))}")
                if set(arg_keys) > set(args.keys()):
                    for key in arg_keys:
                        if key not in args.keys():
                            arg_dict[key] = ""
                arg_dict = {key: arg_dict[key] for key in arg_keys}
        else:
            self.logger.warning(f"Arguments must be a list or dict, got {type(args)}")
            arg_dict = json.loads(args)
        function_schema = {function_name: arg_dict}
        if function_name == 'inputs':
            new_schema = {'input': deepcopy(function_schema)}
            function_schema = new_schema
        self.logger.info(
            f"Using arguments {function_schema} to call function {function_name} at address {self.address}")
        txn_msgs = self.interface.provider.wasm.contract_execute_msg(
            sender_address=self.interface.address,
            contract_address=self.address,
            handle_msg=function_schema,
            contract_code_hash=self.code_hash
        )
        gas = '3000000'
        gas_prices = '0.1uscrt'
        tx_options = CreateTxOptions(
            msgs=[txn_msgs],
            gas=gas,
            gas_prices=gas_prices,
            sequence=deepcopy(self.interface.sequence),
            account_number=self.interface.account_number,
        )
        fee = self.interface.provider.tx.estimate_fee(options=tx_options)
        if self.interface.feegrant_address is not None:
            fee.granter = self.interface.feegrant_address
        tx_options = CreateTxOptions(
            msgs=[txn_msgs],
            gas=gas,
            gas_prices=gas_prices,
            sequence=deepcopy(self.interface.sequence),
            account_number=self.interface.account_number,
            fee=fee
        )
        txn = self.interface.wallet.create_and_sign_tx(options=tx_options)
        self.interface.sequence = self.interface.sequence + 1
        return txn

    def call_function(self, function_name, *args):
        """
        Calls the given function with the given args
        Args:
            function_name: which function to call
            *args: the args to pass

        Returns: the result of the function call

        """
        function_schema = self.get_function(function_name)
        if len(args) == 1 and isinstance(args, list):
            args = args[0]
        if isinstance(args, str):
            args = json.loads(args)
        with self.lock and self.interface.sequence_lock:
            txn = self.construct_txn(function_schema, function_name, args)
        transaction_result = self.interface.sign_and_send_transaction(txn)
        try:
            self.logger.info(f"Transaction result: {transaction_result}")
            logs = transaction_result.logs
        except AttributeError:
            logs = []
        task_list = self.parse_event_from_txn('wasm', logs)
        self.logger.info(f"Transaction result: {task_list}")
        return task_list, transaction_result

    def parse_event_from_txn(self, event_name: str, logs: List[TxLog]):
        """
        Parses the given event from the given logs
        Args:
            event_name: which event to parse
            logs: the logs to parse from

        Returns: a list of tasks corresponding to parsed events

        """
        task_list = []
        for log in logs:
            events = [event for event in log.events if event['type'] == event_name]
            for event in events:
                attr_dict = {attribute['key']: attribute['value'] for attribute in event['attributes']}
                task_list.append(Task(attr_dict))
        return task_list

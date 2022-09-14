import json
from logging import getLogger, basicConfig, DEBUG, StreamHandler
from typing import List

from secret_sdk.client.lcd import LCDClient
from secret_sdk.core.auth.data import TxLog
from secret_sdk.key.raw import RawKey

from base_interface import BaseChainInterface, BaseContractInterface, Task


class SCRTInterface(BaseChainInterface):
    """
    Implementation of the BaseChainInterface standard for the Secret Network

    NOTE: the below default private key is for testing only, and does not correspond to any real account/wallet
    """

    def __init__(self, private_key="c2cdf0a8b0a83b35ace53f097b5e6e6a0a1f2d40535eff1cf434f52a43d59d8f",
                 address=None, api_url="https://api.pulsar.scrttestnet.com", chain_id="pulsar-2", provider=None,
                 **kwargs):
        if isinstance(private_key, str):
            self.private_key = RawKey.from_hex(private_key)
        else:
            self.private_key = RawKey(private_key)
        if provider is None:
            self.provider = LCDClient(url=api_url, chain_id=chain_id, **kwargs)
        else:
            self.provider = provider
        self.address = address
        assert self.address == str(self.private_key.acc_address), f"Address {self.address} and private key " \
                                                                  f"{self.private_key.acc_address} mismatch"
        self.wallet = self.provider.wallet(self.private_key)

    def sign_and_send_transaction(self, tx):
        """
        Signs and broadcasts a transaction to the network, returns the broadcast receipt
        Args:
            tx[StdTx]: transaction to be signed and sent

        Returns:
                the receipt of the broadcast transaction

        """
        signed_tx = self.wallet.key.sign_tx(tx)
        return self.provider.tx.broadcast(signed_tx)

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
        txns = self.provider.tx.search(options={'message.sender': address, 'tx.minheight': height}).txs
        logs_list = [txn.logs for txn in txns]
        flattened_log_list = [item for sublist in logs_list for item in sublist]
        return flattened_log_list


class SCRTContract(BaseContractInterface):
    """
    Implements the BaseContractInterface standard for the Secret Network
    """

    def __init__(self, interface, address, abi):
        self.address = address
        self.abi = json.loads(abi)
        self.interface = interface
        basicConfig(
            level=DEBUG,
            format="%(asctime)s [SCRT interface: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
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
        arg_dict = dict()
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
            arg_dict = args
            if set(arg_keys) != set(args.keys()):
                self.logger.warning(f"Arguments do not match schema."
                                    f"  Expected {sorted(list(arg_keys))} arguments but got {sorted(list(args.keys()))}")
                if set(arg_keys) > set(args.keys()):
                    for key in arg_keys:
                        if key not in args.keys():
                            arg_dict[key] = ""
                arg_dict = {key: arg_dict[key] for key in arg_keys}
        function_schema = {function_name: arg_dict}
        txn_msgs = self.interface.provider.wasm.contract_execute_msg(
            sender_address=self.interface.address,
            contract_address=self.address,
            handle_msg=function_schema,

        )
        txn = self.interface.wallet.create_tx(msgs=[txn_msgs])
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
        if isinstance(args, str):
            args = json.loads(args)
        if len(args) == 1:
            args = args[0]
        args = json.loads(json.dumps(args))
        txn = self.construct_txn(function_schema, function_name, args)
        return self.interface.sign_and_send_transaction(txn)

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

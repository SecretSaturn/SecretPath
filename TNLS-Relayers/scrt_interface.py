import secret_sdk
from secret_sdk.client.lcd import LCDClient
from base_interface import BaseChainInterface, BaseContractInterface

class SCRTInterface(BaseChainInterface):
    def __init__(self, private_key, address, api_url):
        self.private_key = private_key
        self.provider = LCDClient(url=api_url)
        self.address = address
        self.wallet = self.provider.wallet(self.private_key)


class SCRTContract(BaseContractInterface):
    def __init__(self, interface, address, message_type):
        self.address = address
        self.abi = message_type
        self.interface = interface
        self.contract = interface.provider.contract(address=self.address, abi=self.abi)
        pass

    def get_function(self, function_name):
        pass

    def call_function(self, function_name, *args):
        function = self.get_function(function_name)
        txn = self.interface.create_transaction(function, args)
        return self.interface.sign_and_send_transaction(txn)

    def parse_event_from_txn(self, event_name, txn):
        pass
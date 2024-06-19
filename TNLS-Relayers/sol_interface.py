import asyncio
from solana.rpc.api import Client
from solders.keypair import Keypair
from solana.transaction import Transaction
from threading import Lock, Timer
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging import getLogger, basicConfig, INFO, StreamHandler
from typing import List

# Base class for interaction with Solana
class SolanaInterface:
    def __init__(self, private_key="", provider=None, contract_address="", chain_id="", address ="", api_endpoint="", timeout=1, sync_interval=30):
        # Connect to Solana network
        self.client = Client(api_endpoint, timeout)
        self.private_key = private_key
        self.account = Keypair.from_base58_string(private_key)
        self.sync_interval = sync_interval
        self.lock = Lock()
        self.executor = ThreadPoolExecutor(max_workers=1)

        # Set up logging
        basicConfig(
            level=INFO,
            format="%(asctime)s [Solana Interface: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()

        # Schedule synchronization task
        self.schedule_sync()

    def schedule_sync(self):
        """Schedule synchronization of any necessary tasks."""
        try:
            self.executor.submit(self.sync_nonce)
        except Exception as e:
            self.logger.error(f"Error during Solana sync: {e}")
        finally:
            # Re-run the sync at specified intervals
            self.timer = Timer(self.sync_interval, self.schedule_sync)
            self.timer.start()

    def sync_nonce(self):
        """Sync any necessary data or nonce value."""
        # Solana does not use nonce like Ethereum, but you can sync any necessary data
        self.logger.info("Solana synchronization task running.")

    def create_transaction(self, instructions, signers):
        """
        Create a transaction with the given instructions and signers.
        """
        txn = Transaction()
        for instruction in instructions:
            txn.add(instruction)

        return txn

    def sign_and_send_transaction(self, txn):
        """
        Sign and send a transaction to the Solana network.
        """
        signed_txn = txn.sign(self.account)
        tx_response = self.client.send_raw_transaction(signed_txn.serialize())
        return tx_response

    def get_last_block(self):
        """
        Gets the most recent block number on the Solana network.
        """
        return self.client.get_slot()

    def get_confirmed_signatures_for_address2(self, address):
        response = requests.post(self.rpc_url, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getConfirmedSignaturesForAddress2",
            "params": [address]
        })
        return response.json()

    def get_transaction(self, txn):
        response = requests.post(self.rpc_url, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getConfirmedTransaction",
            "params": [txn]
        })
        return response.json()

    def get_transactions(self, address):
        """
        Get transactions for a given address.
        """
        response = self.get_confirmed_signatures_for_address2(address)
        return response['result']

    def process_transaction(self, txn):
        """
        Process a transaction and return its receipt.
        """
        try:
            tx_receipt = self.get_transaction(txn)
            return tx_receipt
        except Exception as e:
            self.logger.warning(e)
            return None

    def fetch_events(self, address):
        """
        Fetch and parse events for a given address.
        """
        transactions = self.get_transactions(address)
        events = []

        for txn_info in transactions:
            txn = txn_info['signature']
            tx_receipt = self.process_transaction(txn)
            if tx_receipt and 'result' in tx_receipt:
                log_messages = tx_receipt['result']['meta']['logMessages']
                for log in log_messages:
                    if 'LogNewTask' in log:
                        event = self.parse_log(log)
                        if event:
                            events.append(event)
        return events

    def parse_log(self, log):
        """
        Parse a log message to extract event data.
        """
        try:
            # Custom parsing logic for your log to extract event data
            # Example: Extract JSON-like string and parse it
            event_data = log.split('LogNewTask: ')[1]
            return json.loads(event_data)
        except (IndexError, json.JSONDecodeError) as e:
            self.logger.warning(f"Failed to parse log: {log} with error: {e}")
            return None


# Base class for interaction with Solana contracts (programs)
class SolanaContract:
    def __init__(self, interface, program_id, program_account):
        self.interface = interface
        self.program_id = program_id
        self.address = program_account
        self.lock = Lock()
        self.logger = getLogger()
        self.logger.info("Initialized Solana contract with program ID: %s", program_id)

    def get_function(self, function_name):
        """Placeholder to simulate getting a specific function."""
        return None  # Functions are not explicitly defined in Solana contracts.

    def call_function(self, instructions):
        """
        Build a transaction and call a specific function with given instructions.
        """
        with self.lock:
            txn = self.interface.create_transaction(instructions, [self.interface.account])
            submitted_txn = self.interface.sign_and_send_transaction(txn)
        return submitted_txn

    def parse_event_from_txn(self, txn):
        """
        Parse an event from a transaction receipt.
        """
        events = []
        try:
            tx_receipt = self.interface.process_transaction(txn)
            # Depending on the program's design, extract relevant information
            # Add appropriate parsing logic to extract events from the transaction receipt
        except Exception as e:
            self.logger.warning(e)

        return events

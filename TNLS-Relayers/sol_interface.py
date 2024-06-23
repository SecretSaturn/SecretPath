import json

from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from anchorpy import Program, Context, Idl
from threading import Lock, Timer
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging import getLogger, basicConfig, INFO, StreamHandler
from borsh_construct import CStruct, U64, String, Vec, U8, U32
from typing import List
import base64

from base_interface import BaseChainInterface, BaseContractInterface, Task

class LogNewTask:

    layout = CStruct(
        "task_id" / U64,
        "source_network" / String,
        "user_address" / Vec(U8),
        "routing_info" / String,
        "payload_hash" / Vec(U8),
        "user_key" / Vec(U8),
        "user_pubkey" / Vec(U8),
        "routing_code_hash" / String,
        "task_destination_network" / String,
        "handle" / String,
        "nonce" / Vec(U8),
        "callback_gas_limit" / U32,
        "payload" / Vec(U8),
        "payload_signature" / Vec(U8)
    )

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
        try:
            return self.client.get_slot(commitment="finalized").value
        except Exception as e:
            self.logger.error(f"Error fetching the most recent block: {e}")
            return None

    def get_transactions(self, contract_interface, height):
        """
        Get transactions for a given address.
        """
        filtered_transactions = []
        try:
            response = self.client.get_signatures_for_address(account = contract_interface.address, limit=100,
                                                              commitment="confirmed")
            if response.value:
                # Filter transactions by slot height
                filtered_transactions = [tx.signature for tx in response.value if tx.slot == height]
            else:
                return []
        except Exception as e:
            self.logger.error(f"Error fetching transactions: {e}")
            return []

        correct_transactions = []

        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                # Create a future for each transaction
                future_to_transaction = {executor.submit(self.process_transaction, signature): signature
                                         for signature in filtered_transactions}
                for future in as_completed(future_to_transaction):
                    result = future.result()
                    if result is not None:
                        correct_transactions.append(result)
        except Exception as e:
            self.logger.error(f"Error fetching transactions: {e}")
            return []

        return correct_transactions

    def process_transaction(self, signature):
        """
        Process a transaction and return its receipt.
        """
        try:
            response = self.client.get_transaction(signature, commitment="confirmed")
            if response.value:
                self.logger.info(f"Transaction found: {signature}")
                log_messages = response.value.transaction.meta.log_messages

                for log in log_messages:
                    if "LogNewTask:" in log:
                        return response.value
                return None
            else:
                self.logger.error(f"Transaction not found: {signature}")
                return None
        except Exception as e:
            self.logger.error(e)
            return None


# Base class for interaction with Solana contracts (programs)
class SolanaContract:
    def __init__(self, interface, program_id, program_account, idl):
        self.interface = interface
        self.program_id = Pubkey.from_string(program_id)
        # Load your program's IDL (you should have the IDL file available)
        idl_path = "/Users/alexanderhertlein/Desktop/SecretPath/TNLS-Gateways/solana-gateway/target/idl/solana_gateway.json"
        with open(idl_path, "r") as f:
            self.idl = Program(Idl.from_json(json.load(f)), self.program_id, interface)
        self.address = Pubkey.from_string(program_account)
        self.lock = Lock()
        self.logger = getLogger()
        self.logger.info("Initialized Solana contract with program ID: %s", program_id)

    def call_function(self, function_name, *args):
        """
        Build a transaction and call a specific function with given instructions.
        """
        print(args)
        with self.lock:
            """
                    Create a transaction with the given instructions and signers.
                    """
            # Create context

            ctx = Context(
                accounts={
                    "gateway_state": self.address,
                    "payer": self.interface.provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                },
                signers=[self.interface.provider.wallet.payer]
            )

            tx = self.program.rpc["post_execution"](
            ctx,
            task_id,
            source_network,
            {
                "payload_hash": post_execution_info.payload_hash,
                "packet_hash": post_execution_info.packet_hash,
                "callback_address": post_execution_info.callback_address,
                "callback_selector": post_execution_info.callback_selector,
                "callback_gas_limit": post_execution_info.callback_gas_limit,
                "packet_signature": post_execution_info.packet_signature,
                "result": post_execution_info.result,
            }
        )
            submitted_txn = self.interface.sign_and_send_transaction(tx)
        return submitted_txn

    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        """
        Parse an event from a transaction receipt.
        """
        task_list = []
        try:
            log_messages = txn.transaction.meta.log_messages

            for log in log_messages:
                if "LogNewTask:" in log:
                    log_data = log.split("LogNewTask:")[1]
                    event_data = LogNewTask.layout.parse(base64.b64decode(log_data))

                    args = {'task_id': event_data.task_id,
                            'task_destination_network': event_data.task_destination_network,
                            'source_network': event_data.source_network,
                            'user_address': base64.b64encode(bytes(event_data.user_address)).decode('ASCII'),
                            'routing_info': event_data.routing_info,
                            'routing_code_hash': event_data.routing_code_hash,
                            'payload': base64.b64encode(bytes(event_data.payload)).decode('ASCII'),
                            'payload_hash': base64.b64encode(bytes(event_data.payload_hash)).decode('ASCII'),
                            'payload_signature': base64.b64encode(bytes(event_data.payload_signature[:-1])).decode('ASCII'),
                            'user_key': base64.b64encode(bytes(event_data.user_key)).decode('ASCII'),
                            'user_pubkey': base64.b64encode(bytes(event_data.user_pubkey)).decode('ASCII'),
                            'handle': event_data.handle,
                            'callback_gas_limit': event_data.callback_gas_limit,
                            'nonce': base64.b64encode(bytes(event_data.nonce)).decode('ASCII')
                    }
                    task_list.append(Task(args))

            return task_list
        except Exception as e:
            self.logger.error(f"Error parsing transaction: {e}")


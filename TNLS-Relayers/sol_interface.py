import json
from solana.rpc.api import Client
from solders.compute_budget import set_compute_unit_limit
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from threading import Lock
from solana.transaction import Transaction
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging import getLogger, basicConfig, INFO, StreamHandler
from borsh_construct import CStruct, U64, String, U8, U32, Bytes
from solders.system_program import ID as SYS_PROGRAM_ID
from solders.instruction import Instruction, AccountMeta
from solana.rpc.commitment import Confirmed
from typing import List
from solana.rpc.types import TxOpts
import base64

from base_interface import Task


class LogNewTask:
    # Define the data layout for the LogNewTask event using Borsh serialization
    layout = CStruct(
        "task_id" / U64,
        "source_network" / String,
        "user_address" / Bytes,
        "routing_info" / String,
        "payload_hash" / U8[32],
        "user_key" / Bytes,
        "user_pubkey" / Bytes,
        "routing_code_hash" / String,
        "task_destination_network" / String,
        "handle" / String,
        "nonce" / U8[12],
        "callback_gas_limit" / U32,
        "payload" / Bytes,
        "payload_signature" / U8[64]
    )


class PostExecution:
    # Define the data layout for the PostExecution event using Borsh serialization
    layout = CStruct(
        "task_id" / U64,
        "source_network" / String,
        "post_execution_info" / CStruct(
            "packet_hash" / U8[32],
            "callback_address" / Bytes,
            "callback_selector" / U8[40],
            "callback_gas_limit" / U8[4],
            "packet_signature" / U8[65],
            "result" / Bytes,
        )
    )

# Base class for interaction with Solana
class SolanaInterface:
    def __init__(self, private_key="", provider=None, contract_address="", chain_id="", api_endpoint="", timeout=1, sync_interval=30):
        # Connect to Solana network
        if provider is None:
            provider = Client(api_endpoint, timeout)

        self.provider = provider  # Solana RPC provider client
        self.private_key = private_key  # User's private key in base58 string format
        self.account = Keypair.from_base58_string(private_key)  # Generate Keypair from private key
        self.address = self.account.pubkey()  # Public key of the account
        self.sync_interval = sync_interval  # Sync interval in seconds
        self.lock = Lock()  # Thread lock for synchronization
        self.executor = ThreadPoolExecutor(max_workers=1)  # Thread pool executor with one worker

        # Set up logging
        basicConfig(
            level=INFO,
            format="%(asctime)s [Solana Interface: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()  # Get the logger instance

    def sign_and_send_transaction(self, txn):
        """
        Sign and send a transaction to the Solana network synchronously.
        """

        # Sign the transaction with the account's keypair
        txn.sign(self.account)

        # Send the transaction to the network
        response = self.provider.send_transaction(
            txn,
            self.account,
            opts=TxOpts(skip_confirmation=False, preflight_commitment=Confirmed)
        )

        # Confirm the transaction on the network
        tx_response = self.provider.confirm_transaction(response.value, commitment=Confirmed)
        return tx_response

    def get_last_block(self):
        """
        Gets the most recent block number on the Solana network.
        """
        try:
            # Fetch the current slot (block number) with confirmed commitment
            return self.provider.get_slot(commitment=Confirmed).value
        except Exception as e:
            self.logger.error(f"Error fetching the most recent block: {e}")
            return None

    def get_transactions(self, contract_interface, height):
        """
        Get transactions for a given address since a certain block height.
        """
        # Set the jump interval (e.g., check every 20 blocks)
        jump = 20
        if height % jump != 0:
            # If the height is not a multiple of jump, return empty list
            return []

        filtered_transactions = []
        try:
            # Get recent signatures for the given contract address
            response = self.provider.get_signatures_for_address(
                account=contract_interface.address,
                limit=10,
                commitment=Confirmed
            )
            if response.value:
                # Filter transactions by slot height (transactions within the last 'jump' slots)
                filtered_transactions = [
                    tx.signature for tx in response.value if tx.slot >= height - jump
                ]
            else:
                return []
        except Exception as e:
            self.logger.error(f"Error fetching transactions: {e}")
            return []

        correct_transactions = []

        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                # Create a future for each transaction to process them concurrently
                future_to_transaction = {
                    executor.submit(self.process_transaction, signature): signature
                    for signature in filtered_transactions
                }
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
        Process a transaction and return its receipt if it contains the expected log.
        """
        try:
            # Fetch the transaction details using its signature
            response = self.provider.get_transaction(signature, commitment=Confirmed)
            if response.value:
                self.logger.info(f"Transaction found: {signature}")
                # Extract the log messages from the transaction metadata
                log_messages = response.value.transaction.meta.log_messages

                # Look for a specific log message indicating a new task
                for log in log_messages:
                    if "LogNewTask:" in log:
                        # Return the transaction if it contains the "LogNewTask:" log
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
    def __init__(self, interface, program_id):
        self.interface = interface  # SolanaInterface instance
        self.program_id = Pubkey.from_string(program_id)  # Program ID (public key) of the contract

        # Find the program-derived address (PDA) for 'gateway_state'
        gateway_pda, gateway_bump = Pubkey.find_program_address([b'gateway_state'], self.program_id)
        # Find the PDA for 'task_state'
        task_pda, task_bump = Pubkey.find_program_address([b'task_state'], self.program_id)

        self.gateway_pda = gateway_pda  # PDA for the gateway state
        self.address = gateway_pda  # Address of the contract (set to gateway_pda)
        self.task_pda = task_pda  # PDA for the task state
        self.lock = Lock()  # Thread lock for synchronization
        self.logger = getLogger()  # Get the logger instance
        self.logger.info("Initialized Solana contract with program ID: %s", program_id)

    def call_function(self, function_name, *args):
        """
        Build a transaction and call a specific function with given instructions.
        """

        with self.lock:
            """
            Create a transaction with the given instructions and signers.
            """

            # Create the list of AccountMeta (accounts involved in the instruction)
            accounts: list[AccountMeta] = [
                AccountMeta(pubkey=self.gateway_pda, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.task_pda, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.interface.address, is_signer=True, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
            ]

            # Parse the JSON arguments if only one argument is provided
            if len(args) == 1:
                args = json.loads(args[0])

            # Ensure the callback_address_bytes length is a multiple of 32 bytes
            callback_address_bytes = bytes.fromhex(args[2][2][2:])  # Remove '0x' prefix
            if len(callback_address_bytes) % 32 != 0:
                raise ValueError("callback_address_bytes length is not a multiple of 32")

            # Check and create callback_accounts
            callback_accounts: List[AccountMeta] = []
            # Iterate over the callback_address_bytes in chunks of 32 bytes
            for i in range(0, len(callback_address_bytes), 32):
                pubkey = Pubkey(callback_address_bytes[i:i + 32])
                # Skip if the pubkey is the interface address or contract address
                if pubkey == self.interface.address or pubkey == self.address:
                    continue
                callback_accounts.append(AccountMeta(pubkey=pubkey, is_signer=False, is_writable=True))

            # Add the callback_accounts to the accounts list
            if callback_accounts is not None:
                accounts += callback_accounts

            # Extract the program_id from the callback_selector
            callback_selector_bytes = bytes.fromhex(args[2][3][2:])
            if len(callback_selector_bytes) < 32:
                raise ValueError("callback_selector does not contain enough bytes for a program_id")
            program_id_bytes = callback_selector_bytes[:32]
            program_id_pubkey = Pubkey(program_id_bytes)

            # Add the extracted program_id as an AccountMeta
            accounts.append(AccountMeta(pubkey=program_id_pubkey, is_signer=False, is_writable=False))

            # The Identifier of the post execution function (function selector)
            identifier = bytes([52, 46, 67, 194, 153, 197, 69, 168])

            # Build the encoded arguments for the instruction data using PostExecution layout
            encoded_args = PostExecution.layout.build(
                {
                    "task_id": args[0],
                    "source_network": args[1],
                    "post_execution_info": {
                        "packet_hash": bytes.fromhex(args[2][1][2:]),
                        "callback_address": bytes.fromhex(args[2][2][2:]),
                        "callback_selector": bytes.fromhex(args[2][3][2:]),
                        "callback_gas_limit": bytes.fromhex(args[2][4][2:]),
                        "packet_signature": bytes.fromhex(args[2][5][2:]),
                        "result": bytes.fromhex(args[2][6][2:]),
                    }
                }
            )

            # Combine the function identifier and encoded arguments to form the instruction data
            data = identifier + encoded_args

            # Create the instruction
            tx = Instruction(program_id=self.program_id, data=data, accounts=accounts)

            # Extract callback_gas_limit from the arguments
            callback_gas_limit = int.from_bytes(bytes.fromhex(args[2][4][2:]), byteorder='big')
            # Create a compute budget instruction to set the compute unit limit
            compute_budget_ix = set_compute_unit_limit(callback_gas_limit)

            # Create the transaction with the fee payer set to the interface address
            transaction = Transaction(fee_payer=self.interface.address)
            # Add the compute budget instruction and the main instruction to the transaction
            transaction.add(compute_budget_ix, tx)

            # Sign and send the transaction using the interface
            submitted_txn = self.interface.sign_and_send_transaction(transaction)
        return submitted_txn

    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        """
        Parse an event from a transaction receipt and extract tasks.
        """
        task_list = []
        try:
            # Get the log messages from the transaction metadata
            log_messages = txn.transaction.meta.log_messages

            for log in log_messages:
                if "LogNewTask:" in log:
                    # Extract the data after "LogNewTask:"
                    log_data = log.split("LogNewTask:")[1]
                    # Parse the event data using LogNewTask layout
                    event_data = LogNewTask.layout.parse(base64.b64decode(log_data))

                    # Build the arguments for the Task object
                    args = {
                        'task_id': event_data.task_id,
                        'task_destination_network': event_data.task_destination_network,
                        'source_network': event_data.source_network,
                        'user_address': base64.b64encode(bytes(event_data.user_address)).decode('ASCII'),
                        'routing_info': event_data.routing_info,
                        'routing_code_hash': event_data.routing_code_hash,
                        'payload': base64.b64encode(bytes(event_data.payload)).decode('ASCII'),
                        'payload_hash': base64.b64encode(bytes(event_data.payload_hash)).decode('ASCII'),
                        'payload_signature': base64.b64encode(bytes(event_data.payload_signature)).decode('ASCII'),
                        'user_key': base64.b64encode(bytes(event_data.user_key)).decode('ASCII'),
                        'user_pubkey': base64.b64encode(bytes(event_data.user_pubkey)).decode('ASCII'),
                        'handle': event_data.handle,
                        'callback_gas_limit': event_data.callback_gas_limit,
                        'nonce': base64.b64encode(bytes(event_data.nonce)).decode('ASCII')
                    }
                    # Create a Task object and add it to the task list
                    task_list.append(Task(args))

            return task_list
        except Exception as e:
            self.logger.error(f"Error parsing transaction: {e}")
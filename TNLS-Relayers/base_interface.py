import abc
import base64
import json
from typing import List
from yaml import safe_load
from pathlib import Path

# Load configuration data from 'config.yml' located in the same directory as this script
with open(f'{Path(__file__).parent.absolute()}/config.yml') as f:
    data = safe_load(f)

# Extract chain IDs for Ethereum (EVM), Solana, and Secret networks based on their type
eth_chains = [info['chain_id'] for key, info in data.items() if info['type'] == 'evm']
solana_chains = [info['chain_id'] for key, info in data.items() if info['type'] == 'solana']
scrt_chains = [info['chain_id'] for key, info in data.items() if info['type'] == 'secret']

# Define the mapping of task keys to message fields for Ethereum-based chains
eth_task_keys_to_msg = {
    '_taskId': 'task_id',
    '_sourceNetwork': 'source_network',
    '_info': [
        'payload_hash',
        'packet_hash',
        'callback_address',
        'callback_selector',
        'callback_gas_limit',
        'packet_signature',
        'result'
    ]
}

# Initialize dictionaries to store task key mappings and their order for each chain
task_keys_to_msg = {}
task_keys_in_order = {}

# For each Ethereum and Solana chain, assign the task key mappings and their order
for chain in eth_chains + solana_chains:
    task_keys_to_msg[chain] = eth_task_keys_to_msg
    task_keys_in_order[chain] = ['_taskId', '_sourceNetwork', '_info']

def to_dict(dict_to_parse, key_type=""):
    """
    Recursively converts an attribute dictionary to a JSON-serializable dict.

    Args:
        dict_to_parse: The dictionary to parse.
        key_type: The type of key to handle specific serialization cases.

    Returns:
        A JSON-serializable dictionary.
    """
    # Convert any 'AttributeDict' types to standard dictionaries
    parsed_dict = dict(dict_to_parse)
    for key, val in parsed_dict.items():
        # If the value is a dictionary, recursively convert it
        if 'dict' in str(type(val)).lower():
            parsed_dict[key] = to_dict(val)
        # Convert 'HexBytes' types to hexadecimal strings
        elif 'HexBytes' in str(type(val)):
            if key_type in task_keys_in_order:
                parsed_dict[key] = val.hex()
            else:
                if key == 'payload_signature':
                    # Remove the last byte for Ethereum-Secret compatibility
                    val = val[:-1]
                # Encode the value in base64
                parsed_dict[key] = base64.b64encode(val).decode('ascii')
        # If the value is bytes, handle it accordingly
        elif isinstance(val, bytes):
            if key_type in task_keys_in_order:
                # Convert bytes to hexadecimal string
                parsed_dict[key] = val.hex()
            else:
                if key == 'payload_signature':
                    # Remove the last byte for Ethereum-Secret compatibility
                    val = val[:-1]
                # Encode the value in base64
                parsed_dict[key] = base64.b64encode(val).decode('ascii')
    return parsed_dict

# Post-execution functions

def translate_dict(dict_to_translate, translation_mechanism):
    """
    Translates a dictionary from one format to another for interchain communication.

    Args:
        dict_to_translate: The dictionary to be translated.
        translation_mechanism: The mapping mechanism for translation.

    Returns:
        The translated dictionary.
    """
    translated_dict = {}
    for key, val in translation_mechanism.items():
        if isinstance(val, list):
            # If the value is a list, create a list of corresponding values
            translated_dict[key] = [dict_to_translate[inner_key] for inner_key in val]
        else:
            # Directly map the value
            translated_dict[key] = dict_to_translate[val]
    return translated_dict

class Task:
    """
    Represents an interchain message task.

    Attributes:
        task_destination_network: The network where the message should be routed.
        task_data: The data associated with the task.
    """

    def __init__(self, task_dict):
        # Ensure the task dictionary is a standard dictionary
        task_dict = dict(task_dict)
        if 'task_id' in task_dict:
            # Convert 'task_id' to a string
            task_dict['task_id'] = str(task_dict['task_id'])
        # Determine the task's destination network
        if 'task_destination_network' in task_dict:
            self.task_destination_network = task_dict['task_destination_network']
        elif 'routing_info' in task_dict and ':' in task_dict['routing_info']:
            # Parse the routing information if it contains a colon
            self.task_destination_network = task_dict['routing_info'].split(':')[0]
            task_dict['routing_info'] = task_dict['routing_info'].split(':')[1]
            task_dict['task_destination_network'] = self.task_destination_network
        elif 'routing_info' in task_dict:
            # Use the routing information directly
            self.task_destination_network = task_dict['routing_info']
            task_dict['task_destination_network'] = self.task_destination_network
        else:
            # If no routing information is available, set to None
            self.task_destination_network = None
        # Store the task data
        self.task_data = task_dict

    def __str__(self):
        # Check if there's a specific message format for the destination network
        if self.task_destination_network in task_keys_to_msg:
            task_translation_mechanism = task_keys_to_msg[self.task_destination_network]
            # Translate the task data according to the network's requirements
            new_task_dict = translate_dict(self.task_data, task_translation_mechanism)
            if '_taskId' in new_task_dict:
                # Ensure '_taskId' is an integer
                new_task_dict['_taskId'] = int(new_task_dict['_taskId'])
            if self.task_destination_network in task_keys_in_order:
                # Convert the task data to a JSON-serializable dictionary
                ndict = to_dict(new_task_dict, key_type=self.task_destination_network)
                # Arrange the task data in the specified order
                new_task_list = [ndict[key] for key in task_keys_in_order[self.task_destination_network]]
                # Return the task data as a JSON-formatted string
                return json.dumps(new_task_list)
            # Return the task data as a JSON-formatted string
            return json.dumps(to_dict(new_task_dict, key_type=self.task_destination_network))
        else:
            # If no specific format, return the task data as JSON
            return json.dumps(to_dict(self.task_data))

    def __repr__(self):
        # Use the string representation for debugging
        return self.__str__()

class BaseChainInterface(abc.ABC):
    """
    Abstract base class for all blockchain interfaces.

    Governs transaction retrieval and creation.
    """

    @abc.abstractmethod
    def sign_and_send_transaction(self, tx):
        """
        Signs and sends a raw transaction to the blockchain.

        Args:
            tx: The raw transaction to be sent.
        """
        pass

    @abc.abstractmethod
    def get_transactions(self, address, height=None):
        """
        Retrieves transactions from the blockchain based on specific filters.

        Args:
            address: The address to fetch transactions for.
            height: The block height to filter transactions (optional).
        """
        pass

    @abc.abstractmethod
    def get_last_block(self):
        """
        Retrieves the latest block height of the blockchain.
        """
        pass

class BaseContractInterface(abc.ABC):
    """
    Abstract base class for all smart contract interfaces.

    Governs contract interaction, execution, and event parsing.
    """
    address = None  # The blockchain address of the contract

    @abc.abstractmethod
    def call_function(self, function_name, *args):
        """
        Calls a function on the smart contract with the given arguments.

        Args:
            function_name: The name of the contract function to call.
            *args: Variable length argument list for function parameters.
        """
        pass

    @abc.abstractmethod
    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        """
        Parses specified events from a transaction.

        Args:
            event_name: The name of the event to parse.
            txn: The transaction from which to parse events.

        Returns:
            A list of Task objects corresponding to the parsed events.
        """
        pass

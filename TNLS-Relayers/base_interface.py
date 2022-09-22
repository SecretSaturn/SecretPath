import abc
import base64
import json
from typing import List

eth_task_keys_to_msg = {
    '_taskId': 'task_id', '_sourceNetwork': 'source_network', '_info': ['payload',
                                                                        'payload_hash',
                                                                        'payload_signature',
                                                                        'result',
                                                                        'result_hash',
                                                                        'result_signature',
                                                                        'packet_hash',
                                                                        'packet_signature']

}
task_keys_to_msg = {'ethereum': eth_task_keys_to_msg}
task_keys_in_order = {'ethereum': ['_taskId', '_sourceNetwork', '_info']}


def to_dict(dict_to_parse, key_type=""):
    """
    deeply converts an attribute dictionary to a json serializable dict
    sourced from SO on attribute dictionaries:
    Args:
        dict_to_parse: the dict to parse

    Returns: a serializable dict

    """
    # convert any 'AttributeDict' type found to 'dict'
    parsed_dict = dict(dict_to_parse)
    for key, val in parsed_dict.items():
        # check for nested dict structures to iterate through
        if 'dict' in str(type(val)).lower():
            parsed_dict[key] = to_dict(val)
        # convert 'HexBytes' type to 'str'
        elif 'HexBytes' in str(type(val)):
            if key_type in task_keys_in_order:
                parsed_dict[key] = val.hex()
            else:
                parsed_dict[key] = base64.b64encode(val).decode('ascii')
        elif isinstance(val, bytes):
            if key_type in task_keys_in_order:
                parsed_dict[key] = val.hex()
            else:
                parsed_dict[key] = base64.b64encode(val).decode('ascii')

    return parsed_dict


# Postexec



def translate_dict(dict_to_translate, translation_mechanism):
    """
    Translates a dictionary from one format to another (for interchain translation)
    Args:
        dict_to_translate: the dictionary to translate
        translation_mechanism: the mechanism to use for translation

    Returns: the translated dictionary
    """
    translated_dict = {}
    for key, val in translation_mechanism.items():
        if isinstance(val, list):
            translated_dict[key] = [dict_to_translate[inner_key] for inner_key in val]
        else:
            translated_dict[key] = dict_to_translate[val]
    return translated_dict


class Task:
    """
    Task class representing an interchain message
    task_destination_network is the network where the message should be routed.
    """

    def __init__(self, task_dict):
        task_dict = dict(task_dict)
        if 'task_destination_network' in task_dict:
            self.task_destination_network = task_dict['task_destination_network']
        elif 'routing_info' in task_dict and ':' in task_dict['routing_info']:
            self.task_destination_network = task_dict['routing_info'].split(':')[0]
            task_dict['routing_info'] = task_dict['routing_info'].split(':')[1]
            task_dict['task_destination_network'] = self.task_destination_network
        elif 'routing_info' in task_dict and 'secret' in task_dict['routing_info']:
            self.task_destination_network = 'secret'
            task_dict['task_destination_network'] = self.task_destination_network
        elif 'routing_info' in task_dict:
            self.task_destination_network = task_dict['routing_info']
            task_dict['task_destination_network'] = self.task_destination_network
        else:
            self.task_destination_network = None
        self.task_data = task_dict

    def __str__(self):
        if self.task_destination_network in task_keys_to_msg:
            task_translation_mechanism = task_keys_to_msg[self.task_destination_network]
            new_task_dict = translate_dict(self.task_data, task_translation_mechanism)
            if '_taskId' in new_task_dict:
                new_task_dict['_taskId'] = int(new_task_dict['_taskId'])
            if self.task_destination_network in task_keys_in_order:
                ndict = to_dict(new_task_dict, key_type=self.task_destination_network)
                new_task_list = [ndict[key] for key in task_keys_in_order[self.task_destination_network]]
                return json.dumps(new_task_list)
            return json.dumps(to_dict(new_task_dict, key_type=self.task_destination_network))
        else:
            return json.dumps(to_dict(self.task_data))

    def __repr__(self):
        return self.__str__()


class BaseChainInterface(abc.ABC):
    """
    Base class for all chain interfaces
    Governs transaction retrieval and creation
    """

    @abc.abstractmethod
    def sign_and_send_transaction(self, tx):
        """
        Given a raw transaction, signs it and sends it to the chain
        Args:
            tx: the raw transaction to be sent to the chain
        """
        pass

    @abc.abstractmethod
    def get_transactions(self, address, height=None):
        """
            Retrieves all transactions from the chain that fit interface-dependent filters
        """
        pass

    @abc.abstractmethod
    def get_last_block(self):
        """
            Retrieves the current block height of the chain
        """
        pass


class BaseContractInterface(abc.ABC):
    """
    Base class for all contract interfaces
    Governs contract interaction, execution, and event parsing.
    """
    address = None

    @abc.abstractmethod
    def call_function(self, function_name, *args):
        """
        Given a function in a contract, and the arguments to that function,
        calls it on chain
        Args:
            function_name: the name of the contract function to call
            *args: the (potentially many) arguments to pass to that function
        """
        pass

    @abc.abstractmethod
    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        """
        Given a transaction, outputs all the events of a particular name
        that were emitted in that transaction
        Args:
            event_name: the event to look for
            txn: the transaction to parse
        Returns: a list of Tasks corresponding to the events
        """
        pass

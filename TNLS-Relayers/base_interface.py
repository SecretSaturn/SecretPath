import abc
import json
from typing import List


def to_dict(dict_to_parse):
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
            parsed_dict[key] = val.hex()
    return parsed_dict


class Task:
    """
    Task class representing an interchain message
    task_destination_network is the network where the message should be routed.
    """
    def __init__(self, task_dict):
        if 'task_destination_network' in task_dict:
            self.task_destination_network = task_dict['task_destination_network']
        elif 'routing_info' in task_dict:
            self.task_destination_network = task_dict['routing_info']
        else:
            self.task_destination_network = None
        self.task_data = task_dict

    def __str__(self):
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
    def get_transactions(self, address):
        """
            Retrieves all transactions from the chain that fit interface-dependent filters
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

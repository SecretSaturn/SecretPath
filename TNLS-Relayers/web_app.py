from threading import Thread
from typing import Dict, Tuple

from flask import Flask, current_app, Blueprint
from yaml import safe_load

from base_interface import BaseChainInterface, BaseContractInterface
from eth_interface import EthInterface, EthContract
from relayer import Relayer

base_map = {'Ethereum': (EthInterface, EthContract)}


def convert_config_file_to_dict(config_file, map_of_names_to_interfaces=None) -> \
        Dict[str, Tuple[BaseChainInterface, BaseContractInterface, str, str]]:
    """
    Converts a yml config file into a dict of names to interfaces for the relayer
    Args:
        config_file: the config file to pull from
        map_of_names_to_interfaces: an initial map of names to the classes they should be instantiated as

    Returns: a dict mapping names to interfaces as the relayer expects

    """
    if map_of_names_to_interfaces is None:
        map_of_names_to_interfaces = base_map
    with open(config_file) as f:
        config_dict = safe_load(f)
    necessary_keys = ['contract_address', 'contract_schema', 'private_key', 'wallet_address',
                      'event_name', 'function_name']
    for key, val in config_dict.items():
        if not all(val_key in val for val_key in necessary_keys):
            raise ValueError(f'{key} is missing necessary keys: {set(necessary_keys) - set(val.keys())}')
        if key not in map_of_names_to_interfaces:
            raise ValueError(f'{key} not in map of names to interfaces')
        chain_interface, contract_interface = map_of_names_to_interfaces[key]
        initialized_chain = chain_interface(private_key=val['private_key'], address=val['wallet_address'])
        initialized_contract = contract_interface(interface=initialized_chain, address=val['contract_address'],
                                                  abi=val['contract_schema'])
        config_dict[key] = (initialized_chain, initialized_contract, val['event_name'], val['function_name'])
    return config_dict


route_blueprint = Blueprint('route_blueprint', __name__)


@route_blueprint.route('/')
def index():
    """

    Returns: The status of the relayer

    """
    return str(current_app.config['RELAYER'])


def app_factory(config_filename, config_file_converter=convert_config_file_to_dict, num_loops=None):
    """
    Creates a Flask app with a relayer running on the backend
    Args:
        config_filename: Which filepath to pull config from
        config_file_converter: How to convert that config file into relayer config
        num_loops: How many times the relayer should run before shutting down, None=Infinity

    Returns: a flask app

    """
    app = Flask(__name__)
    relayer = Relayer(config_file_converter(config_filename), num_loops=num_loops)
    thread = Thread(target=relayer.run)
    thread.start()
    app.config['RELAYER'] = relayer
    app.register_blueprint(route_blueprint)
    return app

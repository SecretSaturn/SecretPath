import json
import os
from pathlib import Path
from threading import Thread

from flask import Flask, current_app, Blueprint
from yaml import safe_load

from eth_interface import EthInterface, EthContract
from relayer import Relayer
from scrt_interface import SCRTInterface, SCRTContract

base_map = {'Ethereum': (EthInterface, EthContract), 'Secret': (SCRTInterface, SCRTContract)}


def generate_eth_config(config_dict, provider=None):
    """
    Converts a config dict into a tuple of (chain_interface, contract_interface, event_name, function_name)
    for ethereum
    Args:
        config_dict: a dict containing contract address, contract schema, and wallet address
        provider: an optional API client

    Returns: the relevant tuple of chain, contract, event, and function

    """
    priv_key = bytes.fromhex(os.environ['ethereum-private-key'])
    address = config_dict['wallet_address']
    contract_address = config_dict['contract_address']
    contract_schema = config_dict['contract_schema']
    event_name = 'logNewTask'
    function_name = 'postExecution'
    initialized_chain = EthInterface(private_key=priv_key, address=address, provider=provider)
    initialized_contract = EthContract(interface=initialized_chain, address=contract_address,
                                       abi=contract_schema)
    eth_tuple = (initialized_chain, initialized_contract, event_name, function_name)
    return eth_tuple


def generate_scrt_config(config_dict, provider=None):
    """
        Converts a config dict into a tuple of (chain_interface, contract_interface, event_name, function_name)
        for secret
        Args:
            config_dict: a dict containing contract address, contract schema, and wallet address
            provider: an optional API client

        Returns: the relevant tuple of chain, contract, event, and function

    """
    priv_key = bytes.fromhex(os.environ['secret-private-key'])
    address = config_dict['wallet_address']
    contract_address = config_dict['contract_address']
    with open(f'{Path(__file__).parent.absolute()}/secret_abi.json') as f:
        contract_schema = f.read()
    event_name = 'wasm'
    function_name = list(json.loads(contract_schema).keys())[0]
    initialized_chain = SCRTInterface(private_key=priv_key, address=address, provider=provider)
    specialized_initialized_chain = SCRTInterface(private_key=priv_key, address=address, provider=provider)
    if provider is None:
        initialized_contract = SCRTContract(interface=specialized_initialized_chain, address=contract_address,
                                            abi=contract_schema)
    else:
        initialized_contract = SCRTContract(interface=initialized_chain, address=contract_address,
                                            abi=contract_schema)
    scrt_tuple = (initialized_chain, initialized_contract, event_name, function_name)
    return scrt_tuple


def generate_full_config(config_file, provider_pair=None):
    """
    Takes in a yaml filepath and generates a config dict for eth and scrt relays
    Args:
        config_file: the path to the relevant config file
        provider_pair: a pair of scrt and eth providers, optional

    Returns:
            a dict mapping scrt and eth to their respective configs

    """
    with open(config_file) as f:
        config_dict = safe_load(f)
    if provider_pair is None:
        provider_eth, provider_scrt = None, None
    else:
        provider_eth, provider_scrt = provider_pair
    eth_config = generate_eth_config(config_dict['ethereum'], provider=provider_eth)
    scrt_config = generate_scrt_config(config_dict['secret'], provider=provider_scrt)
    keys_dict = {'secret': {'verification': config_dict['secret']['contract_eth_address'],
                            'encryption': config_dict['secret']['contract_encryption_key']}}
    return {'ethereum': eth_config, 'secret': scrt_config}, keys_dict


route_blueprint = Blueprint('route_blueprint', __name__)


@route_blueprint.route('/')
def index():
    """

    Returns: a string form of the relayer

    """
    return str(current_app.config['RELAYER'])


@route_blueprint.route('/tasks_to_routes')
def task_json():
    """

    Returns: The status of the relayer

    """
    return str(current_app.config['RELAYER'].task_ids_to_statuses)


@route_blueprint.route('/networks_to_blocks')
def net_to_block():
    """

    Returns: The status of the relayer

    """
    return str(current_app.config['RELAYER'].dict_of_names_to_blocks)


@route_blueprint.route('/ids_to_jsons')
def id_to_json():
    """

    Returns: The status of the relayer

    """
    return str(current_app.config['RELAYER'].task_ids_to_info)


@route_blueprint.route('/networks_to_addresses')
def net_to_address():
    """

        Returns: The map of names to contract addresses

        """
    return str(current_app.config['RELAYER'].dict_of_names_to_addresses)


@route_blueprint.route('/keys')
def keys():
    """

    Returns: the current encryption and verification keys

    """
    return str(current_app.config['KEYS'])


def app_factory(config_filename=f'{Path(__file__).parent.absolute()}/../config.yml',
                config_file_converter=generate_full_config, num_loops=None, do_restart=True):
    """
    Creates a Flask app with a relayer running on the backend
    Args:
        config_filename: Which filepath to pull config from
        config_file_converter: How to convert that config file into relayer config
        num_loops: How many times the relayer should run before shutting down, None=Infinity

    Returns: a flask app

    """
    import warnings
    warnings.simplefilter("ignore", UserWarning)
    app = Flask(__name__)
    config, keys_dict = config_file_converter(config_filename)
    relayer = Relayer(config, num_loops=num_loops)
    app.config['RELAYER'] = relayer
    app.config['KEYS'] = keys_dict
    app.register_blueprint(route_blueprint)
    thread = Thread(target=relayer.run)
    thread.start()

    def _thread_restarter():
        thread_target = thread
        while True:
            thread_target.join()
            relayer = Relayer(config, num_loops=num_loops)
            thread_2 = Thread(target=relayer.run)
            thread_2.start()
            thread_target = thread_2
            app.config['RELAYER'] = relayer

    thread_restarter = Thread(target=_thread_restarter)
    if do_restart:
        thread_restarter.start()
    return app


if __name__ == '__main__':
    app = app_factory(f'{Path(__file__).parent.absolute()}/../config.yml')
    app.run()

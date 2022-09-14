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
    return {'ethereum': eth_config, 'secret': scrt_config}


route_blueprint = Blueprint('route_blueprint', __name__)


@route_blueprint.route('/')
def index():
    """

    Returns: The status of the relayer

    """
    return str(current_app.config['RELAYER'])


def app_factory(config_filename, config_file_converter=generate_full_config, num_loops=None):
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

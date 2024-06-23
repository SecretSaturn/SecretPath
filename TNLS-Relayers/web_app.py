import json
import os
from pathlib import Path

from flask import Flask, current_app, Blueprint
from yaml import safe_load

from eth_interface import EthInterface, EthContract
from relayer import Relayer
from scrt_interface import SCRTInterface, SCRTContract
from sol_interface import SolanaInterface, SolanaContract
from base_interface import eth_chains, scrt_chains, solana_chains
from dotenv import load_dotenv

load_dotenv()

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
    chain_id = config_dict['chain_id']
    api_endpoint = config_dict['api_endpoint']
    timeout = config_dict['timeout']

    event_name = 'logNewTask'
    function_name = 'postExecution'

    initialized_chain = EthInterface(private_key=priv_key, address=address, provider=provider, chain_id=chain_id,
                                     api_endpoint=api_endpoint, timeout=timeout)
    initialized_contract = EthContract(interface=initialized_chain, address=contract_address,
                                       abi=contract_schema)
    eth_tuple = (initialized_chain, initialized_contract, event_name, function_name)
    return eth_tuple

def generate_solana_config(config_dict, provider=None):
    """
    Converts a config dict into a tuple of (rpc_client, contract_address, wallet_address, function_name) for Solana.
    Args:
        config_dict: a dictionary containing relevant information such as RPC endpoint, contract address, wallet address, etc.

    Returns:
        A tuple of Solana RPC client, contract address, wallet public key, and a function name.
    """

    priv_key = os.environ['solana-private-key']
    wallet_address = config_dict["wallet_address"]
    api_endpoint = config_dict["api_endpoint"]
    program_id = config_dict['program_id']
    program_account = config_dict['program_account']
    idl = config_dict['idl']
    chain_id = config_dict['chain_id']
    timeout = config_dict['timeout']

    event_name = 'logNewTask'
    function_name = 'postExecution'

    initialized_chain = SolanaInterface(private_key=priv_key, address=wallet_address,
                                        provider=provider, chain_id=chain_id, api_endpoint=api_endpoint,
                                        timeout=timeout)
    initialized_contract = SolanaContract(interface=initialized_chain, program_id=program_id
                                          , program_account=program_account, idl=idl)

    solana_tuple = (initialized_chain, initialized_contract, event_name, function_name)
    return solana_tuple

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
    api_endpoint = config_dict['api_endpoint']
    chain_id = config_dict['chain_id']
    code_hash = config_dict['code_hash']
    feegrant_address = config_dict['feegrant_address']
    with open(f'{Path(__file__).parent.absolute()}/secret_abi.json') as f:
        contract_schema = f.read()
    event_name = 'wasm'
    function_name = list(json.loads(contract_schema).keys())[0]
    initialized_chain = None

    if provider is None:
        initialized_chain = SCRTInterface(private_key = priv_key, address = address, provider = None,
                                          api_url = api_endpoint, chain_id = chain_id, feegrant_address = feegrant_address)
    else:
        initialized_chain = SCRTInterface(private_key=priv_key, address = address, provider = provider, chain_id = chain_id,  feegrant_address = feegrant_address)

    initialized_contract = SCRTContract(interface=initialized_chain, address=contract_address,
                                        abi=contract_schema, code_hash = code_hash)
    scrt_tuple = (initialized_chain, initialized_contract, event_name, function_name)
    return scrt_tuple


def generate_full_config(config_file, providers=None):
    """
    Takes in a yaml filepath and generates a config dict for eth and scrt relays
    Args:
        config_file: the path to the relevant config file
        providers: inject all providers if needed

    Returns:
            a dict mapping scrt and eth to their respective configs

    """
    with open(config_file) as f:
        config_dict = safe_load(f)
    if providers is None:
        provider_eth, provider_solana, provider_scrt = None, None, None
    else:
        provider_eth, provider_solana, provider_scrt = providers
    keys_dict = {}
    chains_dict = {}
    for chain in eth_chains:
        if config_dict[chain]['active']:
            chains_dict[chain] = generate_eth_config(config_dict[chain], provider=provider_eth)
    for chain in solana_chains:
        if config_dict[chain]['active']:
            chains_dict[chain] = generate_solana_config(config_dict[chain], provider=provider_solana)
    for chain in scrt_chains:
        if config_dict[chain]['active']:
            chains_dict[chain] = generate_scrt_config(config_dict[chain], provider=provider_scrt)
    return chains_dict, keys_dict


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
                config_file_converter=generate_full_config, num_loops=None):
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
    relayer.run()
    return app


if __name__ == '__main__':
    app = app_factory(f'{Path(__file__).parent.absolute()}/../config.yml')
    app.run()

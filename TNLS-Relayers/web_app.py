import json
import os
from logging import getLogger, basicConfig, INFO, StreamHandler
from pathlib import Path

from flask import Flask, current_app, Blueprint
from yaml import safe_load

from eth_interface import EthInterface, EthContract
from relayer import Relayer
from scrt_interface import SCRTInterface, SCRTContract
from sol_interface import SolanaInterface, SolanaContract
from base_interface import eth_chains, scrt_chains, solana_chains
from dotenv import load_dotenv

# Load environment variables from a .env file into os.environ
load_dotenv()

# Read the Ethereum contract ABI (Application Binary Interface) from 'gateway.json'
with open(f'{Path(__file__).parent.absolute()}/gateway.json', 'r') as file:
    eth_contract_schema = file.read()

def generate_eth_config(config_dict, provider=None):
    """
    Converts a configuration dictionary into Ethereum-specific components needed for the relayer.

    Args:
        config_dict (dict): Contains contract address, chain ID, API endpoint, timeout, etc.
        provider (optional): Custom provider (e.g., web3 provider)

    Returns:
        tuple: (chain_interface, contract_interface, event_name, function_name)
    """
    # Retrieve the Ethereum private key from environment variables and convert it to bytes
    priv_key = bytes.fromhex(os.environ['ethereum-private-key'])

    # Extract configuration parameters from the config dictionary
    contract_address = config_dict['contract_address']
    contract_schema = eth_contract_schema  # Use the ABI loaded earlier
    chain_id = config_dict['chain_id']
    api_endpoint = config_dict['api_endpoint']
    timeout = config_dict['timeout']

    # Define the event name to listen for and the function name to invoke
    event_name = 'logNewTask'
    function_name = 'postExecution'

    # Initialize the Ethereum chain interface with the provided parameters
    initialized_chain = EthInterface(
        private_key=priv_key,
        provider=provider,
        chain_id=chain_id,
        api_endpoint=api_endpoint,
        timeout=timeout
    )

    # Initialize the Ethereum contract interface with the chain interface and contract details
    initialized_contract = EthContract(
        interface=initialized_chain,
        address=contract_address,
        abi=contract_schema
    )

    # Create a tuple containing all necessary components
    eth_tuple = (initialized_chain, initialized_contract, event_name, function_name)
    return eth_tuple

def generate_solana_config(config_dict, provider=None):
    """
    Converts a configuration dictionary into Solana-specific components needed for the relayer.

    Args:
        config_dict (dict): Contains program ID, chain ID, API endpoint, timeout, etc.
        provider (optional): Custom provider (e.g., Solana RPC client)

    Returns:
        tuple: (chain_interface, contract_interface, event_name, function_name)
    """
    # Retrieve the Solana private key from environment variables
    priv_key = os.environ['solana-private-key']

    # Extract configuration parameters from the config dictionary
    api_endpoint = config_dict["api_endpoint"]
    program_id = config_dict['program_id']  # Address of the Solana program (smart contract)
    chain_id = config_dict['chain_id']
    timeout = config_dict['timeout']

    # Define the event name to listen for and the function name to invoke
    event_name = 'logNewTask'
    function_name = 'postExecution'

    # Initialize the Solana chain interface with the provided parameters
    initialized_chain = SolanaInterface(
        private_key=priv_key,
        provider=provider,
        chain_id=chain_id,
        api_endpoint=api_endpoint,
        timeout=timeout
    )

    # Initialize the Solana contract interface with the chain interface and program ID
    initialized_contract = SolanaContract(
        interface=initialized_chain,
        program_id=program_id
    )

    # Create a tuple containing all necessary components
    solana_tuple = (initialized_chain, initialized_contract, event_name, function_name)
    return solana_tuple

def generate_scrt_config(config_dict, provider=None):
    """
    Converts a configuration dictionary into Secret Network-specific components needed for the relayer.

    Args:
        config_dict (dict): Contains contract address, code hash, chain ID, API endpoint, etc.
        provider (optional): Custom provider (e.g., SecretJS client)

    Returns:
        tuple: (chain_interface, contract_interface, event_name, function_name)
    """
    # Retrieve the Secret Network private key from environment variables and convert it to bytes
    priv_key = bytes.fromhex(os.environ['secret-private-key'])

    # Extract configuration parameters from the config dictionary
    contract_address = config_dict['contract_address']
    api_endpoint = config_dict['api_endpoint']
    chain_id = config_dict['chain_id']
    code_hash = config_dict['code_hash']  # Required for interacting with Secret contracts

    # Optional fee grant address
    feegrant_address = config_dict['feegrant_address'] if 'feegrant_address' in config_dict else None

    # Load the Secret contract ABI from 'secret_abi.json'
    with open(f'{Path(__file__).parent.absolute()}/secret_abi.json') as f:
        contract_schema = f.read()

    # Define the event name to listen for and determine the function name from the ABI
    event_name = 'wasm'
    function_name = list(json.loads(contract_schema).keys())[0]

    # Initialize the Secret Network chain interface with the provided parameters
    initialized_chain = SCRTInterface(
        private_key=priv_key,
        provider=provider,
        chain_id=chain_id,
        feegrant_address=feegrant_address,
        api_url=api_endpoint
    )

    # Initialize the Secret Network contract interface with the chain interface and contract details
    initialized_contract = SCRTContract(
        interface=initialized_chain,
        address=contract_address,
        abi=contract_schema,
        code_hash=code_hash
    )

    # Create a tuple containing all necessary components
    scrt_tuple = (initialized_chain, initialized_contract, event_name, function_name)
    return scrt_tuple

def generate_full_config(config_file, providers=None):
    """
    Takes in a YAML configuration file and generates configurations for all active chains.

    Args:
        config_file (str): The path to the YAML configuration file.
        providers (tuple, optional): Custom providers for each chain (Ethereum, Solana, Secret).

    Returns:
        tuple: (chains_dict, keys_dict)
            - chains_dict: A dictionary mapping chain names to their configuration tuples.
            - keys_dict: A dictionary for storing keys (currently empty).
    """
    # Set up basic logging configuration for the application
    basicConfig(
        level=INFO,
        format="%(asctime)s [Eth Interface: %(levelname)8.8s] %(message)s",
        handlers=[StreamHandler()],
    )
    logger = getLogger()

    # Load the configuration dictionary from the YAML file
    with open(config_file) as f:
        config_dict = safe_load(f)

    # If no providers are specified, default to None for each chain
    if providers is None:
        provider_eth, provider_solana, provider_scrt = None, None, None
    else:
        provider_eth, provider_solana, provider_scrt = providers
    keys_dict = {}  # Initialize an empty dictionary for keys (future use)
    chains_dict = {}  # Initialize an empty dictionary to store chain configurations

    # Iterate over all Ethereum chains defined in base_interface.eth_chains
    for chain in eth_chains:
        if config_dict[chain]['active']:
            try:
                # Generate the Ethereum configuration tuple and add it to chains_dict
                chains_dict[chain] = generate_eth_config(config_dict[chain], provider=provider_eth)
            except Exception as e:
                logger.error(f"Error generating ETH config for chain '{chain}': {e}")

    # Iterate over all Solana chains defined in base_interface.solana_chains
    for chain in solana_chains:
        if config_dict[chain]['active']:
            # Generate the Solana configuration tuple and add it to chains_dict
            chains_dict[chain] = generate_solana_config(config_dict[chain], provider=provider_solana)

    # Iterate over all Secret Network chains defined in base_interface.scrt_chains
    for chain in scrt_chains:
        if config_dict[chain]['active']:
            try:
                # Generate the Secret Network configuration tuple and add it to chains_dict
                chains_dict[chain] = generate_scrt_config(config_dict[chain], provider=provider_scrt)
            except Exception as e:
                logger.error(f"Error generating SCRT config for chain '{chain}': {e}")

    return chains_dict, keys_dict

# Create a Flask Blueprint for organizing routes
route_blueprint = Blueprint('route_blueprint', __name__)

@route_blueprint.route('/')
def index():
    """
    Root endpoint that returns a string representation of the relayer.

    Returns:
        str: String form of the relayer object.
    """
    return str(current_app.config['RELAYER'])

@route_blueprint.route('/tasks_to_routes')
def task_json():
    """
    Endpoint to get the status of tasks managed by the relayer.

    Returns:
        str: String representation of task IDs mapped to their statuses.
    """
    return str(current_app.config['RELAYER'].task_ids_to_statuses)

@route_blueprint.route('/networks_to_blocks')
def net_to_block():
    """
    Endpoint to get the latest processed block numbers for each network.

    Returns:
        str: String representation of network names mapped to their latest block numbers.
    """
    return str(current_app.config['RELAYER'].dict_of_names_to_blocks)

@route_blueprint.route('/ids_to_jsons')
def id_to_json():
    """
    Endpoint to get detailed information about each task.

    Returns:
        str: String representation of task IDs mapped to their detailed information.
    """
    return str(current_app.config['RELAYER'].task_ids_to_info)

@route_blueprint.route('/networks_to_addresses')
def net_to_address():
    """
    Endpoint to get the mapping of network names to contract addresses.

    Returns:
        str: String representation of network names mapped to contract addresses.
    """
    return str(current_app.config['RELAYER'].dict_of_names_to_addresses)

@route_blueprint.route('/keys')
def keys():
    """
    Endpoint to get the current encryption and verification keys.

    Returns:
        str: String representation of the keys.
    """
    return str(current_app.config['KEYS'])

def app_factory(config_filename=f'{Path(__file__).parent.absolute()}/config.yml',
                config_file_converter=generate_full_config, num_loops=None):
    """
    Factory function to create and configure the Flask app with the relayer.

    Args:
        config_filename (str): Path to the configuration YAML file.
        config_file_converter (function): Function to convert the config file into relayer configuration.
        num_loops (int, optional): Number of times the relayer should run before shutting down. None means infinite.

    Returns:
        Flask: Configured Flask app instance.
    """
    import warnings
    warnings.simplefilter("ignore", UserWarning)  # Ignore user warnings for cleaner output
    app = Flask(__name__)  # Initialize the Flask app
    # Generate the relayer configuration and keys dictionary
    config, keys_dict = config_file_converter(config_filename)
    # Initialize the relayer with the generated configuration
    relayer = Relayer(config, num_loops=num_loops)
    # Store the relayer and keys in the app's configuration
    app.config['RELAYER'] = relayer
    app.config['KEYS'] = keys_dict
    # Register the blueprint containing the defined routes
    app.register_blueprint(route_blueprint)
    # Start the relayer's main loop (this might block execution if not run in a separate thread)
    relayer.run()
    return app

if __name__ == '__main__':
    # If the script is run directly, create the app using the default configuration file
    app = app_factory(f'{Path(__file__).parent.absolute()}/config.yml')
    # Run the Flask app on the local development server
    app.run()
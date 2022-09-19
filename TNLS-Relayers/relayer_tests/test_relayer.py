import os
import time
from json import loads
from logging import WARNING
from typing import List

import pytest
from eth_tester import EthereumTester, PyEVMBackend
from secret_sdk.client.localsecret import LocalSecret, LOCAL_MNEMONICS, LOCAL_DEFAULTS
from secret_sdk.core.bank import MsgSend
from secret_sdk.core.coins import Coins
from secret_sdk.key.mnemonic import MnemonicKey
from web3 import Web3
from yaml import safe_load, safe_dump

from base_interface import BaseChainInterface, BaseContractInterface, Task, translate_dict
from relayer import Relayer
from web_app import app_factory, generate_scrt_config, generate_eth_config, \
    generate_full_config


@pytest.fixture
def provider_privkey_address_eth(monkeypatch):
    """
    Fixture that provides a mock eth backend as well as a private key and address
    for an account on that backend

    """
    base_provider = Web3.EthereumTesterProvider(EthereumTester(backend=PyEVMBackend()))
    base_priv_key = base_provider.ethereum_tester.backend.account_keys[0]
    base_addr = base_provider.ethereum_tester.get_accounts()[0]
    web3provider = Web3(base_provider)
    yield web3provider, base_priv_key, base_addr


@pytest.fixture
def provider_privkey_address_scrt(monkeypatch):
    """
    Fixture that provides a mock scrt backend as well as a private key and address
    for an account on that backend

    """
    LOCAL_DEFAULTS['secretdev-1'] = {
        "url": "http://localhost:1317",
        "chain_id": 'secretdev-1',
        "gas_prices": {"uscrt": 0.25},
        "gas_adjustment": 1.0,
    }
    LOCAL_MNEMONICS['secretdev-1'] = {
        "wallet_a": {
            "mnemonic": "grant rice replace explain federal release fix clever romance raise"
                        " often wild taxi quarter soccer fiber love must tape steak together observe swap guitar"

        }

    }
    local_provider = LocalSecret(chain_id='secretdev-1')
    key = MnemonicKey(mnemonic=LOCAL_MNEMONICS['secretdev-1']['wallet_a']['mnemonic'])
    private_key = key.private_key
    address = key.acc_address
    return local_provider, private_key, address


@pytest.fixture
def set_os_env_vars(provider_privkey_address_eth, provider_privkey_address_scrt):
    """
    Fixture that sets the environment variables for the relayer to run
    and then unsets them afterwards
    """
    curr_scrt = os.environ.get('secret-private-key', None)
    curr_eth = os.environ.get('eth-private-key', None)
    scrt_key = provider_privkey_address_scrt[1]
    eth_key = provider_privkey_address_eth[1]
    os.environ['secret-private-key'] = scrt_key.hex()
    os.environ['ethereum-private-key'] = eth_key.to_hex()[2:]
    yield
    if curr_scrt is None:
        del os.environ['secret-private-key']
    else:
        os.environ['secret-private-key'] = curr_scrt
    if curr_eth is None:
        del os.environ['ethereum-private-key']
    else:
        os.environ['ethereum-private-key'] = curr_eth


@pytest.fixture
def address_and_abi_of_contract(provider_privkey_address_eth):
    """
    Creates a contract with the below code, deploys it, and returns it, it's address, and ABI.
    """

    #
    # pragma solidity^0.5.3;
    #
    # contract Foo {
    #
    #     string public bar;
    #     event barred(string _bar);
    #
    #     constructor() public {
    #         bar = "hello world";
    #     }
    #
    #     function setBar(string memory _bar) public {
    #         bar = _bar;
    #         emit barred(_bar);
    #     }
    #
    # }
    provider_privkey_address = provider_privkey_address_eth
    deploy_address = Web3.EthereumTesterProvider().ethereum_tester.get_accounts()[0]

    abi = """[{"anonymous":false,"inputs":[{"indexed":false,"name":"_bar","type":"string"}],"name":"barred","type":"event"},{"constant":false,"inputs":[{"name":"_bar","type":"string"}],"name":"setBar","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"constant":true,"inputs":[],"name":"bar","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}]"""  # noqa: E501
    # This bytecode is the output of compiling with
    # solc version:0.5.3+commit.10d17f24.Emscripten.clang
    bytecode = """608060405234801561001057600080fd5b506040805190810160405280600b81526020017f68656c6c6f20776f726c640000000000000000000000000000000000000000008152506000908051906020019061005c929190610062565b50610107565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100a357805160ff19168380011785556100d1565b828001600101855582156100d1579182015b828111156100d05782518255916020019190600101906100b5565b5b5090506100de91906100e2565b5090565b61010491905b808211156101005760008160009055506001016100e8565b5090565b90565b6103bb806101166000396000f3fe608060405234801561001057600080fd5b5060043610610053576000357c01000000000000000000000000000000000000000000000000000000009004806397bc14aa14610058578063febb0f7e14610113575b600080fd5b6101116004803603602081101561006e57600080fd5b810190808035906020019064010000000081111561008b57600080fd5b82018360208201111561009d57600080fd5b803590602001918460018302840111640100000000831117156100bf57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610196565b005b61011b61024c565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561015b578082015181840152602081019050610140565b50505050905090810190601f1680156101885780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b80600090805190602001906101ac9291906102ea565b507f5f71ad82e16f082de5ff496b140e2fbc8621eeb37b36d59b185c3f1364bbd529816040518080602001828103825283818151815260200191508051906020019080838360005b8381101561020f5780820151818401526020810190506101f4565b50505050905090810190601f16801561023c5780820380516001836020036101000a031916815260200191505b509250505060405180910390a150565b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156102e25780601f106102b7576101008083540402835291602001916102e2565b820191906000526020600020905b8154815290600101906020018083116102c557829003601f168201915b505050505081565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061032b57805160ff1916838001178555610359565b82800160010185558215610359579182015b8281111561035857825182559160200191906001019061033d565b5b509050610366919061036a565b5090565b61038c91905b80821115610388576000816000905550600101610370565b5090565b9056fea165627a7a72305820ae6ca683d45ee8a71bba45caee29e4815147cd308f772c853a20dfe08214dbb50029"""  # noqa: E501

    # Create our contract class.
    foo_contract = provider_privkey_address[0].eth.contract(abi=abi, bytecode=bytecode)
    # issue a transaction to deploy the contract.
    tx_hash = foo_contract.constructor().transact(
        {
            "from": deploy_address,
            'gas': 1000000,
        }
    )
    # wait for the transaction to be mined
    tx_receipt = provider_privkey_address[0].eth.wait_for_transaction_receipt(tx_hash, 180)
    # instantiate and return an instance of our contract.
    return tx_receipt.contractAddress, abi, foo_contract(tx_receipt.contractAddress)


def test_scrt_config(set_os_env_vars, provider_privkey_address_scrt):
    # Tests that scrt config generates properly from config dict
    provider = provider_privkey_address_scrt[0]
    address = provider_privkey_address_scrt[2]
    config_dict = {'wallet_address': provider_privkey_address_scrt[2], 'contract_address': '0x0'}
    interface, contract_interface, evt_name, function_name = generate_scrt_config(config_dict, provider=provider)
    assert evt_name == 'wasm'
    assert function_name == 'PreExecutionMsg'
    assert contract_interface.address == '0x0'
    assert contract_interface.interface == interface
    fee = interface.wallet.lcd.custom_fees["send"]

    msg = MsgSend(address, address, Coins.from_str("1000uscrt"))
    signed_tx = interface.wallet.create_tx([msg], fee=fee)
    broadcast_rcpt = interface.sign_and_send_transaction(signed_tx)
    logs = loads(broadcast_rcpt.raw_log)[0]
    assert 'events' in logs
    event = [event for event in logs['events'] if event["type"] == "coin_received"][0]
    attribute = [attribute for attribute in event['attributes'] if attribute['key'] == "amount"][0]
    assert attribute['value'] == "1000uscrt"
    height = broadcast_rcpt.height
    txns = interface.get_transactions(address=address, height=height)
    assert len(txns) == 1
    logs = txns[0]
    event = [event for event in logs.events if event["type"] == "coin_received"][0]
    attribute = [attribute for attribute in event['attributes'] if attribute['key'] == "amount"][0]
    assert attribute['value'] == "1000uscrt"
    attribute = [attribute for attribute in event['attributes'] if attribute['key'] == "receiver"][0]
    assert attribute['value'] == address


def test_eth_config(set_os_env_vars, provider_privkey_address_eth, address_and_abi_of_contract):
    # Tests that eth config generates properly from config dict
    address, abi, _ = address_and_abi_of_contract
    config_dict = {'wallet_address': provider_privkey_address_eth[2], 'contract_address': address,
                   'contract_schema': abi}
    chain_interface, contract_interface, evt_name, function_name = generate_eth_config(config_dict, provider=
    provider_privkey_address_eth[0])
    assert evt_name == 'logNewTask'
    assert function_name == 'postExecution'
    assert contract_interface.address == address
    assert contract_interface.interface == chain_interface
    transaction = {'data': '0x123', 'from': provider_privkey_address_eth[2], 'nonce': 1, 'gas': 200000,
                   'to': provider_privkey_address_eth[2], 'gasPrice': 1000000000000}
    # string is saved tx_hash
    assert str(Web3.toInt(chain_interface.sign_and_send_transaction(
        transaction))) == '18798041108694988948920655944567079244253059705561626119739063556193487749726'


@pytest.fixture
def rewrite_yaml(address_and_abi_of_contract, provider_privkey_address_eth, provider_privkey_address_scrt,
                 set_os_env_vars, request):
    """
    Fixture that correctly generates a full relayer config file for testing from test provider vars

    """
    yml_file = f'{request.path.parent}/../../config.yml'
    tempfile = f'{request.path.parent}/sample_config_full.yml'

    with open(yml_file, 'r') as f:
        config_dict = safe_load(f)

    eth_wallet_address = provider_privkey_address_eth[2]
    scrt_wallet_address = provider_privkey_address_scrt[2]
    eth_contract_address = address_and_abi_of_contract[0]
    scrt_contract_address = '0x0'
    eth_contract_schema = address_and_abi_of_contract[1]
    config_dict['ethereum']['wallet_address'] = eth_wallet_address
    config_dict['ethereum']['contract_address'] = eth_contract_address
    config_dict['ethereum']['contract_schema'] = eth_contract_schema
    config_dict['secret']['wallet_address'] = scrt_wallet_address
    config_dict['secret']['contract_address'] = scrt_contract_address
    with open(tempfile, 'w') as f:
        safe_dump(config_dict, f, default_flow_style=False)


def test_gen_full_config(rewrite_yaml, request, provider_privkey_address_scrt, provider_privkey_address_eth):
    # Tests that config correctly populates from config file
    config, keys_dict = generate_full_config(f'{request.path.parent}/sample_config_full.yml',
                                             provider_pair=(
                                             provider_privkey_address_eth[0], provider_privkey_address_scrt[0]))
    eth_config = config['ethereum']
    scrt_config = config['secret']
    interface, contract_interface, evt_name, function_name = scrt_config
    assert evt_name == 'wasm'
    assert function_name == 'PreExecutionMsg'
    assert contract_interface.address == '0x0'
    assert contract_interface.interface == interface
    interface, contract_interface, evt_name, function_name = eth_config
    assert evt_name == 'logNewTask'
    assert function_name == 'postExecution'
    assert contract_interface.interface == interface
    assert keys_dict['secret'] == {'encryption': "INSERT_SECRET_CONTRACT_ENCRYPTION_KEY_HERE",
                                   'verification': "INSERT_SECRET_CONTRACT_ETH_ADDRESS_HERE"}


class FakeChainInterface(BaseChainInterface):
    """
    A testing chain interface that returns a fixed set of transactions
    """

    def __init__(self, tx_list):
        self.tx_list = tx_list
        self.height_call_list = []
        self.start_height = 1
        pass

    def get_transactions(self, _, height=None):
        self.height_call_list.append(height)
        return self.tx_list
        pass

    def create_transaction(self, _contract_function, _data):
        pass

    def sign_and_send_transaction(self, _tx):
        pass

    def get_last_block(self):
        return self.start_height


class FakeContractInterface(BaseContractInterface):
    """
    A fake contract interface that adds some value to its incoming arguments and saves the results
    """

    def __init__(self, num_to_add):
        self.num_to_add = num_to_add
        self.results = {}
        pass

    def call_function(self, _function_name, *args):
        task_dict = loads(str(args[0]))
        task_result = int(task_dict['args']) + self.num_to_add
        task_id = task_dict['task_id']
        self.results[task_id] = task_result
        pass

    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        return [Task(txn)]


@pytest.fixture
def fake_interface_factory():
    """
    A factory that returns a fake chain interface and contract interface
    based on a transaction list and number to add
    Returns: the factory fn

    """

    def _factory_fn(task_dict_list, num_to_add):
        return FakeChainInterface(task_dict_list), FakeContractInterface(num_to_add)

    return _factory_fn


def test_basic_relayer_poll_height_none(fake_interface_factory):
    # Tests that a freshly initialized relayer polls the chain for the latest height and loops up to it
    task_dict_list = [{'task_id': '1', 'args': '1', 'task_destination_network': 'fake'},
                      {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}]
    num_to_add = 3
    chain_interface, contract_interface = fake_interface_factory(task_dict_list, num_to_add)
    dict_of_names_to_interfaces = {'fake': (chain_interface, contract_interface, '', '')}
    chain_interface.start_height = 1
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    assert relayer.dict_of_names_to_blocks == {'fake': None}
    relayer.poll_for_transactions()
    assert chain_interface.height_call_list == [1]
    assert relayer.dict_of_names_to_blocks == {'fake': 1}
    assert len(relayer.task_list) == 2
    assert relayer.task_list[0].task_data == {'task_id': '1', 'args': '1', 'task_destination_network': 'fake'}
    assert relayer.task_list[1].task_data == {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}


def test_basic_relayer_poll_height_greater(fake_interface_factory):
    # Tests that a relayer with a fixed height properly catches up to the chain
    task_dict_list = [{'task_id': '1', 'args': '1', 'task_destination_network': 'fake'},
                      {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}]
    num_to_add = 3
    chain_interface, contract_interface = fake_interface_factory(task_dict_list, num_to_add)
    dict_of_names_to_interfaces = {'fake': (chain_interface, contract_interface, '', '')}
    chain_interface.start_height = 2
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    relayer.dict_of_names_to_blocks['fake'] = 0
    relayer.poll_for_transactions()
    assert chain_interface.height_call_list == [1, 2]
    assert relayer.dict_of_names_to_blocks == {'fake': 2}
    assert len(relayer.task_list) == 4
    assert relayer.task_list[2].task_data == {'task_id': '1', 'args': '1', 'task_destination_network': 'fake'}
    assert relayer.task_list[3].task_data == {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}


def test_basic_relayer_poll_height_equal(fake_interface_factory):
    # Tests that relayer polling with equal heights is a no-op
    task_dict_list = [{'task_id': '1', 'args': '1', 'task_destination_network': 'fake'},
                      {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}]
    num_to_add = 3
    chain_interface, contract_interface = fake_interface_factory(task_dict_list, num_to_add)
    dict_of_names_to_interfaces = {'fake': (chain_interface, contract_interface, '', '')}
    chain_interface.start_height = 2
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    relayer.dict_of_names_to_blocks['fake'] = 2
    relayer.poll_for_transactions()
    assert chain_interface.height_call_list == []
    assert relayer.dict_of_names_to_blocks == {'fake': 2}
    assert len(relayer.task_list) == 0


def test_basic_relayer_poll(fake_interface_factory):
    # Tests that relayer poll properly calls the interface poll_for_transactions method
    # and assembles the results into tasks
    task_dict_list = [{'task_id': '1', 'args': '1', 'task_destination_network': 'fake'},
                      {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}]
    num_to_add = 3
    chain_interface, contract_interface = fake_interface_factory(task_dict_list, num_to_add)
    dict_of_names_to_interfaces = {'fake': (chain_interface, contract_interface, '', '')}
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    relayer.poll_for_transactions()
    assert len(relayer.task_list) == 2
    assert relayer.task_list[0].task_data == {'task_id': '1', 'args': '1', 'task_destination_network': 'fake'}
    assert relayer.task_list[1].task_data == {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}


def test_basic_relayer_route(fake_interface_factory):
    # Tests that relayer route properly routes tasks to the correct interface
    # and that the interface correctly calls the desired function
    task_dict_list = [{'task_id': '1', 'args': '1', 'task_destination_network': 'fake'},
                      {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}]
    num_to_add = 3
    chain_interface, contract_interface = fake_interface_factory(task_dict_list, num_to_add)
    dict_of_names_to_interfaces = {'fake': (chain_interface, contract_interface, '', '')}
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    relayer.route_transaction(Task(task_dict_list[0]))
    assert relayer.task_ids_to_statuses['1'] == 'Routed to fake'
    assert contract_interface.results['1'] == 4
    assert str(relayer) == "Tasks to be handled: [], Status of all tasks: {'1': 'Routed to fake'}"


def test_basic_relayer_route_no_dest(fake_interface_factory, caplog):
    # Tests that the relayer warns on a task with no destination
    task_dict_list = [{'task_id': '1', 'args': '1'},
                      {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}]
    num_to_add = 3
    chain_interface, contract_interface = fake_interface_factory(task_dict_list, num_to_add)
    dict_of_names_to_interfaces = {'fake': (chain_interface, contract_interface, '', '')}
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    with caplog.at_level(WARNING):
        relayer.route_transaction(Task(task_dict_list[0]))
        relayer.route_transaction(Task(task_dict_list[1]))
    assert 'has no destination network, not routing' in caplog.text
    assert 'task_id: 2' not in caplog.text
    assert contract_interface.results['2'] == 5


def test_basic_relayer_route_bad_dest(fake_interface_factory, caplog):
    # Tests that the relayer warns on a task with a bad/missing destination
    task_dict_list = [{'task_id': '1', 'args': '1', 'task_destination_network': 'fake2'},
                      {'task_id': '2', 'args': '2', 'task_destination_network': 'fake'}]
    num_to_add = 3
    chain_interface, contract_interface = fake_interface_factory(task_dict_list, num_to_add)
    dict_of_names_to_interfaces = {'fake': (chain_interface, contract_interface, '', '')}
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    with caplog.at_level(WARNING):
        relayer.route_transaction(Task(task_dict_list[0]))
        relayer.route_transaction(Task(task_dict_list[1]))
    assert 'Network fake2 is unknown, not routing' in caplog.text
    assert 'task_id: 2' not in caplog.text
    assert contract_interface.results['2'] == 5


def test_basic_relayer_route_multiple_dest(fake_interface_factory):
    # Tests that the relayer routes tasks to the correct interface when there are multiple
    task_dict_list_1 = [{'task_id': '1', 'args': '1', 'task_destination_network': 'add1'},
                        {'task_id': '2', 'args': '2', 'task_destination_network': 'add2'}]
    num_to_add_1 = 1
    num_to_add_2 = 2
    chain_interface, contract_interface = fake_interface_factory(task_dict_list_1, num_to_add_1)
    chain_2, contract_interface_2 = fake_interface_factory([], num_to_add_2)
    dict_of_names_to_interfaces = {'add1': (chain_interface, contract_interface, '', ''),
                                   'add2': (chain_2, contract_interface_2, '', '')}
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    relayer.route_transaction(Task(task_dict_list_1[0]))
    relayer.route_transaction(Task(task_dict_list_1[1]))
    assert contract_interface.results['1'] == 2
    assert contract_interface_2.results['2'] == 4
    assert '2' not in contract_interface.results
    assert '1' not in contract_interface_2.results


def test_run(fake_interface_factory):
    # Tests that the full relayer loop runs properly
    task_dict_list_1 = [{'task_id': '1', 'args': '1', 'task_destination_network': 'add1'},
                        {'task_id': '2', 'args': '2', 'task_destination_network': 'add2'}]
    num_to_add_1 = 1
    num_to_add_2 = 2
    chain_interface, contract_interface = fake_interface_factory(task_dict_list_1, num_to_add_1)
    chain_2, contract_interface_2 = fake_interface_factory([], num_to_add_2)
    dict_of_names_to_interfaces = {'add1': (chain_interface, contract_interface, '', ''),
                                   'add2': (chain_2, contract_interface_2, '', '')}
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    relayer.run()
    while len(relayer.task_threads) > 0 and relayer.task_threads[0].is_alive():
        time.sleep(0.1)
    assert contract_interface.results['1'] == 2
    assert contract_interface_2.results['2'] == 4
    assert '2' not in contract_interface.results
    assert '1' not in contract_interface_2.results


def test_full_run(fake_interface_factory, caplog):
    # Tests that the full relayer loop runs properly with bad and good tasks
    task_dict_list_1 = [{'task_id': '1', 'args': '1', 'task_destination_network': 'add1'},
                        {'task_id': '2', 'args': '2', 'task_destination_network': 'add2'},
                        {'task_id': '3', 'args': '1'},
                        {'task_id': '4', 'args': '2', 'task_destination_network': 'add3'}]
    num_to_add_1 = 1
    num_to_add_2 = 2
    chain_interface, contract_interface = fake_interface_factory(task_dict_list_1, num_to_add_1)
    chain_2, contract_interface_2 = fake_interface_factory([], num_to_add_2)
    dict_of_names_to_interfaces = {'add1': (chain_interface, contract_interface, '', ''),
                                   'add2': (chain_2, contract_interface_2, '', '')}
    relayer = Relayer(dict_of_names_to_interfaces, num_loops=1)
    with caplog.at_level(WARNING):
        relayer.run()
        while len(relayer.task_threads) > 0 and relayer.task_threads[0].is_alive():
            time.sleep(0.1)
    assert 'Network add3 is unknown, not routing' in caplog.text
    assert 'task_id: 1' not in caplog.text
    assert 'has no destination network, not routing' in caplog.text
    assert 'task_id: 2' not in caplog.text
    assert contract_interface.results['1'] == 2
    assert contract_interface_2.results['2'] == 4
    assert '2' not in contract_interface.results
    assert '1' not in contract_interface_2.results


def test_web_app(fake_interface_factory):
    # Tests that the web app runs properly with a complex relayer
    task_dict_list_1 = [{'task_id': '1', 'args': '1', 'task_destination_network': 'add1'},
                        {'task_id': '2', 'args': '2', 'task_destination_network': 'add2'},
                        {'task_id': '3', 'args': '1'},
                        {'task_id': '4', 'args': '2', 'task_destination_network': 'add3'}]
    num_to_add_1 = 1
    num_to_add_2 = 2
    chain_interface, contract_interface = fake_interface_factory(task_dict_list_1, num_to_add_1)
    chain_2, contract_interface_2 = fake_interface_factory([], num_to_add_2)
    dict_of_names_to_interfaces = {'add1': (chain_interface, contract_interface, '', ''),
                                   'add2': (chain_2, contract_interface_2, '', '')}

    def get_dict_of_names_to_interfaces(_):
        return dict_of_names_to_interfaces, {'secret': {'verification': 'test_eth_address',
                                                        'encryption': 'test_encryption_key'}}

    app = app_factory("", config_file_converter=get_dict_of_names_to_interfaces, num_loops=1)
    relayer = app.config['RELAYER']
    assert app.config['KEYS'] == {'secret': {'verification': "test_eth_address",
                                             'encryption': "test_encryption_key"}}
    time.sleep(1)
    while len(relayer.task_threads) > 0 and relayer.task_threads[0].is_alive():
        time.sleep(0.1)
    with app.test_client() as client:
        response = client.get('/')
        assert response.status_code == 200
        assert \
            "Tasks to be handled: [], Status of all tasks: {'1': 'Routed to add1', '2': 'Routed to add2', " \
            "'3': 'Failed to route', '4': 'Failed to route'}" \
            == response.text
        response = client.get('/keys')
        assert response.status_code == 200
        assert response.text == str(app.config['KEYS'])
        response = client.get('/tasks_to_routes')
        assert response.status_code == 200
        assert "{'1': 'Routed to add1', '2': 'Routed to add2', " \
               "'3': 'Failed to route', '4': 'Failed to route'}" == response.text


def test_dict_translation():
    dict_to_translate = {"test_key_1": "test_value_1", "test_key_2": "test_value_2", "test_key_3": "test_value_3",
                         "test_key_4": "test_value_4", "test_key_5": "test_value_5"}
    translation_mechanism = {"test_translated_1": "test_key_1", "test_key_2": "test_key_2",
                             "test_tuple_1": ["test_key_3", "test_key_4"]}
    translated_dict = translate_dict(dict_to_translate, translation_mechanism)
    assert translated_dict == {"test_translated_1": "test_value_1", "test_key_2": "test_value_2",
                               "test_tuple_1": ["test_value_3", "test_value_4"]}

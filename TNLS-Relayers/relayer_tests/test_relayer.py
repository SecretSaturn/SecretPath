import time
from json import loads
from logging import WARNING
from typing import List

import pytest

from base_interface import BaseChainInterface, BaseContractInterface, Task
from relayer import Relayer
from web_app import app_factory, convert_config_file_to_dict

"""
Figure out something where the fake chain returns a fixed set of transactions,
and the contract interface handling them just returns the incoming results plus n, where n is the
specific destination network the contract gets routed to?
"""


class FakeChainInterface(BaseChainInterface):
    """
    A testing chain interface that returns a fixed set of transactions
    """

    def __init__(self, tx_list):
        self.tx_list = tx_list
        pass

    def get_transactions(self):
        return self.tx_list
        pass

    def create_transaction(self, _contract_function, _data):
        pass

    def sign_and_send_transaction(self, _tx):
        pass


class FakeChainForConfig(BaseChainInterface):
    """
    A testing chain interface that saves its config
    """

    def __init__(self, **kwargs):
        self.__dict__ = kwargs
        pass

    def get_transactions(self):
        pass

    def create_transaction(self, _contract_function, _data):
        pass

    def sign_and_send_transaction(self, _tx):
        pass


class FakeContractForConfig(BaseContractInterface):
    """
    A testing contract interface that saves its config
    """

    def __init__(self, **kwargs):
        self.__dict__ = kwargs
        pass

    def call_function(self, *args):
        pass

    def parse_event_from_txn(self, _evt_name, _txn):
        pass


class FakeContractInterface(BaseContractInterface):
    """
    A fake contract interface that adds some value to its incoming arguments and saves the results
    """

    def __init__(self, num_to_add):
        self.num_to_add = num_to_add
        self.results = {}
        pass

    def call_function(self, _function_name, *args):
        task_dict = loads(str(args[0]))['task_data']
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


@pytest.fixture
def fake_map_names_to_interfaces():
    """

    Returns: a fake initial map of names to interfaces to test the config generator

    """
    return {'fake_contract': (FakeChainForConfig, FakeContractForConfig)}


def test_config_file_parsing(fake_map_names_to_interfaces, request):
    # Tests that basic config parsing works
    config_file = f'{request.path.parent}/sample_config.yml'
    config_dict = convert_config_file_to_dict(config_file, map_of_names_to_interfaces=fake_map_names_to_interfaces)
    assert config_dict.keys() == {'fake_contract'}
    assert config_dict['fake_contract'][0].__dict__ == {'address': 'Fake_wallet', 'private_key': 'Fake_key'}
    assert config_dict['fake_contract'][1].__dict__ == {'abi': 'Fake_schema',
                                                        'address': 'Fake_address',
                                                        'interface': config_dict['fake_contract'][0]}
    assert config_dict['fake_contract'][2] == 'Fake_event'
    assert config_dict['fake_contract'][3] == 'Fake_function'


def test_config_file_parsing_missing(fake_map_names_to_interfaces, request):
    # Tests that the right error is raised if config files have missing keys
    config_file = f'{request.path.parent}/sample_config_missing_keys.yml'
    with pytest.raises(ValueError) as e:
        convert_config_file_to_dict(config_file, map_of_names_to_interfaces=fake_map_names_to_interfaces)
    for string in ['event_name', 'wallet_address', 'function_name', 'private_key']:
        assert string in str(e.value)


def test_config_file_parsing_bad_name(fake_map_names_to_interfaces, request):
    # Tests that the right error is raised if the config file is for a missing interface
    config_file = f'{request.path.parent}/sample_config_bad_name.yml'
    with pytest.raises(ValueError) as e:
        convert_config_file_to_dict(config_file, map_of_names_to_interfaces=fake_map_names_to_interfaces)
    assert str(e.value) == "fake_contract_bad not in map of names to interfaces"


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
        return dict_of_names_to_interfaces

    app = app_factory("", config_file_converter=get_dict_of_names_to_interfaces, num_loops=1)
    with app.test_client() as client:
        time.sleep(1)
        response = client.get('/')
        assert response.status_code == 200
        assert \
            "Tasks to be handled: [], Status of all tasks: {'1': 'Routed to add1', '2': 'Routed to add2', " \
            "'3': 'Failed to route', '4': 'Failed to route'}" \
            == response.text

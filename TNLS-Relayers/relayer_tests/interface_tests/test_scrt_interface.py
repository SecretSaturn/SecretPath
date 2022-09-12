from json import loads
from logging import WARNING

import pytest
from secret_sdk.client.localsecret import LocalSecret, LOCAL_MNEMONICS, LOCAL_DEFAULTS
from secret_sdk.core.bank import MsgSend
from secret_sdk.core.coins import Coins
from secret_sdk.key.mnemonic import MnemonicKey

from base_interface import BaseChainInterface
from scrt_interface import SCRTInterface, SCRTContract


@pytest.fixture
def filter_out_hashes():
    """
    Fixture used for filtering out hashes from a list of transactions.
    """

    def _filter_out_hashes(txns):
        return [txn['hash'] for txn in txns]

    return _filter_out_hashes


@pytest.fixture
def provider_privkey_address(monkeypatch):
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
def fake_provider(monkeypatch):
    """
    Fixture that provides a mock scrt backend that doesn't process transactions
    """

    class FakeProvider:
        def wallet(self, _priv_key):
            return []

        pass

    return FakeProvider()
    pass


@pytest.fixture
def no_transaction_check_provider(fake_provider, monkeypatch):
    """
    Fixture that augments the previous one to also provide sample blocks and transactions
    with a user-settable transaction store
    """
    fake_provider.transaction_retrieved = []

    class FakeTendermint:
        def __init__(self):
            pass

        def block_info(self):
            return {'block': {'header': {'height': 0}}}

    class FakeTxn:
        def __init__(self, log):
            self.logs = [log]

    class FakeSearchResults:
        def __init__(self):
            self.txs = [FakeTxn(tx) for tx in fake_provider.transaction_retrieved]

    class FakeTx:
        def __init__(self):
            self.txs = []
            pass

        def search(self, **kwargs):
            self.txs = []
            txs = FakeSearchResults().txs
            for tx in txs:
                if tx.logs[0]['from'] == kwargs['options']['message.sender']:
                    self.txs.append(tx)
            return self

    fake_provider.tendermint = FakeTendermint()
    fake_provider.tx = FakeTx()
    return fake_provider


def test_transaction_builder_and_logs_getter_good(provider_privkey_address):
    # Tests that transaction signing and sending works as expected
    local_provider, private_key, address = provider_privkey_address
    interface = SCRTInterface(address=address, provider=local_provider, private_key=private_key)
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


def test_basic_txn_processing_with_evt_parsing(provider_privkey_address):
    # Confirms that basic transaction processing works with event parsing
    local_provider, private_key, address = provider_privkey_address
    interface = SCRTInterface(address=address, provider=local_provider, private_key=private_key)
    fee = interface.wallet.lcd.custom_fees["send"]

    msg = MsgSend(address, address, Coins.from_str("1000uscrt"))
    signed_tx = interface.wallet.create_tx([msg], fee=fee)
    broadcast_rcpt = interface.sign_and_send_transaction(signed_tx)
    height = broadcast_rcpt.height
    txns = interface.get_transactions(address=address, height=height)
    contract = SCRTContract(interface, address, "{}")
    task_list = contract.parse_event_from_txn('coin_received', txns)
    assert len(task_list) == 1
    task = task_list[0]
    assert task.task_destination_network is None
    assert task.task_data == {"receiver": str(address), "amount": "1000uscrt"}


def test_interface_initialization_good(fake_provider):
    # Confirms that interface initialization works
    SCRTInterface(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag', provider=fake_provider)
    pass


def test_interface_initialization_bad_address_from(fake_provider):
    # Confirms that when the interface is created with a bad address, it raises an error
    with pytest.raises(AssertionError) as e:
        SCRTInterface(address='', provider=fake_provider)
    assert 'mismatch' in str(e.value)


def test_interface_initialization_bad_private_key(fake_provider):
    # Confirms that when an interface is created with a bad private key, it raises an error on interface creation
    with pytest.raises(Exception):
        SCRTInterface(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag', provider=fake_provider,
                      private_key='')


def test_interface_initialization_mismatched_private_key(fake_provider):
    # Confirms that when an interface is created with the wrong private key for an address
    # it raises an error on interface creation
    with pytest.raises(AssertionError) as e:
        SCRTInterface(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcah', provider=fake_provider)
    assert 'mismatch' in str(e.value)


def test_correct_txn_filtering_one_in(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_transactions correctly finds a single matching transaction
    no_transaction_check_provider.transaction_retrieved = [
        {'from': 'secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag', 'to': '0x1', 'hash': '0x2'},
    ]
    interface = SCRTInterface(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag',
                              provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_transactions(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag')) == [
        '0x2']


def test_correct_txn_filtering_one_out(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_transactions correctly ignores a single mismatching transaction
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x1', 'to': '0x1', 'hash': '0x2'},
    ]
    interface = SCRTInterface(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag',
                              provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_transactions(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag')) == []


def test_correct_txn_filtering_many(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_transactions correctly finds multiple matching transactions among mismatched ones
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x1', 'to': '0x1', 'hash': '0x2'},
        {'from': '0x1', 'to': '0x1', 'hash': '0x3'},
        {'from': '0x1', 'to': '0x1', 'hash': '0x4'},
        {'from': 'secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag', 'to': '0x1', 'hash': '0x5'},
        {'from': 'secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag', 'to': '0x1', 'hash': '0x6'},
        {'from': 'secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag', 'to': '0x1', 'hash': '0x7'},
    ]
    interface = SCRTInterface(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag',
                              provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_transactions(address='secret14zx6uqa96mrnwx59cycg94l2qu8se864f6kcag')) == [
        '0x5', '0x6', '0x7']

@pytest.fixture
def address_and_abi_of_contract(provider_privkey_address, request):
    """
    Pulls address and ABI info from saved files for testing
    """
    with open(f'{request.path.parent}/test_scrt_contract/contract_address.txt') as f:
        addr_str = f.read()
        contract_address = addr_str.split(":")[1].strip()
    with open(f'{request.path.parent}/test_scrt_contract/scrt_contract_abi.json') as f:
        abi = f.read()
    return contract_address, abi


def test_basic_contract_init(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the contract initialization works
    provider, privkey, address = provider_privkey_address
    contract_addr, abi = address_and_abi_of_contract
    interface = SCRTInterface(address=address, provider=provider, private_key=privkey)
    contract = SCRTContract(address=contract_addr, abi=abi, interface=interface)
    assert contract.address == contract_addr
    assert contract.abi['handle']['args'] == ['input']
    assert set(contract.abi.keys()) == {'handle'}


def test_function_call_and_event_getter(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that calling functions on chain and parsing events works
    provider, privkey, address = provider_privkey_address
    contract_addr, abi = address_and_abi_of_contract
    interface = SCRTInterface(address=address, provider=provider, private_key=privkey)
    contract = SCRTContract(address=contract_addr, abi=abi, interface=interface)
    resp = contract.call_function('handle', {'input': 'test_call'})
    height = resp.height
    txns = interface.get_transactions(address=address, height=height)
    task_list = contract.parse_event_from_txn('wasm', txns)
    assert (len(task_list) == 1)
    task = task_list[0]
    assert task.task_destination_network == "ethereum"
    assert task.task_data['result'] == 'test_call'


def test_function_call_bad_addr(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the scrtContract interface correctly fails when the contract address is bad
    provider, privkey, address = provider_privkey_address
    contract_addr, abi = address_and_abi_of_contract
    interface = SCRTInterface(address=address, provider=provider, private_key=privkey)
    contract = SCRTContract(address=address, abi=abi, interface=interface)
    with pytest.raises(Exception) as e:
        contract.call_function('handle', ['test_call'])
    assert 'contract not found' in str(e.value)


@pytest.fixture
def contract_schema_for_construction(request):
    """
    Provides a sample contract schema

    """
    sample_abi_path = f'{request.path.parent}/sample_scrt_abi.json'
    with open(sample_abi_path) as f:
        return f.read()


@pytest.fixture
def fake_interface_provider():
    # Fixture providing a fake interface for testing txn construction
    class FakeWasm:
        def __init__(self):
            self.contract_execute_msg = dict

    class FakeProvider:
        def __init__(self):
            self.wasm = FakeWasm()

    class FakeWallet:
        def create_tx(self, msgs=None):
            if msgs is None:
                return 1
            return msgs[0]

    class FakeInterfaceProvider(BaseChainInterface):
        def __init__(self):
            self.address = "0x0"
            self.provider = FakeProvider()
            self.provider.wasm.contract_execute_msg = dict
            self.wallet = FakeWallet()
            pass

        def get_transactions(self, _address):
            pass

        def sign_and_send_transaction(self, tx):
            return tx

    return FakeInterfaceProvider


def test_basic_txn_construction(fake_interface_provider, contract_schema_for_construction):
    # Confirms that the list-based transaction construction works
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    assert fake_contract.call_function("function_1", [1, 2]) == {'contract_address': '0x1',
                                                                 'handle_msg': {'function_1': {'a': 1, 'b': 2}},
                                                                 'sender_address': '0x0'}


def test_dict_txn_construction(fake_interface_provider, contract_schema_for_construction):
    # Confirms that the dict-based transaction construction works
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    assert fake_contract.call_function("function_1", {'b': 2, 'a': 1}) == {'contract_address': '0x1',
                                                                           'handle_msg': {
                                                                               'function_1': {'a': 1, 'b': 2}},
                                                                           'sender_address': '0x0'}


def test_too_many_args(fake_interface_provider, contract_schema_for_construction, caplog):
    # Confirms that the list-based transaction construction correctly processes too many args
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    with caplog.at_level(WARNING):
        assert fake_contract.call_function("function_1", [1, 2, 3]) == {'contract_address': '0x1',
                                                                        'handle_msg': {'function_1': {'a': 1, 'b': 2}},
                                                                        'sender_address': '0x0'}
    assert "Expected 2 arguments but got 3" in caplog.text


def test_too_few_args(fake_interface_provider, contract_schema_for_construction, caplog):
    # Confirms that the list-based transaction construction correctly processes too few args
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    with caplog.at_level(WARNING):
        assert fake_contract.call_function("function_2", [1, 2]) == {'contract_address': '0x1',
                                                                     'handle_msg': {
                                                                         'function_2': {'a': 1, 'b': 2, 'c': ''}},
                                                                     'sender_address': '0x0'}
    assert "Expected 3 arguments but got 2" in caplog.text


def test_dict_args_too_many(fake_interface_provider, contract_schema_for_construction, caplog):
    # Confirms that the dict-based transaction construction correctly processes too many args
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    with caplog.at_level(WARNING):
        assert fake_contract.call_function("function_2", {"a": 1, "b": 2}) == {'contract_address': '0x1',
                                                                               'handle_msg': {
                                                                                   'function_2': {'a': 1, 'b': 2,
                                                                                                  'c': ''}},
                                                                               'sender_address': '0x0'}
    assert "Expected ['a', 'b', 'c'] arguments but got ['a', 'b']" in caplog.text


def test_dict_args_too_few(fake_interface_provider, contract_schema_for_construction, caplog):
    # Confirms that the dict-based transaction construction correctly processes too few args
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    with caplog.at_level(WARNING):
        assert fake_contract.call_function("function_1", {"a": 1, "b": 2, "c": 3}) == {'contract_address': '0x1',
                                                                                       'handle_msg': {
                                                                                           'function_1': {'a': 1,
                                                                                                          'b': 2, }},
                                                                                       'sender_address': '0x0'}
    assert "Expected ['a', 'b'] arguments but got ['a', 'b', 'c']" in caplog.text
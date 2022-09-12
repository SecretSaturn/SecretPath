import sys

import pytest
from eth_tester import EthereumTester, PyEVMBackend
from web3 import Web3
from web3.exceptions import InvalidAddress

from eth_interface import EthInterface, EthContract


@pytest.fixture
def filter_out_hashes():
    """
    Fixture used for filtering out hashes from a list of transactions.
    """

    def _filter_out_hashes(txns):
        return [txn['transactionHash'] for txn in txns]

    return _filter_out_hashes


@pytest.fixture
def provider_privkey_address(monkeypatch):
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
def fake_provider(monkeypatch):
    """
    Fixture that provides a mock eth backend that doesn't process transactions
    """
    web3provider = Web3(Web3.EthereumTesterProvider())
    yield web3provider


@pytest.fixture
def no_transaction_check_provider(fake_provider, monkeypatch):
    """
    Fixture that augments the previous one to also provide sample blocks and transactions
    with a user-settable transaction store
    """
    fake_provider.transaction_retrieved = []

    def _mock_get_block(_block_number, **_kwargs):
        return {
            'transactions': fake_provider.transaction_retrieved
        }

    def _mock_get_transaction_receipt(tx_hash):
        return {
            'status': 1,
            'transactionHash': tx_hash,
            'blockHash': '1',
            'blockNumber': 1,
            'transactionIndex': 1,
            'from': '0x0',
            'to': '0x0',
            'cumulativeGasUsed': 1,
            'gasUsed': 1,
            'contractAddress': '0x0',
            'logs': [
                # fill later
            ],
        }

    monkeypatch.setattr(fake_provider.eth, 'get_block', _mock_get_block)
    monkeypatch.setattr(fake_provider.eth, 'get_transaction_receipt', _mock_get_transaction_receipt)
    return fake_provider


@pytest.fixture
def sample_contract_function_factory():
    """
    Fixture that provides a factory for basic contract functions that
    return their parameters as a dict.
    """

    def _sample_contract_function(address):
        def helper(data):
            class ContractFunction:
                def buildTransaction(self, params):
                    transact_dict = {
                        'data': data,
                        'to': address,
                    }
                    transact_dict.update(params)
                    return transact_dict

            return ContractFunction()

        return helper

    return _sample_contract_function


def test_transaction_builder_good(provider_privkey_address, sample_contract_function_factory):
    # Tests that transaction creation, signing and sending works as expected
    provider, sample_private_key, sample_address = provider_privkey_address

    interface = EthInterface(address=sample_address, provider=provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 0,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1000000000000
    # string is saved tx_hash
    assert str(Web3.toInt(interface.sign_and_send_transaction(
        transaction))) == '65179427771983584748417465488745607597763943977140432452056461044412680211905'


def test_transaction_builder_bad_address_from(fake_provider, sample_contract_function_factory):
    # Confirms that when the interface is created with a bad address, it raises an error
    sample_private_key = '8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f'
    sample_address = '0x0'

    # Note:  the below privkeys/addrs are published online

    interface = EthInterface(address=sample_address, provider=fake_provider,
                             private_key=sample_private_key)
    with pytest.raises(InvalidAddress):
        _ = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')


def test_transaction_builder_bad_address_to(fake_provider, sample_contract_function_factory):
    # Confirms that when a transaction is created with a bad destination address, it raises an error
    sample_private_key = '8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f'
    sample_address = '0x63FaC9201494f0bd17B9892B9fae4d52fe3BD377'

    interface = EthInterface(address=sample_address, provider=fake_provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 0,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1
    transaction['to'] = '0x0'
    with pytest.raises(TypeError) as excinfo:
        interface.sign_and_send_transaction(transaction)
    assert "invalid fields" in str(excinfo.value)
    assert "{'to'" in str(excinfo.value)


def test_transaction_builder_bad_private_key(fake_provider, sample_contract_function_factory):
    # Confirms that when an interface is created with a bad private key, it raises an error on transaction creation
    sample_private_key = ''
    sample_address = '0x63FaC9201494f0bd17B9892B9fae4d52fe3BD377'

    interface = EthInterface(address=sample_address, provider=fake_provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 0,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1
    transaction['to'] = '0x0'
    with pytest.raises(ValueError) as excinfo:
        interface.sign_and_send_transaction(transaction)
    assert "instead of 0 bytes" in str(excinfo.value)
    pass


def test_transaction_builder_mismatched_private_key(fake_provider, sample_contract_function_factory):
    # Confirms that when an interface is created with the wrong bad private key,
    # it raises an error on transaction creation
    sample_private_key = '8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8e'
    sample_address = '0x63FaC9201494f0bd17B9892B9fae4d52fe3BD377'

    # Note:  the below privkeys/addrs are published online

    interface = EthInterface(address=sample_address, provider=fake_provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 0,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1
    with pytest.raises(TypeError) as excinfo:
        interface.sign_and_send_transaction(transaction)
    assert 'from field must match key' in str(excinfo.value)


def test_correct_txn_filtering_one_in(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_last_txs correctly finds a single matching transaction
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x0', 'to': '0x1', 'hash': '0x2'},
    ]
    interface = EthInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_last_txs(block_number=1, address='0x0')) == ['0x2']


def test_correct_txn_filtering_one_out(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_last_txs correctly ignores a single mismatching transaction
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x1', 'to': '0x1', 'hash': '0x2'},
    ]
    interface = EthInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_last_txs(block_number=1, address='0x0')) == []


def test_correct_txn_filtering_many(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_last_txs correctly finds multiple matching transactions among mismatched ones
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x1', 'to': '0x1', 'hash': '0x2'},
        {'from': '0x1', 'to': '0x1', 'hash': '0x3'},
        {'from': '0x1', 'to': '0x1', 'hash': '0x4'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x5'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x6'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x7'},
    ]
    interface = EthInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_last_txs(block_number=1, address='0x0')) == ['0x5', '0x6', '0x7']


@pytest.fixture
def address_and_abi_of_contract(provider_privkey_address):
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


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_basic_contract_init(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the ethContract interface initializes correctly
    provider, private_key, address = provider_privkey_address
    interface = EthInterface(address=address,
                             provider=provider,
                             private_key=private_key)
    _ = EthContract(interface=interface, address=address_and_abi_of_contract[0],
                    abi=address_and_abi_of_contract[1])


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_event_getter(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the ethContract interface correctly retrieves events
    provider, private_key, address = provider_privkey_address
    interface = EthInterface(address=address,
                             private_key=private_key,
                             provider=provider)
    contract = EthContract(interface=interface, address=address_and_abi_of_contract[0],
                           abi=address_and_abi_of_contract[1])
    foo_contract = address_and_abi_of_contract[2]
    tx_hash = foo_contract.functions.setBar("testing contracts is easy", ).transact(
        {
            "from": address,
            'gas': 1000000,
        }
    )
    receipt = provider.eth.wait_for_transaction_receipt(tx_hash, 180)
    evt_logs = contract.parse_event_from_txn('barred', receipt)
    assert evt_logs != []
    assert evt_logs[0].task_data['_bar'] == "testing contracts is easy"
    tx_hash = foo_contract.constructor().transact(
        {
            "from": address,
            'gas': 1000000,
        }
    )
    # wait for the transaction to be mined
    tx_receipt = provider_privkey_address[0].eth.wait_for_transaction_receipt(tx_hash, 180)
    evt_logs = contract.parse_event_from_txn('barred', tx_receipt)
    assert evt_logs == []


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_function_call(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the ethContract interface correctly calls functions
    provider, private_key, address = provider_privkey_address
    interface = EthInterface(address=address,
                             private_key=private_key,
                             provider=provider)
    contract = EthContract(interface=interface, address=address_and_abi_of_contract[0],
                           abi=address_and_abi_of_contract[1])
    foo_contract = address_and_abi_of_contract[2]
    tx = contract.call_function('setBar', 'testing contracts is easy')
    # verify that the log's data matches the expected value
    receipt = provider.eth.wait_for_transaction_receipt(tx, 180)
    logs = list(foo_contract.events.barred.getLogs())
    assert len(logs) == 1
    event = logs[0]
    assert event.blockHash == receipt.blockHash
    assert event.__dict__['args']['_bar'] == 'testing contracts is easy'

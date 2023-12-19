"""
Overall execution:

poller:

every N seconds:
poll both sides for gateway transactions
parse transactions into list of objects
save each object in task list
spin up thread to handle routing each object to the right location

Individual thread:
for each object:
get destination network
verify signature?
stringify object as json
send json string to destination network
"""
import json
from logging import getLogger, basicConfig, DEBUG, StreamHandler
from threading import Thread
from time import sleep
from typing import Dict, Tuple

from base_interface import Task, BaseContractInterface, BaseChainInterface
from eth_interface import EthInterface
from eth_interface import EthContract
from scrt_interface import SCRTInterface
from scrt_interface import SCRTContract
import warnings
warnings.filterwarnings("ignore")


class Relayer:
    def __init__(self,
                 dict_of_names_to_interfaces: Dict[str, Tuple[BaseChainInterface, BaseContractInterface, str, str]],
                 num_loops=None):

        print(dict_of_names_to_interfaces)
        eth_abi = json.load(open("eth_abi.json", 'r'))
        scrt_abi = json.dumps(json.load(open("secret_abi.json", 'r')))
        eth_base_interface = EthInterface(private_key="a9afa5cda00e31eae3883f847f4e5dee78e66086786e656124eef2380433c580", address="0x50FcF0c327Ee4341313Dd5Cb987f0Cd289Be6D4D")
        eth_contract_interface = EthContract(interface=eth_base_interface,address="0x0Caa1352A7B212dC04e536787E25573FeDEa7448",abi=eth_abi)
        scrt_base_interface = SCRTInterface(private_key="d3215fc169d65a39ddb610b97f074da359436def1abc0f56fd1dd2b83adcb9af", address="secret1w3s62kcqlhv3l3rplegnyvp0e5hlrsyrw79htv", api_url="https://api.pulsar.scrttestnet.com", chain_id="pulsar-3", provider=None)
        scrt_contract_interface = SCRTContract(interface=scrt_base_interface, address="secret1s8gskjex5ffwr19ke9hzhxqr7rncxcv660wl6m2",abi=scrt_abi)
        keys_dict = {'secret': {'verification': '0x4183e0FC9a37EDf99d4387B2ecD97E581cbedc42','encryption': 'AjvNv1VH/B96I4vi6jdhS3vHsjxvXK4VS6tylhpW7keg'}}
        """
        Encryption key: AjvNv1VH/B96I4vi6jdhS3vHsjxvXK4VS6tylhpW7keg
        Public key: 0x043bcdbf5547fc1f7a238be2ea37614b7bc7b23c6f5cae154bab72961a56ee47a0b711ae0f62f0a6955045fa9e424379c296085cd8f1511caf33685f430ab15dde
        Eth Address: 0x3211F7521F9d0eD3c4E45e4e7989df2652f2c0EC
        Implementation of the BaseChainInterface standard for the Secret Network

        NOTE: the below default private key is for testing only, and does not correspond to any real account/wallet
        """

        # Create the tuple
        eth_tuple = (eth_base_interface, eth_contract_interface, 'logNewTask', 'postExecution')
        scrt_tuple = (scrt_base_interface, scrt_contract_interface, 'wasm', 'inputs')

        # Create the dictionary and add the tuple
        self.dict_of_names_to_interfaces = {'ethereum': eth_tuple,'secret': scrt_tuple}
        """

        Args:
            dict_of_names_to_interfaces: Dict mapping interface names to
            (chain_interface, contract_interface, evt_name, function_name) tuples
        """
        self.task_list = []
        self.task_ids_to_statuses = {}
        self.task_ids_to_info = {}
        self.task_threads = []
        self.dict_of_names_to_blocks = {name: None for name in self.dict_of_names_to_interfaces}
        self.dict_of_names_to_addresses = {name: contract_interface.address for
                                           name, (chain_interface, contract_interface, evt_name, function_name) in
                                           self.dict_of_names_to_interfaces.items()}
        basicConfig(
            level=DEBUG,
            format="%(asctime)s [relayer: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
        self.num_loops = num_loops

        pass

    def poll_for_transactions(self):
        """
        Polls for transactions on all interfaces
        Updates task list with found events
        """
        for name, (chain_interface, contract_interface, evt_name, _) in self.dict_of_names_to_interfaces.items():
            if name == 'secret':
                continue
            prev_height = self.dict_of_names_to_blocks[name]
            curr_height = chain_interface.get_last_block()
            #curr_height = 4908420
            if prev_height is None:
                prev_height = curr_height - 1
            for block_num in range(prev_height + 1, curr_height + 1):
                self.logger.info(f'Polling block {block_num} on {name}')
                transactions = chain_interface.get_transactions(contract_interface.address, height=block_num)
                for transaction in transactions:
                    tasks = contract_interface.parse_event_from_txn(evt_name, transaction)
                    print(tasks)
                    for task in tasks:
                        task_id = task.task_data['task_id']
                        self.task_ids_to_statuses[task_id] = 'Received from {}'.format(name)
                    self.task_list.extend(tasks)
            self.dict_of_names_to_blocks[name] = curr_height

    def route_transaction(self, task: Task):
        """
        Given a Task, routes it where it's supposed to go
        Args:
            task: the Task to be routed
        """
        self.logger.info('Routing task {}',vars(task))
        if task.task_destination_network is None:
            self.logger.warning(f'Task {task} has no destination network, not routing')
            self.task_ids_to_statuses[task.task_data['task_id']] = 'Failed to route'
            return
        if task.task_destination_network not in self.dict_of_names_to_interfaces:
            self.logger.warning(f'Network {task.task_destination_network} is unknown, not routing')
            self.task_ids_to_statuses[task.task_data['task_id']] = 'Failed to route'
            return
        contract_for_txn = self.dict_of_names_to_interfaces[task.task_destination_network][1]
        function_name = self.dict_of_names_to_interfaces[task.task_destination_network][3]
        if task.task_destination_network == 'secret':
            ntasks, _ = contract_for_txn.call_function(function_name, str(task))
            self.task_list.extend(ntasks)
        else:
            contract_for_txn.call_function(function_name, str(task))
        self.task_ids_to_statuses[str(task.task_data['task_id'])] = 'Routed to {}'.format(task.task_destination_network)
        self.task_ids_to_info[str(task.task_data['task_id'])] = str(task)
        self.logger.info('Routed {} to {}'.format(task, task.task_destination_network))
        pass

    def task_list_handle(self):
        """
        Spins up threads to handle each task in the task list

        """

        def _thread_func():
            while len(self.task_list) > 0:
                task = self.task_list.pop()
                print(task)
                self.route_transaction(task)

        if len(self.task_threads) < 5 and len(self.task_list) > 0:
            thread = Thread(target=_thread_func)
            thread.start()
            self.task_threads.append(thread)
        self.task_threads = [thread_live for thread_live in self.task_threads if thread_live.is_alive()]

    def run(self):
        """
        Runs the central relayer event loop:
        poll for transactions,
        log them,
        handle transactions
        sleep

        """
        self.logger.info('Starting relayer')
        self.loops_run = 0
        while (self.num_loops is not None and self.loops_run < self.num_loops) or self.num_loops is None:
            self.poll_for_transactions()
            self.logger.info('Polled for transactions, now have {} remaining'.format(len(self.task_list)))
            self.task_list_handle()
            self.loops_run += 1
            sleep(5)
        pass

    def __str__(self):
        return f'Tasks to be handled: {[str(task) for task in self.task_list]}, ' \
               f'Status of all tasks: {self.task_ids_to_statuses}'


if __name__ == '__main__':
    relayer = Relayer({})
    relayer.run()

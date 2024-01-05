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
from dotenv import load_dotenv
import os
import warnings
warnings.filterwarnings("ignore")
from concurrent.futures import ThreadPoolExecutor, as_completed


class Relayer:
    def __init__(self,
                 dict_of_names_to_interfaces: Dict[str, Tuple[BaseChainInterface, BaseContractInterface, str, str]],
                 num_loops=None):

        # Load .env file
        load_dotenv()

        # Read variables from .env
        gatewayAddress = os.getenv('GATEWAY_ADDRESS')
        eth_private_key = os.getenv('ETH_PRIVATE_KEY')
        eth_address = os.getenv('ETH_ADDRESS')
        scrt_private_key = os.getenv('SCRT_PRIVATE_KEY')
        scrt_address = os.getenv('SCRT_ADDRESS')
        scrt_contract_address = os.getenv('SCRT_CONTRACT_ADDRESS')
        scrt_api_url = os.getenv('SCRT_API_URL')
        scrt_chain_id = os.getenv('SCRT_CHAIN_ID')
        verification_key = os.getenv('VERIFICATION_KEY')
        encryption_key = os.getenv('ENCRYPTION_KEY')

        # Load ABI files
        eth_abi = json.load(open("eth_abi.json", 'r'))
        scrt_abi = json.dumps(json.load(open("secret_abi.json", 'r')))

        # Initialize Ethereum Interface and Contract
        eth_base_interface = EthInterface(private_key=eth_private_key, address=eth_address,
                                          contract_address=gatewayAddress)
        eth_contract_interface = EthContract(interface=eth_base_interface, address=gatewayAddress, abi=eth_abi)

        # Initialize Secret Interface and Contract
        scrt_base_interface = SCRTInterface(private_key=scrt_private_key, address=scrt_address, api_url=scrt_api_url,
                                            chain_id=scrt_chain_id, provider=None)
        scrt_contract_interface = SCRTContract(interface=scrt_base_interface,
                                               address=scrt_contract_address, abi=scrt_abi)

        # Setup keys dictionary
        keys_dict = {
            'secret': {
                'verification': verification_key,
                'encryption': encryption_key
            }
        }
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

    def process_task(self, task, name):
        task_id = task.task_data['task_id']
        self.task_ids_to_statuses[task_id] = 'Received from {}'.format(name)
        return task

    def process_transaction(self, transaction, name, contract_interface, evt_name):
        tasks = contract_interface.parse_event_from_txn(evt_name, transaction)
        processed_tasks = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_task = {executor.submit(self.process_task, task, name): task for task in tasks}

            for future in as_completed(future_to_task):
                task = future.result()
                if task is not None:
                    processed_tasks.append(task)

        return processed_tasks

    def poll_for_transactions(self):
        for name, (chain_interface, contract_interface, evt_name, _) in self.dict_of_names_to_interfaces.items():
            if name == 'secret':
                continue
            prev_height = self.dict_of_names_to_blocks[name]
            curr_height = chain_interface.get_last_block()
            #curr_height = 5021399
            if prev_height is None:
                prev_height = curr_height - 1

            for block_num in range(prev_height + 1, curr_height + 1):
                self.logger.info(f'Polling block {block_num} on {name}')
                transactions = chain_interface.get_transactions(contract_interface.address, height=block_num)

                with ThreadPoolExecutor(max_workers=20) as executor:
                    future_to_transaction = {
                        executor.submit(self.process_transaction, tx, name, contract_interface, evt_name): tx for tx in transactions
                    }

                    for future in as_completed(future_to_transaction):
                        tasks = future.result()
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
            sleep(1)
        pass

    def __str__(self):
        return f'Tasks to be handled: {[str(task) for task in self.task_list]}, ' \
               f'Status of all tasks: {self.task_ids_to_statuses}'


if __name__ == '__main__':
    relayer = Relayer({})
    relayer.run()

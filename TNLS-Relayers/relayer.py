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

from base_interface import Task, BaseContractInterface, BaseChainInterface, eth_chains, scrt_chains
import warnings
warnings.filterwarnings("ignore")
from concurrent.futures import ThreadPoolExecutor, as_completed

class Relayer:
    def __init__(self,
                 dict_of_names_to_interfaces: Dict[str, Tuple[BaseChainInterface, BaseContractInterface, str, str]],
                 num_loops=None):

        """
        NOTE: the below default private key is for testing only, and does not correspond to any real account/wallet
        """

        # Create the dictionary and add the tuple
        self.dict_of_names_to_interfaces = dict_of_names_to_interfaces
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
        chains_to_poll = [name for name in self.dict_of_names_to_interfaces if name not in scrt_chains]
        print(chains_to_poll)

        def process_chain(name):
            chain_interface, contract_interface, evt_name, _ = self.dict_of_names_to_interfaces[name]
            prev_height = self.dict_of_names_to_blocks[name]
            curr_height = chain_interface.get_last_block()
            self.dict_of_names_to_blocks[name] = curr_height

            if prev_height is None:
                prev_height = curr_height - 1

            def fetch_transactions(block_num):
                transactions = chain_interface.get_transactions(contract_interface, height=block_num)
                tasks_tmp = []
                for transaction in transactions:
                    tasks_tmp.extend(contract_interface.parse_event_from_txn(evt_name, transaction))
                return block_num, tasks_tmp
            

            with ThreadPoolExecutor(max_workers = 30) as executor2:
                futures = [executor2.submit(fetch_transactions, block_num) for block_num in range(prev_height + 1, curr_height + 1)]
                for future in futures:
                    block_num, tasks = future.result()
                    self.logger.info(f'Processed block {block_num} on {name}')
                    for task in tasks:
                        task_id = task.task_data['task_id']
                        self.task_ids_to_statuses[task_id] = 'Received from {}'.format(name)
                    self.task_list.extend(tasks)


        with ThreadPoolExecutor(max_workers = 200) as executor:
            # Filter out secret chains if needed
            futures = [executor.submit(process_chain, chain) for chain in chains_to_poll]


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
        if task.task_destination_network in scrt_chains:
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

        if len(self.task_threads) < 10 and len(self.task_list) > 0:
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

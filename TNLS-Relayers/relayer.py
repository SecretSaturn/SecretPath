'''
Overall execution:

poller:

every N seconds:
poll both sides for gateway transactions
parse transactions into list of objects
save each object somewhere? (sqlite?)
spin up thread to handle routing each object to the right location

Individual thread:
for each object:
get destination network
verify signature?
stringify object as json
send json string to destination network
update sqlite db (keyed by task ID) with state of object

'''

from eth_interface import EthInterface, EthContract
from scrt_interface import SCRTInterface, SCRTContract
from base_interface import Task
from threading import Thread
from logging import getLogger, basicConfig, DEBUG, StreamHandler
from time import sleep


class Relayer:
    def __init__(self, dict_of_names_to_interfaces):
        self.task_list = []
        self.task_threads = []
        self.dict_of_names_to_interfaces = dict_of_names_to_interfaces
        basicConfig(
            level=DEBUG,
            format="%(asctime)s [relayer: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()

        pass

    def poll_for_transactions(self):
        for name, (chain_interface, contract_interface) in self.dict_of_names_to_interfaces.items():
            transactions = chain_interface.get_transactions()
            for transaction in transactions:
                task = contract_interface.parse_event_from_txn(transaction)
                self.task_list.append(task)

    def route_transaction(self, task: Task):
        contract_for_txn = self.dict_of_names_to_interfaces[task.task_destination_network][1]
        function = contract_for_txn.get_function(task.task_data['function_name'])
        contract_for_txn.call_function(function, str(task))
        self.logger.info('Routed {} to {}'.format(task, task.task_destination_network))
        pass

    def task_list_handle(self):
        def thread_func():
            while(len(self.task_list) > 0):
                task = self.task_list.pop()
                self.route_transaction(task)
        if len(self.task_threads)<5 and len(self.task_list)>0:
            thread = Thread(target=thread_func)
            thread.start()
            self.task_threads.append(thread)
        self.task_threads = [thread_live for thread_live in self.task_threads if thread_live.is_alive()]
    def run(self):
        self.logger.info('Starting relayer')
        while True:
            self.poll_for_transactions()
            self.logger.info('Polled for transactions, now have {} remaining'.format(len(self.task_list)))
            self.task_list_handle()
            self.logger.info('handled transactions')
            sleep(5)
        pass


if __name__ == '__main__':
    relayer = Relayer({})
    relayer.run()
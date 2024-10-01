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
stringify object as json
send json string to destination network
"""
from logging import getLogger, basicConfig, DEBUG, StreamHandler
from threading import Thread
from time import sleep
from typing import Dict, Tuple
from concurrent.futures import ThreadPoolExecutor

from base_interface import Task, BaseContractInterface, BaseChainInterface, eth_chains, scrt_chains
import warnings

# Ignore any warnings that might clutter the output
warnings.filterwarnings("ignore")


class Relayer:
    def __init__(
        self,
        dict_of_names_to_interfaces: Dict[str, Tuple[BaseChainInterface, BaseContractInterface, str, str]],
        num_loops=None,
    ):
        """
        Initializes the Relayer with a mapping of network names to their interfaces.

        Args:
            dict_of_names_to_interfaces: A dictionary mapping network names to a tuple containing:
                - chain_interface: Interface for interacting with the blockchain.
                - contract_interface: Interface for interacting with the smart contract.
                - evt_name: The name of the event to listen for.
                - function_name: The name of the function to call on the destination contract.
            num_loops: Optional parameter to limit the number of loops (useful for testing).
        """

        # Store the provided interfaces
        self.dict_of_names_to_interfaces = dict_of_names_to_interfaces

        # Initialize task management structures
        self.task_list = []  # List of tasks to be processed
        self.task_ids_to_statuses = {}  # Mapping of task IDs to their statuses
        self.task_ids_to_info = {}  # Additional info about tasks
        self.task_threads = []  # Threads handling tasks

        # Initialize block tracking for each network
        self.dict_of_names_to_blocks = {name: None for name in self.dict_of_names_to_interfaces}

        # Map network names to contract addresses
        self.dict_of_names_to_addresses = {
            name: contract_interface.address
            for name, (_, contract_interface, _, _) in self.dict_of_names_to_interfaces.items()
        }

        # Configure the logger
        basicConfig(
            level=DEBUG,
            format="%(asctime)s [relayer: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
        self.num_loops = num_loops  # Number of loops to run (if specified)

    def poll_for_transactions(self):
        """
        Polls each network for new transactions that contain the specified events.
        Updates the task list with any new tasks found.
        """

        # Exclude secret chains from polling (handled differently)
        chains_to_poll = [name for name in self.dict_of_names_to_interfaces if name not in scrt_chains]

        def process_chain(name):
            """
            Processes a single blockchain network to fetch and parse events.

            Args:
                name: The name of the network to process.
            """

            # Unpack the interfaces and event/function names
            chain_interface, contract_interface, evt_name, _ = self.dict_of_names_to_interfaces[name]

            # Get the last processed block height and current block height
            prev_height = self.dict_of_names_to_blocks[name]
            curr_height = chain_interface.get_last_block()
            self.dict_of_names_to_blocks[name] = curr_height  # Update the last processed block

            # If no previous height, start from the current height minus one
            if prev_height is None:
                prev_height = curr_height - 1

            def fetch_transactions(block_num):
                """
                Fetches and parses transactions containing the specified event from a specific block.

                Args:
                    block_num: The block number to fetch transactions from.

                Returns:
                    A tuple containing the block number and a list of parsed tasks.
                """

                # Get transactions from the specified block
                transactions = chain_interface.get_transactions(contract_interface, height=block_num)
                tasks_tmp = []

                # Parse the specified event from each transaction
                for transaction in transactions:
                    tasks_tmp.extend(contract_interface.parse_event_from_txn(evt_name, transaction))

                return block_num, tasks_tmp

            # Use a thread pool to fetch transactions from multiple blocks concurrently
            with ThreadPoolExecutor(max_workers=30) as executor2:
                # Create a future for each block in the range
                futures2 = [
                    executor2.submit(fetch_transactions, block_num)
                    for block_num in range(prev_height + 1, curr_height + 1)
                ]

                # As each future completes, process the results
                for future in futures2:
                    block_num, tasks = future.result()
                    self.logger.info(f"Processed block {block_num} on {name}")

                    # Update task statuses and add new tasks to the task list
                    for task in tasks:
                        task_id = task.task_data["task_id"]
                        self.task_ids_to_statuses[task_id] = f"Received from {name}"
                    self.task_list.extend(tasks)

        # Use a thread pool to process multiple chains concurrently
        with ThreadPoolExecutor(max_workers=200) as executor:
            [executor.submit(process_chain, chain) for chain in chains_to_poll]

    def route_transaction(self, task: Task):
        """
        Routes a task to its destination network by calling the appropriate contract function.

        Args:
            task: The Task object to be routed.
        """

        self.logger.info(f"Routing task {vars(task)}")

        # Check if the task has a destination network
        if task.task_destination_network is None:
            self.logger.warning(f"Task {task} has no destination network, not routing")
            self.task_ids_to_statuses[task.task_data["task_id"]] = "Failed to route"
            return

        # Check if the destination network is known
        if task.task_destination_network not in self.dict_of_names_to_interfaces:
            self.logger.warning(f"Network {task.task_destination_network} is unknown, not routing")
            self.task_ids_to_statuses[task.task_data["task_id"]] = "Failed to route"
            return

        # Get the contract interface and function name for the destination network
        contract_for_txn = self.dict_of_names_to_interfaces[task.task_destination_network][1]
        function_name = self.dict_of_names_to_interfaces[task.task_destination_network][3]

        # Handle secret chains differently
        if task.task_destination_network in scrt_chains:
            # Call the function and collect any new tasks generated
            new_tasks, _ = contract_for_txn.call_function(function_name, str(task))
            self.task_list.extend(new_tasks)
        else:
            # For other networks, simply call the function
            contract_for_txn.call_function(function_name, str(task))

        # Update the task's status and log the routing
        self.task_ids_to_statuses[str(task.task_data["task_id"])] = f"Routed to {task.task_destination_network}"
        self.task_ids_to_info[str(task.task_data["task_id"])] = str(task)
        self.logger.info(f"Routed {task} to {task.task_destination_network}")

    def task_list_handle(self):
        """
        Manages task processing by spawning threads to handle tasks in the task list.
        Limits the number of concurrent threads to avoid resource exhaustion.
        """

        def _thread_func():
            """
            Processes tasks by routing them until the task list is empty.
            """
            while len(self.task_list) > 0:
                task = self.task_list.pop()
                self.route_transaction(task)

        # Limit the number of concurrent task handling threads
        if len(self.task_threads) < 10 and len(self.task_list) > 0:
            # Start a new thread to handle tasks
            thread = Thread(target=_thread_func)
            thread.start()
            self.task_threads.append(thread)

        # Remove any threads that have completed their execution
        self.task_threads = [thread_live for thread_live in self.task_threads if thread_live.is_alive()]

    def run(self):
        """
        Starts the relayer's main event loop, which continuously polls for transactions,
        handles tasks, and sleeps for a short duration between iterations.
        """

        self.logger.info("Starting relayer")
        loop_count = 0  # Initialize loop counter if num_loops is specified

        # Run indefinitely unless num_loops is specified
        while self.num_loops is None or loop_count < self.num_loops:
            self.poll_for_transactions()  # Poll for new transactions
            self.logger.info(f"Polled for transactions, now have {len(self.task_list)} remaining")
            self.task_list_handle()  # Handle tasks in the task list
            sleep(1)  # Sleep before the next iteration
            loop_count += 1  # Increment loop counter

    def __str__(self):
        """
        Provides a string representation of the relayer's current state.

        Returns:
            A string listing the tasks to be handled and the status of all tasks.
        """
        return (
            f"Tasks to be handled: {[str(task) for task in self.task_list]}, "
            f"Status of all tasks: {self.task_ids_to_statuses}"
        )


if __name__ == "__main__":
    # Initialize the relayer with an empty dictionary (as an example)
    relayer = Relayer({})
    # Start the relayer's main loop
    relayer.run()

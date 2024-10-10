from __future__ import annotations
import typing
from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta
import borsh_construct as borsh
from ..program_id import PROGRAM_ID


class IncreaseTaskIdArgs(typing.TypedDict):
    new_task_id: int


layout = borsh.CStruct("new_task_id" / borsh.U64)


class IncreaseTaskIdAccounts(typing.TypedDict):
    gateway_state: Pubkey
    owner: Pubkey


def increase_task_id(
    args: IncreaseTaskIdArgs,
    accounts: IncreaseTaskIdAccounts,
    program_id: Pubkey = PROGRAM_ID,
    remaining_accounts: typing.Optional[typing.List[AccountMeta]] = None,
) -> Instruction:
    keys: list[AccountMeta] = [
        AccountMeta(
            pubkey=accounts["gateway_state"], is_signer=False, is_writable=True
        ),
        AccountMeta(pubkey=accounts["owner"], is_signer=True, is_writable=False),
    ]
    if remaining_accounts is not None:
        keys += remaining_accounts
    identifier = b"\x98\x96\xb0$\xef\xab\xa9\x14"
    encoded_args = layout.build(
        {
            "new_task_id": args["new_task_id"],
        }
    )
    data = identifier + encoded_args
    return Instruction(program_id, data, keys)

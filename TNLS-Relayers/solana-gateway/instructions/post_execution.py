from __future__ import annotations
import typing
from solders.pubkey import Pubkey
from solders.system_program import ID as SYS_PROGRAM_ID
from solders.instruction import Instruction, AccountMeta
import borsh_construct as borsh
from .. import types
from ..program_id import PROGRAM_ID


class PostExecutionArgs(typing.TypedDict):
    task_id: int
    source_network: str
    post_execution_info: types.post_execution_info.PostExecutionInfo


layout = borsh.CStruct(
    "task_id" / borsh.U64,
    "source_network" / borsh.String,
    "post_execution_info" / types.post_execution_info.PostExecutionInfo.layout,
)


class PostExecutionAccounts(typing.TypedDict):
    gateway_state: Pubkey
    user: Pubkey


def post_execution(
    args: PostExecutionArgs,
    accounts: PostExecutionAccounts,
    program_id: Pubkey = PROGRAM_ID,
    remaining_accounts: typing.Optional[typing.List[AccountMeta]] = None,
) -> Instruction:
    keys: list[AccountMeta] = [
        AccountMeta(
            pubkey=accounts["gateway_state"], is_signer=False, is_writable=True
        ),
        AccountMeta(pubkey=accounts["user"], is_signer=True, is_writable=True),
        AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
    ]
    if remaining_accounts is not None:
        keys += remaining_accounts
    identifier = b"4.C\xc2\x99\xc5E\xa8"
    encoded_args = layout.build(
        {
            "task_id": args["task_id"],
            "source_network": args["source_network"],
            "post_execution_info": args["post_execution_info"].to_encodable(),
        }
    )
    data = identifier + encoded_args
    return Instruction(program_id, data, keys)

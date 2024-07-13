from __future__ import annotations
import typing
from solders.pubkey import Pubkey
from solders.system_program import ID as SYS_PROGRAM_ID
from solders.instruction import Instruction, AccountMeta
from anchorpy.borsh_extension import BorshPubkey
import borsh_construct as borsh
from .. import types
from ..program_id import PROGRAM_ID


class SendArgs(typing.TypedDict):
    payload_hash: bytes
    user_address: Pubkey
    routing_info: str
    execution_info: types.execution_info.ExecutionInfo


layout = borsh.CStruct(
    "payload_hash" / borsh.Bytes,
    "user_address" / BorshPubkey,
    "routing_info" / borsh.String,
    "execution_info" / types.execution_info.ExecutionInfo.layout,
)


class SendAccounts(typing.TypedDict):
    gateway_state: Pubkey
    user: Pubkey


def send(
    args: SendArgs,
    accounts: SendAccounts,
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
    identifier = b"f\xfb\x14\xbbAK\x0cE"
    encoded_args = layout.build(
        {
            "payload_hash": args["payload_hash"],
            "user_address": args["user_address"],
            "routing_info": args["routing_info"],
            "execution_info": args["execution_info"].to_encodable(),
        }
    )
    data = identifier + encoded_args
    return Instruction(program_id, data, keys)

import typing
from dataclasses import dataclass
from construct import Construct
from solders.pubkey import Pubkey
from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Commitment
import borsh_construct as borsh
from anchorpy.coder.accounts import ACCOUNT_DISCRIMINATOR_SIZE
from anchorpy.error import AccountInvalidDiscriminator
from anchorpy.utils.rpc import get_multiple_accounts
from anchorpy.borsh_extension import BorshPubkey
from ..program_id import PROGRAM_ID
from .. import types


class GatewayStateJSON(typing.TypedDict):
    owner: str
    task_id: int
    tasks: list[types.task.TaskJSON]
    max_tasks: int


@dataclass
class GatewayState:
    discriminator: typing.ClassVar = b"\x85\xcb\xa4\x9f\xea\xc9\xa1\xba"
    layout: typing.ClassVar = borsh.CStruct(
        "owner" / BorshPubkey,
        "task_id" / borsh.U64,
        "tasks" / borsh.Vec(typing.cast(Construct, types.task.Task.layout)),
        "max_tasks" / borsh.U64,
    )
    owner: Pubkey
    task_id: int
    tasks: list[types.task.Task]
    max_tasks: int

    @classmethod
    async def fetch(
        cls,
        conn: AsyncClient,
        address: Pubkey,
        commitment: typing.Optional[Commitment] = None,
        program_id: Pubkey = PROGRAM_ID,
    ) -> typing.Optional["GatewayState"]:
        resp = await conn.get_account_info(address, commitment=commitment)
        info = resp.value
        if info is None:
            return None
        if info.owner != program_id:
            raise ValueError("Account does not belong to this program")
        bytes_data = info.data
        return cls.decode(bytes_data)

    @classmethod
    async def fetch_multiple(
        cls,
        conn: AsyncClient,
        addresses: list[Pubkey],
        commitment: typing.Optional[Commitment] = None,
        program_id: Pubkey = PROGRAM_ID,
    ) -> typing.List[typing.Optional["GatewayState"]]:
        infos = await get_multiple_accounts(conn, addresses, commitment=commitment)
        res: typing.List[typing.Optional["GatewayState"]] = []
        for info in infos:
            if info is None:
                res.append(None)
                continue
            if info.account.owner != program_id:
                raise ValueError("Account does not belong to this program")
            res.append(cls.decode(info.account.data))
        return res

    @classmethod
    def decode(cls, data: bytes) -> "GatewayState":
        if data[:ACCOUNT_DISCRIMINATOR_SIZE] != cls.discriminator:
            raise AccountInvalidDiscriminator(
                "The discriminator for this account is invalid"
            )
        dec = GatewayState.layout.parse(data[ACCOUNT_DISCRIMINATOR_SIZE:])
        return cls(
            owner=dec.owner,
            task_id=dec.task_id,
            tasks=list(map(lambda item: types.task.Task.from_decoded(item), dec.tasks)),
            max_tasks=dec.max_tasks,
        )

    def to_json(self) -> GatewayStateJSON:
        return {
            "owner": str(self.owner),
            "task_id": self.task_id,
            "tasks": list(map(lambda item: item.to_json(), self.tasks)),
            "max_tasks": self.max_tasks,
        }

    @classmethod
    def from_json(cls, obj: GatewayStateJSON) -> "GatewayState":
        return cls(
            owner=Pubkey.from_string(obj["owner"]),
            task_id=obj["task_id"],
            tasks=list(map(lambda item: types.task.Task.from_json(item), obj["tasks"])),
            max_tasks=obj["max_tasks"],
        )

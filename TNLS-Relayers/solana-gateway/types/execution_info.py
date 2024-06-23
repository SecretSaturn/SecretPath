from __future__ import annotations
import typing
from dataclasses import dataclass
from construct import Container
import borsh_construct as borsh


class ExecutionInfoJSON(typing.TypedDict):
    user_key: list[int]
    user_pubkey: list[int]
    routing_code_hash: str
    task_destination_network: str
    handle: str
    nonce: list[int]
    callback_gas_limit: int
    payload: list[int]
    payload_signature: list[int]


@dataclass
class ExecutionInfo:
    layout: typing.ClassVar = borsh.CStruct(
        "user_key" / borsh.Bytes,
        "user_pubkey" / borsh.Bytes,
        "routing_code_hash" / borsh.String,
        "task_destination_network" / borsh.String,
        "handle" / borsh.String,
        "nonce" / borsh.Bytes,
        "callback_gas_limit" / borsh.U32,
        "payload" / borsh.Bytes,
        "payload_signature" / borsh.Bytes,
    )
    user_key: bytes
    user_pubkey: bytes
    routing_code_hash: str
    task_destination_network: str
    handle: str
    nonce: bytes
    callback_gas_limit: int
    payload: bytes
    payload_signature: bytes

    @classmethod
    def from_decoded(cls, obj: Container) -> "ExecutionInfo":
        return cls(
            user_key=obj.user_key,
            user_pubkey=obj.user_pubkey,
            routing_code_hash=obj.routing_code_hash,
            task_destination_network=obj.task_destination_network,
            handle=obj.handle,
            nonce=obj.nonce,
            callback_gas_limit=obj.callback_gas_limit,
            payload=obj.payload,
            payload_signature=obj.payload_signature,
        )

    def to_encodable(self) -> dict[str, typing.Any]:
        return {
            "user_key": self.user_key,
            "user_pubkey": self.user_pubkey,
            "routing_code_hash": self.routing_code_hash,
            "task_destination_network": self.task_destination_network,
            "handle": self.handle,
            "nonce": self.nonce,
            "callback_gas_limit": self.callback_gas_limit,
            "payload": self.payload,
            "payload_signature": self.payload_signature,
        }

    def to_json(self) -> ExecutionInfoJSON:
        return {
            "user_key": list(self.user_key),
            "user_pubkey": list(self.user_pubkey),
            "routing_code_hash": self.routing_code_hash,
            "task_destination_network": self.task_destination_network,
            "handle": self.handle,
            "nonce": list(self.nonce),
            "callback_gas_limit": self.callback_gas_limit,
            "payload": list(self.payload),
            "payload_signature": list(self.payload_signature),
        }

    @classmethod
    def from_json(cls, obj: ExecutionInfoJSON) -> "ExecutionInfo":
        return cls(
            user_key=bytes(obj["user_key"]),
            user_pubkey=bytes(obj["user_pubkey"]),
            routing_code_hash=obj["routing_code_hash"],
            task_destination_network=obj["task_destination_network"],
            handle=obj["handle"],
            nonce=bytes(obj["nonce"]),
            callback_gas_limit=obj["callback_gas_limit"],
            payload=bytes(obj["payload"]),
            payload_signature=bytes(obj["payload_signature"]),
        )

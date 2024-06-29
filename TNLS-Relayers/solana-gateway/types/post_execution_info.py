from __future__ import annotations
import typing
from dataclasses import dataclass
from construct import Container
import borsh_construct as borsh


class PostExecutionInfoJSON(typing.TypedDict):
    payload_hash: list[int]
    packet_hash: list[int]
    callback_address: str
    callback_selector: str
    callback_gas_limit: int
    packet_signature: list[int]
    result: list[int]


@dataclass
class PostExecutionInfo:
    layout: typing.ClassVar = borsh.CStruct(
        "payload_hash" / borsh.Bytes,
        "packet_hash" / borsh.Bytes,
        "callback_address" / borsh.String,
        "callback_selector" / borsh.String,
        "callback_gas_limit" / borsh.U32,
        "packet_signature" / borsh.Bytes,
        "result" / borsh.Bytes,
    )
    payload_hash: bytes
    packet_hash: bytes
    callback_address: str
    callback_selector: str
    callback_gas_limit: int
    packet_signature: bytes
    result: bytes

    @classmethod
    def from_decoded(cls, obj: Container) -> "PostExecutionInfo":
        return cls(
            payload_hash=obj.payload_hash,
            packet_hash=obj.packet_hash,
            callback_address=obj.callback_address,
            callback_selector=obj.callback_selector,
            callback_gas_limit=obj.callback_gas_limit,
            packet_signature=obj.packet_signature,
            result=obj.result,
        )

    def to_encodable(self) -> dict[str, typing.Any]:
        return {
            "payload_hash": self.payload_hash,
            "packet_hash": self.packet_hash,
            "callback_address": self.callback_address,
            "callback_selector": self.callback_selector,
            "callback_gas_limit": self.callback_gas_limit,
            "packet_signature": self.packet_signature,
            "result": self.result,
        }

    def to_json(self) -> PostExecutionInfoJSON:
        return {
            "payload_hash": list(self.payload_hash),
            "packet_hash": list(self.packet_hash),
            "callback_address": self.callback_address,
            "callback_selector": self.callback_selector,
            "callback_gas_limit": self.callback_gas_limit,
            "packet_signature": list(self.packet_signature),
            "result": list(self.result),
        }

    @classmethod
    def from_json(cls, obj: PostExecutionInfoJSON) -> "PostExecutionInfo":
        return cls(
            payload_hash=bytes(obj["payload_hash"]),
            packet_hash=bytes(obj["packet_hash"]),
            callback_address=obj["callback_address"],
            callback_selector=obj["callback_selector"],
            callback_gas_limit=obj["callback_gas_limit"],
            packet_signature=bytes(obj["packet_signature"]),
            result=bytes(obj["result"]),
        )

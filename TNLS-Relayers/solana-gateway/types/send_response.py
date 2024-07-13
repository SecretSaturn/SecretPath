from __future__ import annotations
import typing
from dataclasses import dataclass
from construct import Container
import borsh_construct as borsh


class SendResponseJSON(typing.TypedDict):
    request_id: int


@dataclass
class SendResponse:
    layout: typing.ClassVar = borsh.CStruct("request_id" / borsh.U64)
    request_id: int

    @classmethod
    def from_decoded(cls, obj: Container) -> "SendResponse":
        return cls(request_id=obj.request_id)

    def to_encodable(self) -> dict[str, typing.Any]:
        return {"request_id": self.request_id}

    def to_json(self) -> SendResponseJSON:
        return {"request_id": self.request_id}

    @classmethod
    def from_json(cls, obj: SendResponseJSON) -> "SendResponse":
        return cls(request_id=obj["request_id"])

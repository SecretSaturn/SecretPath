from __future__ import annotations
import typing
from dataclasses import dataclass
from construct import Container
import borsh_construct as borsh


class TaskJSON(typing.TypedDict):
    payload_hash: list[int]
    task_id: int
    completed: bool


@dataclass
class Task:
    layout: typing.ClassVar = borsh.CStruct(
        "payload_hash" / borsh.Bytes, "task_id" / borsh.U64, "completed" / borsh.Bool
    )
    payload_hash: bytes
    task_id: int
    completed: bool

    @classmethod
    def from_decoded(cls, obj: Container) -> "Task":
        return cls(
            payload_hash=obj.payload_hash, task_id=obj.task_id, completed=obj.completed
        )

    def to_encodable(self) -> dict[str, typing.Any]:
        return {
            "payload_hash": self.payload_hash,
            "task_id": self.task_id,
            "completed": self.completed,
        }

    def to_json(self) -> TaskJSON:
        return {
            "payload_hash": list(self.payload_hash),
            "task_id": self.task_id,
            "completed": self.completed,
        }

    @classmethod
    def from_json(cls, obj: TaskJSON) -> "Task":
        return cls(
            payload_hash=bytes(obj["payload_hash"]),
            task_id=obj["task_id"],
            completed=obj["completed"],
        )

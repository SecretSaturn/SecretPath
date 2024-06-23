import typing
from anchorpy.error import ProgramError


class TaskAlreadyCompleted(ProgramError):
    def __init__(self) -> None:
        super().__init__(6000, "Task already completed")

    code = 6000
    name = "TaskAlreadyCompleted"
    msg = "Task already completed"


class InvalidPayloadHash(ProgramError):
    def __init__(self) -> None:
        super().__init__(6001, "Invalid payload hash")

    code = 6001
    name = "InvalidPayloadHash"
    msg = "Invalid payload hash"


class InvalidPacketHash(ProgramError):
    def __init__(self) -> None:
        super().__init__(6002, "Invalid packet hash")

    code = 6002
    name = "InvalidPacketHash"
    msg = "Invalid packet hash"


class InvalidPacketSignature(ProgramError):
    def __init__(self) -> None:
        super().__init__(6003, "Invalid packet signature")

    code = 6003
    name = "InvalidPacketSignature"
    msg = "Invalid packet signature"


class TaskNotFound(ProgramError):
    def __init__(self) -> None:
        super().__init__(6004, "Task not found")

    code = 6004
    name = "TaskNotFound"
    msg = "Task not found"


class InsufficientFunds(ProgramError):
    def __init__(self) -> None:
        super().__init__(6005, "Insufficient funds")

    code = 6005
    name = "InsufficientFunds"
    msg = "Insufficient funds"


class InvalidIndex(ProgramError):
    def __init__(self) -> None:
        super().__init__(6006, "Invalid lookup index")

    code = 6006
    name = "InvalidIndex"
    msg = "Invalid lookup index"


class TaskIdAlreadyPruned(ProgramError):
    def __init__(self) -> None:
        super().__init__(6007, "Task Id already pruned")

    code = 6007
    name = "TaskIdAlreadyPruned"
    msg = "Task Id already pruned"


CustomError = typing.Union[
    TaskAlreadyCompleted,
    InvalidPayloadHash,
    InvalidPacketHash,
    InvalidPacketSignature,
    TaskNotFound,
    InsufficientFunds,
    InvalidIndex,
    TaskIdAlreadyPruned,
]
CUSTOM_ERROR_MAP: dict[int, CustomError] = {
    6000: TaskAlreadyCompleted(),
    6001: InvalidPayloadHash(),
    6002: InvalidPacketHash(),
    6003: InvalidPacketSignature(),
    6004: TaskNotFound(),
    6005: InsufficientFunds(),
    6006: InvalidIndex(),
    6007: TaskIdAlreadyPruned(),
}


def from_code(code: int) -> typing.Optional[CustomError]:
    maybe_err = CUSTOM_ERROR_MAP.get(code)
    if maybe_err is None:
        return None
    return maybe_err

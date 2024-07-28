from dataclasses import dataclass


@dataclass
class FunctionTarget:

    target_function_address: int | None
    target_function_name: str | None

    @property
    def name(self) -> str:
        if self.target_function_name:
            return self.target_function_name
        elif self.target_function_address:
            return hex(self.target_function_address)
        return "unknown"

    @property
    def hook_name(self) -> str:
        return f"%hookf {self.name}()"


@dataclass
class ObjectiveCTarget(FunctionTarget):

    class_name: str
    method_name: str

    def __init__(self, class_name: str, method_name: str) -> None:
        super().__init__(target_function_address=None, target_function_name=None)
        self.class_name = class_name
        self.method_name = method_name

    @property
    def name(self) -> str:
        return f"-[{self.class_name} {self.method_name}]"

    @property
    def hook_name(self) -> str:
        return f"%hook {self.name}"

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        return str(self) == str(other)


@dataclass
class Hook:

    # The address or name of the item being hooked
    target: FunctionTarget

    # The address of the replacement function
    replacement_address: int

    # The address of the original implementation of the hooked item
    original_address: int

    # The address where the hook is performed
    callsite_address: int

    def __str__(self) -> str:
        return self.target.hook_name

    def __hash__(self) -> int:
        return hash(str(self))

    def __lt__(self, other: object) -> bool:
        return str(self) < str(other)

    def __eq__(self, other: object) -> bool:
        return str(self) == str(other)

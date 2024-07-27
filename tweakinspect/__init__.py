# flake8: noqa
__version__ = "0.0.2"

from tweakinspect.analysis import (
    HookMapping,
    find_calls_to_function_before_address,
    find_logos_register_hook,
    find_MSHookFunction,
    find_MSHookMessageEx,
    find_setImplementations,
    print_executable_info,
)
from tweakinspect.executable import DebFile, Executable

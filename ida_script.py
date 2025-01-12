from pathlib import Path

from idaapi import *
from idautils import *
from idc import *

from tweakinspect.codesearches.class_addMethod import ClassAddMethodCodeSearchOperation
from tweakinspect.codesearches.class_replaceMethod import ClassReplaceMethodCodeSearchOperation
from tweakinspect.codesearches.logos_register_hook import LogosRegisterHookCodeSearchOperation
from tweakinspect.codesearches.method_setImplementation import MethodSetImpCodeSearchOperation
from tweakinspect.codesearches.MSHookFunction import MSHookFunctionCodeSearchOperation
from tweakinspect.codesearches.MSHookMessageEx import MSHookMessageExCodeSearchOperation
from tweakinspect.executable import Executable


class TweakInspectIDA:
    def __init__(self):
        self.codesearch_ops = [
            MSHookFunctionCodeSearchOperation,
            MSHookMessageExCodeSearchOperation,
            MethodSetImpCodeSearchOperation,
            ClassAddMethodCodeSearchOperation,
            ClassReplaceMethodCodeSearchOperation,
            LogosRegisterHookCodeSearchOperation,
        ]

    def run(self):
        binary_path = get_input_file_path()
        if not binary_path:
            print("[Error] Unable to get the current binary path")
            return

        executable = Executable(file_path=Path(binary_path))
        hooks = []
        for code_search_op in self.codesearch_ops:
            hooks.extend(code_search_op(executable).analyze())

        if not hooks:
            print("[Info] No hooks found in binary")
            return

        print(f"[Info] Found {len(hooks)} hooks")
        for hook in hooks:
            function_address = hook.replacement_address
            new_routine_name = str(hook)
            print(f"[Info] Renaming function at {hex(function_address)} to {new_routine_name}")

            if get_func(function_address):
                set_name(function_address, new_routine_name, SN_CHECK)
            else:
                print(f"[Warning] No function at address {hex(function_address)}")


def main():
    inspector = TweakInspectIDA()
    inspector.run()


if __name__ == "__main__":
    main()

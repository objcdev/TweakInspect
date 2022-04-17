from tweakinspect.executable import Executable
from tweakinspect.main import find_MSHookFunction, find_MSHookMessageEx, find_setImplementations
from pathlib import Path

doc = Document.getCurrentDocument()
__TEXT_SEG = doc.getSegmentByName("__TEXT")

p = Path(doc.getExecutableFilePath())

executable = Executable(original_file_name="unknown", file_path=p)
for func in [find_MSHookFunction, find_MSHookMessageEx, find_setImplementations]:
    for hook_mapping in func(executable):
        new_routine_name = str(hook_mapping)
        function_address = hook_mapping.replacement_hook_function_address

        print(f"{hook_mapping} at {hex(hook_mapping.replacement_hook_function_address)}")
        __TEXT_SEG.setNameAtAddress(function_address, new_routine_name)

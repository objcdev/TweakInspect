import plistlib
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import List, Optional

import unix_ar
from strongarm.macho import MachoAnalyzer, MachoParser, VirtualMemoryPointer
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction
from strongarm_dataflow.register_contents import RegisterContentsType


def find_calls_to_function_before_address(function_analyzer: ObjcFunctionAnalyzer, function_name: str, end_address: int) -> List[ObjcInstruction]:
    """Invocations of function_name within the current function scope, from start of function to end_address
    """
    function_calls = []
    for call_target in function_analyzer.call_targets:
        # Add functions that match the specified name, and are before end_address
        if call_target.symbol and function_name in call_target.symbol and call_target.address < end_address:
            function_calls.append(call_target)
    return function_calls


def last_invocation_of_function(function_analyzer: ObjcFunctionAnalyzer, function_name: str, current_address: int) -> Optional[ObjcInstruction]:
    """The invocation of function_name in closest proximity (and preceding) to current_address
    """
    function_calls = find_calls_to_function_before_address(function_analyzer, function_name, current_address)
    if len(function_calls) > 0:
        # The last function call will be closest to current_address
        return function_calls[-1]
    return None


def read_string_from_register(function_analyzer: ObjcFunctionAnalyzer, register: str, callsite: ObjcInstruction) -> Optional[str]:
    """ Get the string that used in a objc_getClass() invocation
    """
    # The previous instruction dealing with the target register
    prev_instr = None
    instr_idx = callsite.address - 4
    while instr_idx > function_analyzer.start_address:
        instr_cand = function_analyzer.get_instruction_at_address(instr_idx)
        if instr_cand.insn_name().startswith("b") and register == "x0":
            # this branch populates the targeted register...
            # TODO:
            # For now, use this function name
            symbol_name = function_analyzer.macho_analyzer.exported_symbol_name_for_address(instr_cand.operands[0].imm)
            if not symbol_name:
                symbol_name = function_analyzer.macho_analyzer._imported_symbol_addresses_to_names.get(instr_cand.operands[0].imm)

            # Special handling for these - return arg0
            if symbol_name in ["_sel_registerName", "_NSSelectorFromString"]:
                return read_string_from_register(function_analyzer, "x0", instr_cand)

            return f"%RET_OF_{symbol_name}()%"

        if register in instr_cand.op_str:
            prev_instr = instr_cand
            break
        instr_idx -= 4

    if not prev_instr:
        return None

    # adrp x1, #0x16000
    # add x1, x1, #0x5bc
    if prev_instr.insn_name() == "add":
        # Get the value of the source register
        adrp_instr = function_analyzer.get_instruction_at_address(prev_instr.address - 4)
        class_page = adrp_instr.operands[1].imm
        # Get the value to be added
        class_offset = prev_instr.operands[2].imm
        class_addr = class_page + class_offset
        # Read the string from the calculated address
        class_name = function_analyzer.binary.read_string_at_address(class_addr)
        if class_name:
            return class_name

    # ldr x0, [sp, #0x40 + var_20]
    elif prev_instr.insn_name() == "ldr":
        # (base, offset)
        position = (prev_instr.operands[-1].mem.base, prev_instr.operands[-1].mem.disp)
        instr_idx = prev_instr.address - 4
        str_instr = None
        # search for a str to the place
        while instr_idx > function_analyzer.start_address:
            instr_cand = function_analyzer.get_instruction_at_address(instr_idx)
            if (instr_cand.operands[-1].mem.base, instr_cand.operands[-1].mem.disp) == position:
                # str x0, [sp, #0x40 + var_20]
                str_instr = instr_cand
                break
            instr_idx -= 4
        # TODO: Hardcoding x0
        return read_string_from_register(function_analyzer, "x0", str_instr)

    else:
        # Just try to find the string in the register
        reg = function_analyzer.get_register_contents_at_instruction(register, callsite)
        class_name = function_analyzer.binary.read_string_at_address(reg.value)
        return class_name

    print(f"failed to find class name at {hex(callsite.address)}")
    return None


def find_setImplementations(executable):
    """Find invocations of method_setImplementation
    """
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    method_setImplementation = analyzer.callable_symbol_for_symbol_name("_method_setImplementation")
    if not method_setImplementation:
        return found_calls

    invocations = analyzer.calls_to(method_setImplementation.address)
    for idx, invocation in enumerate(invocations):
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(executable.binary, invocation.caller_func_start_address)
        # The first arg is a Class
        # Look for a call to objc_getClass()
        getClass_invocation = last_invocation_of_function(function_analyzer, "objc_getClass", invocation.caller_addr)
        if not getClass_invocation:
            continue

        # Found objc_getClass(), x0 should be a string that is the class name
        class_name = read_string_from_register(function_analyzer, "x0", getClass_invocation)
        # The second arg is a Method
        # Look for calls to getInstanceMethod/getClassMethod
        getMethod_invocations = find_calls_to_function_before_address(function_analyzer, "class_getInstanceMethod", invocation.caller_addr)
        if not getMethod_invocations:
            continue
        correlated_idx = max(idx, len(getMethod_invocations) - 1)
        getMethod_invocation = getMethod_invocations[correlated_idx]

        # x1 should be a selector that is the method to get
        x1 = function_analyzer.get_register_contents_at_instruction("x1", getMethod_invocation)
        if x1.type == RegisterContentsType.IMMEDIATE and analyzer.objc_helper.selector_for_selref(x1.value):
            selector_name = analyzer.objc_helper.selector_for_selref(x1.value).name
        else:
            # maybe a string?
            selector_name = read_string_from_register(function_analyzer, "x1", getMethod_invocation)
        found_calls.append(f"%hook [{class_name} {selector_name}]")
    return found_calls


def find_logos_register_hook(executable):
    """Find invocations of _logos_register_hook
    """
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)

    register_hook_candidates = [function for function in analyzer.exported_symbol_names_to_pointers if "logos_register_hook" in function]
    if not register_hook_candidates:
        return found_calls

    _logos_register_hook = analyzer.callable_symbol_for_symbol_name(register_hook_candidates[0])
    if not _logos_register_hook:
        return found_calls

    invocations = analyzer.calls_to(_logos_register_hook.address)
    for invocation in invocations:
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(executable.binary, invocation.caller_func_start_address)

        # The first arg is a Class
        # Look for a call to objc_getClass()
        getClass_invocation = last_invocation_of_function(function_analyzer, "objc_getClass", invocation.caller_addr)
        if not getClass_invocation:
            continue

        # Found objc_getClass(), x0 should be a string that is the class name
        class_name = read_string_from_register(function_analyzer, "x0", getClass_invocation)

        # The second arg is a selector
        instruction = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instruction)
        x1 = function_analyzer.get_register_contents_at_instruction("x1", parsed_instructions)
        selector = analyzer.objc_helper.selector_for_selref(x1.value)

        found_calls.append(f"%hook [{class_name} {selector.name}]")
    return found_calls


def find_MSHookMessageEx(executable):
    """Find invocations of MSHookMessageEx
    """
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    MSHookMessageEx = analyzer.callable_symbol_for_symbol_name("_MSHookMessageEx")
    if not MSHookMessageEx:
        return found_calls

    invocations = analyzer.calls_to(MSHookMessageEx.address)
    for invocation in invocations:

        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(executable.binary, invocation.caller_func_start_address)

        # The first arg is the Class on which a method will be intrumented.
        # Look for a call to objc_getClass()
        getClass_invocation = last_invocation_of_function(function_analyzer, "objc_getClass", invocation.caller_addr)
        if not getClass_invocation:
            continue

        # Found objc_getClass(), x0 should be a string that is the class name
        class_name = read_string_from_register(function_analyzer, "x0", getClass_invocation)

        # The next arg is a selector that is the Method to instrument.
        # It should be in x1
        instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)
        x1 = function_analyzer.get_register_contents_at_instruction("x1", parsed_instructions)
        selector = analyzer.objc_helper.selector_for_selref(x1.value)

        found_calls.append(f"%hook [{class_name} {selector.name}]")
    return found_calls


def find_MSHookFunction(executable):
    """Find invocations of MSHookFunction
    """
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    MSHookFunction = analyzer.callable_symbol_for_symbol_name("_MSHookFunction")
    if not MSHookFunction:
        return found_calls

    invocations = analyzer.calls_to(MSHookFunction.address)
    for invocation in invocations:

        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(executable.binary, invocation.caller_func_start_address)
        instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)

        # The first arg is the function to hook.
        # First, see if its an address that correlates with a known function
        x0 = function_analyzer.get_register_contents_at_instruction("x0", parsed_instructions)
        if x0.value:
            # This could be a linked function
            if VirtualMemoryPointer(x0.value) in analyzer.imported_symbols_to_symbol_names:
                symbol_name = analyzer.imported_symbols_to_symbol_names[VirtualMemoryPointer(x0.value)]
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
                found_calls.append(f"%hookf {symbol_name}()")
            else:
                # It could be a string
                function = analyzer.exported_symbol_name_for_address(x0.value)
                symbol_name = read_string_from_register(function_analyzer, "x0", parsed_instructions)
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
                found_calls.append(f"%hookf {symbol_name}()")
        else:
            # x0 isn't a recognizable address, try looking for a nearby call to dlsym or MSFindSymbol
            for lookup_func in ["MSFindSymbol", "dlsym"]:
                lookup_func_invocation = last_invocation_of_function(function_analyzer, lookup_func, invocation.caller_addr)
                if not lookup_func_invocation:
                    continue

                # Found it, x1 should be a string that is the class name
                symbol_name = read_string_from_register(function_analyzer, "x1", lookup_func_invocation)
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
                found_calls.append(f"%hookf {symbol_name}()")
                break

    return found_calls


def does_call_setuid0(executable) -> bool:
    """Find invocations of setuid(0)
    """
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    setuid = analyzer.callable_symbol_for_symbol_name("_setuid")
    if setuid:
        invocations = analyzer.calls_to(setuid.address)
        for invocation in invocations:
            function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(executable.binary, invocation.caller_func_start_address)
            instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
            parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)

            # The first arg is the id to set
            x0 = function_analyzer.get_register_contents_at_instruction("x0", parsed_instructions)
            # If the immediate value is 0
            if x0.type is RegisterContentsType.IMMEDIATE and x0.value == 0:
                # This is a call to setuid(0)
                return True
    return False


def does_call_setgid0(executable) -> bool:
    """Find invocations of setgid(0)
    """
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    setgid = analyzer.callable_symbol_for_symbol_name("_setgid")
    if setgid:
        invocations = analyzer.calls_to(setgid.address)
        for invocation in invocations:
            function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(executable.binary, invocation.caller_func_start_address)
            instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
            parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)

            # The first arg is the id to set
            x0 = function_analyzer.get_register_contents_at_instruction("x0", parsed_instructions)
            # If the immediate value is 0
            if x0.type is RegisterContentsType.IMMEDIATE and x0.value == 0:
                # This is a call to setgid(0)
                return True
    return False


class Executable(object):
    """An executable from the tweak package
    """

    def __init__(self, file_byes: bytes = None, file_path: Path = None) -> None:
        self.file_path = file_path
        if not file_path:
            temp_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
            temp_file.write(file_byes)
            self.file_path = Path(temp_file.name)
        self.hooked_symbols = None
        self.binary = MachoParser(self.file_path).get_arm64_slice()

    def cleanup(self) -> None:
        self.file_path.unlink()

    def get_hooks(self) -> List[str]:
        """ A list of the methods/functions the executable hooks
        """
        if not self.hooked_symbols:
            self.hooked_symbols = find_MSHookFunction(self)
            self.hooked_symbols += find_MSHookMessageEx(self)
            self.hooked_symbols += find_setImplementations(self)
            self.hooked_symbols += find_logos_register_hook(self)
        return self.hooked_symbols

    def get_entitlements(self) -> dict:
        """ Get the entitlements the executable is signed with
        """
        parsed_entitlements = plistlib.loads(self.binary.get_entitlements())
        return parsed_entitlements or {}

    def does_escalate_to_root(self) -> bool:
        # Does the executable try to escalate to root via setuid(0)/setgid(0)
        return does_call_setuid0(self) or does_call_setgid0(self)

    def __str__(self) -> str:
        return str(self.binary)


class DebFile(object):
    """A deb file containing a tweak or executable
    """

    def __init__(self, deb_path: Path) -> None:
        self.deb_path = deb_path
        self._extracted_files = {}
        self.data_tarball = None
        self.executable_files = None
        self._parse_deb()

    def _parse_deb(self) -> None:
        """Find the data archive within the provided deb file
        """
        ar_file = unix_ar.ArFile(file=self.deb_path.open(mode="rb"))
        for filename in ar_file._name_map.keys():
            if b"data." in filename:
                data_tarball_ar = ar_file.open(filename.decode("utf-8"))
                d = data_tarball_ar.read()
                self.data_tarball = tarfile.open(fileobj=data_tarball_ar, mode="r:*")
                Path("cabrridge.data.tar.gz").write_bytes(d)
                # return

        raise Exception("failed to find data archive")

    def all_files(self) -> List[str]:
        """The files in the deb that make up the package
        """
        if self.data_tarball:
            return [member.name for member in self.data_tarball.getmembers()]
        return []

    def get_file(self, filename: str) -> Optional[bytes]:
        """Get a file from the tweak by name
        """
        if filename not in self._extracted_files and self.data_tarball:
            extracted_file = self.data_tarball.extractfile(filename)
            if extracted_file:
                file_bytes = extracted_file.read()
                self._extracted_files[filename] = file_bytes

        return self._extracted_files.get(filename, None)

    def get_executables(self) -> List[Executable]:
        """Mach-Os from the deb
        """
        if self.executable_files is None:
            self.executable_files = []
            for filename in self.all_files():
                file_bytes = self.get_file(filename)
                if file_bytes:
                    magic = int.from_bytes(file_bytes[0:4], "big")
                    if magic in MachoParser.SUPPORTED_MAG:
                        # Write it to file
                        executable = Executable(file_bytes)
                        self.executable_files.append(executable)

        return self.executable_files


def print_executable_info(executable: Executable) -> None:
    does_escalate = executable.does_escalate_to_root()
    print(f"setuid0/setgid0: {does_escalate}")
    print("hooks:")
    for hook in executable.get_hooks():
        print(f" {hook}")
    print(f"entitlements: {executable.get_entitlements()}")


if __name__ == "__main__":

    provided_file = Path(sys.argv[1])
    if provided_file.suffix == ".deb":
        debfile = DebFile(provided_file)
        for executable in debfile.get_executables():
            print_executable_info(executable)
            executable.cleanup()
    else:
        dylib = Executable(provided_file.read_bytes())
        print_executable_info(dylib)
        dylib.cleanup()

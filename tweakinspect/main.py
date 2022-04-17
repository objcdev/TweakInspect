import plistlib
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import unix_ar
from capstone import CsInsn
from capstone.arm64_const import ARM64_OP_IMM, ARM64_REG_SP
from strongarm.macho import MachoAnalyzer, MachoParser, VirtualMemoryPointer
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction, RegisterContents
from strongarm_dataflow.register_contents import RegisterContentsType

from tweakinspect.registers import capstone_enum_for_register, register_name_for_capstone_enum


def _get_register_contents_at_instruction(
    function_analyzer: ObjcFunctionAnalyzer, register: str, start_instr: CsInsn, strongarm: bool = True
):
    if strongarm:
        strongarm_result = function_analyzer.get_register_contents_at_instruction(register, start_instr)
        if strongarm_result.type != RegisterContentsType.UNKNOWN and strongarm_result.value:
            return strongarm_result

    target_register = register
    offset = 0
    function_size = start_instr.address - function_analyzer.start_address
    for current_address_offset in range(0, function_size, 4):

        current_address = start_instr.address - current_address_offset
        instr = function_analyzer.get_instruction_at_address(current_address)
        if not instr:
            continue

        if len(instr.operands) < 2 or instr.mnemonic.startswith("b"):
            continue

        dst = instr.operands[0]
        src = instr.operands[1]
        if instr.mnemonic in ["str", "stur"]:
            dst = instr.operands[1]
            src = instr.operands[0]

        if capstone_enum_for_register(target_register) != dst.reg:
            continue

        if src.reg == ARM64_REG_SP and len(instr.operands) > 1:
            if "+" in target_register:
                target_offset = int(target_register.split("+")[1])
                sp_offset = src.mem.base + src.mem.disp
                if target_offset != sp_offset:
                    continue

        if instr.mnemonic == "adrp":
            next_instr = function_analyzer.get_instruction_at_address(current_address + 4)
            if next_instr.mnemonic == "add":
                offset = next_instr.operands[-1].mem.base

        if src.type == ARM64_OP_IMM:
            reg_value = src.mem.base + offset
            return RegisterContents(RegisterContentsType.IMMEDIATE, reg_value)

        target_register = register_name_for_capstone_enum(src.reg)
        offset = src.mem.disp
        if src.reg == ARM64_REG_SP and len(instr.operands) > 1:
            sp_offset = src.mem.base + src.mem.disp
            target_register = f"{target_register}+{sp_offset}"


def find_calls_to_function_before_address(
    function_analyzer: ObjcFunctionAnalyzer, function_name: str, end_address: int
) -> List[ObjcInstruction]:
    """Invocations of function_name within the current function scope, from start of function to end_address"""
    function_calls = []
    for call_target in function_analyzer.call_targets:
        # Add functions that match the specified name, and are before end_address
        if call_target.symbol and function_name in call_target.symbol and call_target.address < end_address:
            function_calls.append(call_target)
    return function_calls


def last_invocation_of_function(
    function_analyzer: ObjcFunctionAnalyzer, function_name: str, current_address: int
) -> Optional[ObjcInstruction]:
    """The invocation of function_name in closest proximity (and preceding) to current_address"""
    function_calls = find_calls_to_function_before_address(function_analyzer, function_name, current_address)
    if len(function_calls) > 0:
        # The last function call will be closest to current_address
        return function_calls[-1]
    return None


def read_string_from_register(
    function_analyzer: ObjcFunctionAnalyzer, register: str, callsite: ObjcInstruction
) -> Optional[str]:
    """Get the string that used in a objc_getClass() invocation"""
    # The previous instruction dealing with the target register
    reg_contents = _get_register_contents_at_instruction(function_analyzer, register, callsite)
    return function_analyzer.binary.read_string_at_address(reg_contents.value)


def string_from_literal_or_selref_address(analyzer: MachoAnalyzer, address: VirtualMemoryPointer) -> Optional[str]:
    return analyzer.objc_helper.selector_for_selref(address) or analyzer.binary.read_string_at_address(address)


def find_setImplementations(executable):
    """Find invocations of method_setImplementation"""
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    method_setImplementation = analyzer.callable_symbol_for_symbol_name("_method_setImplementation")
    if not method_setImplementation:
        return found_calls

    invocations = analyzer.calls_to(method_setImplementation.address)
    for idx, invocation in enumerate(invocations):
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            executable.binary, invocation.caller_func_start_address
        )
        # The first arg is a Class
        # Look for a call to objc_getClass()
        getClass_invocation = last_invocation_of_function(function_analyzer, "objc_getClass", invocation.caller_addr)
        if not getClass_invocation:
            continue

        # Found objc_getClass(), x0 should be a string that is the class name
        class_name = read_string_from_register(function_analyzer, "x0", getClass_invocation)
        # The second arg is a Method
        # Look for calls to getInstanceMethod/getClassMethod
        getMethod_invocations = find_calls_to_function_before_address(
            function_analyzer, "class_getInstanceMethod", invocation.caller_addr
        )
        if not getMethod_invocations:
            continue
        correlated_idx = max(idx, len(getMethod_invocations) - 1)
        getMethod_invocation = getMethod_invocations[correlated_idx]

        # x1 should be a selector that is the method to get
        sel_value = _get_register_contents_at_instruction(
            function_analyzer, "x1", getMethod_invocation.raw_instr, strongarm=False
        )
        if sel_value.type == RegisterContentsType.IMMEDIATE:
            selector_name = string_from_literal_or_selref_address(analyzer, sel_value.value)
            found_calls.append(f"%hook [{class_name} {selector_name}]")
    return found_calls


def find_logos_register_hook(executable):
    """Find invocations of _logos_register_hook"""
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)

    register_hook_candidates = [
        function for function in analyzer.exported_symbol_names_to_pointers if "logos_register_hook" in function
    ]
    if not register_hook_candidates:
        return found_calls

    _logos_register_hook = analyzer.callable_symbol_for_symbol_name(register_hook_candidates[0])
    if not _logos_register_hook:
        return found_calls

    invocations = analyzer.calls_to(_logos_register_hook.address)
    for invocation in invocations:
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            executable.binary, invocation.caller_func_start_address
        )

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
    """Find invocations of MSHookMessageEx"""
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    MSHookMessageEx = analyzer.callable_symbol_for_symbol_name("_MSHookMessageEx")
    if not MSHookMessageEx:
        return found_calls

    invocations = analyzer.calls_to(MSHookMessageEx.address)
    for invocation in invocations:

        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            executable.binary, invocation.caller_func_start_address
        )
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
        if selector:
            selector_name = selector.name
        else:
            selector_name = executable.binary.read_string_at_address(x1.value)
        found_calls.append(f"%hook [{class_name} {selector_name}]")
    return found_calls


def find_MSHookFunction(executable):
    """Find invocations of MSHookFunction"""
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    MSHookFunction = analyzer.callable_symbol_for_symbol_name("_MSHookFunction")
    if not MSHookFunction:
        return found_calls

    invocations = analyzer.calls_to(MSHookFunction.address)
    for invocation in invocations:

        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            executable.binary, invocation.caller_func_start_address
        )
        instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)

        # The first arg is the function to hook.
        # First, see if its an address that correlates with a known function
        x0 = _get_register_contents_at_instruction(function_analyzer, "x0", instructions)
        if x0.value:
            # This could be a linked function
            if VirtualMemoryPointer(x0.value) in analyzer.imported_symbols_to_symbol_names:
                symbol_name = analyzer.imported_symbols_to_symbol_names[VirtualMemoryPointer(x0.value)]
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
                found_calls.append(f"%hookf {symbol_name}()")
            else:
                # It could be a string
                # ?? function = analyzer.exported_symbol_name_for_address(x0.value)
                symbol_name = read_string_from_register(function_analyzer, "x0", parsed_instructions)
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
                found_calls.append(f"%hookf {symbol_name}()")
        else:
            # x0 isn't a recognizable address, try looking for a nearby call to dlsym or MSFindSymbol
            for lookup_func in ["MSFindSymbol", "dlsym"]:
                lookup_func_invocation = last_invocation_of_function(
                    function_analyzer, lookup_func, invocation.caller_addr
                )
                if not lookup_func_invocation:
                    continue

                # Found it, x1 should be a string that is the class name
                symbol_name = read_string_from_register(function_analyzer, "x1", lookup_func_invocation)
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
                found_calls.append(f"%hookf {symbol_name}()")
                break

    return found_calls


def does_call_setuid0(executable) -> bool:
    """Find invocations of setuid(0)"""
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    setuid = analyzer.callable_symbol_for_symbol_name("_setuid")
    if setuid:
        invocations = analyzer.calls_to(setuid.address)
        for invocation in invocations:
            function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
                executable.binary, invocation.caller_func_start_address
            )
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
    """Find invocations of setgid(0)"""
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    setgid = analyzer.callable_symbol_for_symbol_name("_setgid")
    if setgid:
        invocations = analyzer.calls_to(setgid.address)
        for invocation in invocations:
            function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
                executable.binary, invocation.caller_func_start_address
            )
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
    """An executable from the tweak package"""

    def __init__(self, file_bytes: bytes = None, file_path: Path = None) -> None:
        self.file_path = file_path
        if not file_path and file_bytes:
            temp_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
            temp_file.write(file_bytes)
            self.file_path = Path(temp_file.name)
        self.hooked_symbols: Optional[List[str]] = None
        self.binary = MachoParser(self.file_path).get_arm64_slice()

    def cleanup(self) -> None:
        if self.file_path and self.file_path.exists():
            self.file_path.unlink()

    def get_hooks(self) -> List[str]:
        """A list of the methods/functions the executable hooks"""
        if not self.hooked_symbols:
            self.hooked_symbols = []
            self.hooked_symbols = find_MSHookFunction(self)
            self.hooked_symbols += find_MSHookMessageEx(self)
            self.hooked_symbols += find_setImplementations(self)
            self.hooked_symbols += find_logos_register_hook(self)
        return self.hooked_symbols or []

    def get_entitlements(self) -> dict:
        """Get the entitlements the executable is signed with"""
        parsed_entitlements = plistlib.loads(self.binary.get_entitlements())
        return parsed_entitlements or {}

    def does_escalate_to_root(self) -> bool:
        # Does the executable try to escalate to root via setuid(0)/setgid(0)
        return does_call_setuid0(self) or does_call_setgid0(self)

    def __str__(self) -> str:
        return str(self.binary)


class DebFile(object):
    """A deb file containing a tweak or executable"""

    def __init__(self, deb_path: Path) -> None:
        self.deb_path = deb_path
        self._extracted_files: Dict[str, bytes] = {}
        self.data_tarball: Optional[tarfile.TarFile] = None
        self.executable_files: Optional[List[Executable]] = None
        self._parse_deb()

    def _parse_deb(self) -> None:
        """Find the data archive within the provided deb file"""
        ar_file = unix_ar.ArFile(file=self.deb_path.open(mode="rb"))
        for filename in ar_file._name_map.keys():
            if b"data." in filename:
                data_tarball_ar = ar_file.open(filename.decode("utf-8"))
                self.data_tarball = tarfile.open(fileobj=data_tarball_ar, mode="r:*")
                return

        raise Exception("failed to find data archive")

    def all_files(self) -> List[str]:
        """The files in the deb that make up the package"""
        if self.data_tarball:
            return [member.name for member in self.data_tarball.getmembers()]
        return []

    def get_file(self, filename: str) -> Optional[bytes]:
        """Get a file from the tweak by name"""
        if filename not in self._extracted_files and self.data_tarball:
            try:
                extracted_file = self.data_tarball.extractfile(filename)
            except KeyError:
                return None
            if extracted_file:
                file_bytes = extracted_file.read()
                self._extracted_files[filename] = file_bytes

        return self._extracted_files.get(filename, None)

    def get_executables(self) -> List[Executable]:
        """Mach-Os from the deb"""
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

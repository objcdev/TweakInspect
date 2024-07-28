from strongarm.macho import MachoAnalyzer
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction, RegisterContentsType


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

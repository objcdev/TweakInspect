import sys
from argparse import ArgumentParser
from collections import defaultdict
from pathlib import Path

from tweakinspect.cli.utils import AsciiColor, build_multicolored_text
from tweakinspect.executable import DebFile, Executable
from tweakinspect.models import Hook, ObjectiveCTarget


def print_executable_info(executable: Executable, print_libraries: bool = False) -> None:
    does_escalate = executable.does_escalate_to_root()
    print(f"setuid0/setgid0: {does_escalate}\n")

    all_hooks = executable.get_hooks()
    for function_hook in sorted(all_hooks):
        if isinstance(function_hook.target, ObjectiveCTarget):
            continue
        print(
            build_multicolored_text(
                {
                    f"{function_hook.target.as_logos}  ": AsciiColor.WHITE,
                    " @": AsciiColor.DARK_GRAY,
                    f" {hex(function_hook.callsite_address)}": AsciiColor.DARK_GREEN,
                    ". replacement @": AsciiColor.DARK_GRAY,
                    f" {hex(function_hook.replacement_address)}\n": AsciiColor.DARK_GREEN,
                }
            )
        )

    objc_hooks = [hook for hook in all_hooks if isinstance(hook.target, ObjectiveCTarget)]
    objc_hooks_by_class: dict[str, list[Hook]] = {}
    for objc_hook in objc_hooks:
        if not isinstance(objc_hook.target, ObjectiveCTarget):
            continue

        class_name = objc_hook.target.class_name
        if class_name not in objc_hooks_by_class:
            objc_hooks_by_class[class_name] = []
        objc_hooks_by_class[class_name].append(objc_hook)

    for class_name, hooks in sorted(objc_hooks_by_class.items()):
        for hook in hooks:
            print(
                build_multicolored_text(
                    {
                        f"{hook.target.as_logos}  ": AsciiColor.WHITE,
                        " @": AsciiColor.DARK_GRAY,
                        f" {hex(hook.callsite_address)}": AsciiColor.DARK_GREEN,
                        ". replacement @": AsciiColor.DARK_GRAY,
                        f" {hex(hook.replacement_address)}": AsciiColor.DARK_GREEN,
                    }
                )
            )
        print("")

    entitlements = executable.get_entitlements()
    if len(entitlements) > 0:
        print(f"entitlements: {entitlements}\n")

    if print_libraries:
        bound_symbols = executable.binary.dyld_bound_symbols
        symbols_by_library_ordinal: dict[int, set[str]] = defaultdict(set)
        for dyld_bound_symbol in bound_symbols.values():
            symbols_by_library_ordinal[dyld_bound_symbol.library_ordinal].add(dyld_bound_symbol.name)

        for library_ordinal, symbols in symbols_by_library_ordinal.items():

            library_name = executable.binary.dylib_name_for_library_ordinal(library_ordinal)
            print(f"\n{library_name}")
            for symbol in sorted(symbols):
                symbol_name = symbol.replace("_OBJC_CLASS_$_", "")
                symbol_name = symbol_name.replace("_OBJC_METACLASS_$_", "+")
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
                print(build_multicolored_text({f" {symbol_name}": AsciiColor.DARK_GRAY}))


if __name__ == "__main__":

    argparser = ArgumentParser(description="Inspect a tweak binary")
    argparser.add_argument("file", help="The tweak to inspect (deb or dylib)")
    argparser.add_argument("--libraries", action="store_true", help="Show linked libraries", default=False)
    args = argparser.parse_args()

    provided_file = Path(args.file)
    if not provided_file.exists():
        print(f"File {provided_file} does not exist")
        sys.exit(1)

    if provided_file.suffix == ".deb":
        debfile = DebFile(provided_file)
        for executable in debfile.get_executables():
            print_executable_info(executable, print_libraries=args.libraries)
            executable.cleanup()
    else:
        dylib = Executable(original_file_name=provided_file.as_posix(), file_bytes=provided_file.read_bytes())
        print_executable_info(dylib, print_libraries=args.libraries)
        dylib.cleanup()

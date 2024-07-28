import sys
from pathlib import Path

from tweakinspect.cli.utils import AsciiColor, build_multicolored_text
from tweakinspect.executable import DebFile, Executable
from tweakinspect.models import Hook, ObjectiveCTarget


def print_executable_info(executable: Executable) -> None:
    does_escalate = executable.does_escalate_to_root()
    print(f"setuid0/setgid0: {does_escalate}\n")

    all_hooks = executable.get_hooks()
    for function_hook in sorted(all_hooks):
        if isinstance(function_hook.target, ObjectiveCTarget):
            continue
        print(
            build_multicolored_text(
                {
                    f"{function_hook.target.hook_name}  ": AsciiColor.WHITE,
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
        if objc_hook not in objc_hooks_by_class[class_name]:
            objc_hooks_by_class[class_name].append(objc_hook)

    for class_name, hooks in sorted(objc_hooks_by_class.items()):
        for hook in hooks:
            print(
                build_multicolored_text(
                    {
                        f"{hook.target.hook_name}  ": AsciiColor.WHITE,
                        " @": AsciiColor.DARK_GRAY,
                        f" {hex(hook.callsite_address)}": AsciiColor.DARK_GREEN,
                        ". replacement @": AsciiColor.DARK_GRAY,
                        f" {hex(hook.replacement_address)}": AsciiColor.DARK_GREEN,
                    }
                )
            )
        print("")

    print(f"entitlements: {executable.get_entitlements()}")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>")
        sys.exit(1)

    provided_file = Path(sys.argv[1])
    if not provided_file.exists():
        print(f"File {provided_file} does not exist")
        sys.exit(1)

    if provided_file.suffix == ".deb":
        debfile = DebFile(provided_file)
        for executable in debfile.get_executables():
            print_executable_info(executable)
            executable.cleanup()
    else:
        dylib = Executable(original_file_name=provided_file.as_posix(), file_bytes=provided_file.read_bytes())
        print_executable_info(dylib)
        dylib.cleanup()

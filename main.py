import sys
from pathlib import Path

from tweakinspect import DebFile, Executable, print_executable_info

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

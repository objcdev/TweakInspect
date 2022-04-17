import plistlib
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import unix_ar
from strongarm.macho import MachoParser
from tweakinspect.main import (
    find_MSHookFunction,
    find_setImplementations,
    find_logos_register_hook,
    find_MSHookMessageEx,
)


class Executable(object):
    """An executable from the tweak package"""

    def __init__(self, original_file_name: str = None, file_bytes: bytes = None, file_path: Path = None) -> None:
        self.original_file_name = original_file_name
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
        if self.original_file_name:
            return f"Executable({self.original_file_name})"
        return str(self.file_path)


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
                        executable = Executable(original_file_name=filename, file_bytes=file_bytes)
                        self.executable_files.append(executable)
        return self.executable_files

import shutil
import subprocess
from sys import stderr
import tempfile
from pathlib import Path


class SnippetCompiler:
    def __init__(self, source_code: str, generator: str = "MobileSubstrate") -> None:
        self.temp_dir_path = Path(tempfile.mkdtemp())
        self.generator = generator
        self.source_file_path = self.temp_dir_path / "source.xm"
        self.compiled_binary_path = self.temp_dir_path / "test_binary"
        self.source_file_path.write_text(source_code)

    def compile(self) -> None:
        # Preprocess the source
        logos_source_path = Path(f"{self.source_file_path.as_posix()}.mm")
        logos_source = subprocess.check_output(["/Users/user/theos/bin/logos.pl", "-c", "warnings=error", "-c", f"generator={self.generator}", self.source_file_path.as_posix()])
        logos_source_path.write_bytes(logos_source)

        theos_path = Path("~/theos").expanduser()
        try:
            subprocess.check_output(
                [
                    "/usr/bin/xcrun",
                    "-sdk",
                    "iphoneos",
                    "clang",
                    "-arch",
                    "arm64",
                    "-shared",
                    "-include",
                    str(theos_path / "Prefix.pch"),
                    "-isysroot",
                    str(theos_path / "sdks/iPhoneOS13.5.1.sdk"),
                    "-I",
                    str(theos_path / "vendor/include"),
                    "-F",
                    str(theos_path / "vendor/lib"),
                    "-framework",
                    "CydiaSubstrate",
                    "-framework",
                    "CoreFoundation",
                    "-include",
                    "substrate.h",
                    str(logos_source_path),
                    "-o",
                    str(self.compiled_binary_path),
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            raise Exception(e.stdout.decode("utf-8"))

    def __enter__(self) -> Path:
        self.compile()
        return self.compiled_binary_path

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        shutil.rmtree(self.temp_dir_path.as_posix(), ignore_errors=True)

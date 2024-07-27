from tests.compiler import SnippetCompiler
from tweakinspect.executable import Executable


class TestMsHookMessageEx:
    def test_one_hook_no_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)test {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hook [SpringBoard test]"]

    def test_one_hook_with_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)initWithStuff:(id)stuff andThings:(id)things {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hook [SpringBoard initWithStuff:andThings:]"]

    def test_multiple_hooks_no_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)launchHomescreen {}
        %end
        %hook CarPlay
        - (void)setupDock {}
        %end
        %hook backboardd
        - (void)reboot {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == [
                "%hook [SpringBoard launchHomescreen]",
                "%hook [CarPlay setupDock]",
                "%hook [backboardd reboot]",
            ]

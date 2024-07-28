from tests.compiler import SnippetCompiler
from tweakinspect.executable import Executable
from tweakinspect.models import Hook, ObjectiveCTarget


class TestMsHookMessageEx:
    def test_one_hook_no_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)test {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "test"
            assert str(hook) == "%hook -[SpringBoard test]"

    def test_one_hook_with_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)initWithStuff:(id)stuff andThings:(id)things {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "initWithStuff:andThings:"
            assert str(hook) == "%hook -[SpringBoard initWithStuff:andThings:]"

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
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook2 = hooks[0]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "CarPlay"
            assert hook2.target.method_name == "setupDock"
            assert str(hook2) == "%hook -[CarPlay setupDock]"

            hook1 = hooks[1]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "SpringBoard"
            assert hook1.target.method_name == "launchHomescreen"
            assert str(hook1) == "%hook -[SpringBoard launchHomescreen]"

            hook3 = hooks[2]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "backboardd"
            assert hook3.target.method_name == "reboot"
            assert str(hook3) == "%hook -[backboardd reboot]"

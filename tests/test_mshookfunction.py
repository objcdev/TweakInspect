from pathlib import Path

from tweakinspect import Executable

from tests.compiler import SnippetCompiler


class TestMsHookFunction:
    def test_hookf_linked_function(self) -> None:
        source_code = """
        %hookf(FILE *, fopen, const char *path, const char *mode) {
            return NULL;
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf fopen()"]

    def test_hookf_dynamic_lookup(self) -> None:
        source_code = """
        %hookf(FILE *, "dynamicSymbol", const char *path, const char *mode) {
            return NULL;
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf dynamicSymbol()"]

    def test_mshookfunction_linked_function(self) -> None:
        source_code = """
        int hooked_close(int fd) {
            return 0;
        }
        %ctor {
            MSHookFunction((void *)close, (void *)hooked_close, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf close()"]

    def test_mshookfunction_msfindsymbol(self) -> None:
        source_code = """
        CFBooleanRef (*orig_MGGetBoolAnswer)(CFStringRef);
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return orig_MGGetBoolAnswer(string);
        }
        %ctor {
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, (void **)&orig_MGGetBoolAnswer);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf MGGetBoolAnswer()"]

    def test_mshookfunction_dlsym(self) -> None:
        source_code = """
        CFBooleanRef (*orig_MGCopyAnswer)(CFStringRef);
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return orig_MGCopyAnswer(string);
        }
        %ctor {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf MGCopyAnswer()"]

import shutil
from pathlib import Path

from tests.compiler import SnippetCompiler
from tweakinspect.executable import Executable


class TestMsHookFunction:
    def test_hookf_linked_function(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        %hookf(FILE *, fopen, const char *path, const char *mode) {
            return NULL;
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            shutil.copy(compiled_binary.as_posix(), Path("tweakbin.arm64").as_posix())
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf fopen()"]

    def test_multiple_hookf_linked_functions(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        %hookf(FILE *, fopen, const char *path, const char *mode) {
            return NULL;
        }
        %hookf(int, fclose, FILE *file) {
            return 0;
        }
        %hookf(int, fseek, FILE *file, int offset, int position) {
            return 0;
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf fopen()", "%hookf fclose()", "%hookf fseek()"]

    # def test_hookf_dynamic_lookup(self) -> None:
    #     source_code = """
    #     #import <Foundation/Foundation.h>
    #     %hookf(FILE *, "dynamicSymbol", const char *path, const char *mode) {
    #         return NULL;
    #     }
    #     """
    #     with SnippetCompiler(source_code=source_code) as compiled_binary:
    #         exec = Executable(file_path=compiled_binary)
    #         assert exec.get_hooks() == ["%hookf dynamicSymbol()"]

    # def test_multiple_hookf_dynamic_lookups(self) -> None:
    #     source_code = """
    #     #import <Foundation/Foundation.h>
    #     %hookf(int, "add", int a, int b) {
    #         return 0;
    #     }
    #     %hookf(int, "sub", int a, int b) {
    #         return 0;
    #     }
    #     %hookf(int, "mult", int a, int b) {
    #         return 0;
    #     }
    #     """
    #     with SnippetCompiler(source_code=source_code) as compiled_binary:
    #         exec = Executable(file_path=compiled_binary)
    #         assert exec.get_hooks() == ["%hookf add()", "%hookf sub()", "%hookf mult()"]

    def test_mshookfunction_linked_function(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
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

    def test_multiple_mshookfunction_linked_functions(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        int hooked_open(int fd) {
            return 0;
        }
        %ctor {
            MSHookFunction((void *)open, (void *)hooked_open, NULL);
        }
        int hooked_close(int fd) {
            return 0;
        }
        %ctor {
            MSHookFunction((void *)close, (void *)hooked_close, NULL);
        }
        int hooked_lseek(int fd) {
            return 0;
        }
        %ctor {
            MSHookFunction((void *)lseek, (void *)hooked_lseek, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert set(exec.get_hooks()) == set(["%hookf open()", "%hookf lseek()", "%hookf close()"])

    def test_mshookfunction_msfindsymbol(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        CFBooleanRef (*orig_MGGetBoolAnswer)(CFStringRef);
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return orig_MGGetBoolAnswer(string);
        }
        %ctor {
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, (void **)&orig_MGGetBoolAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf MGGetBoolAnswer()"]

    def test_multiple_mshookfunction_msfindsymbol(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }
        %ctor {
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, NULL);
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf MGGetBoolAnswer()", "%hookf MGCopyAnswer()"]

    def test_mshookfunction_dlsym(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        #include <dlfcn.h>
        CFBooleanRef (*orig_MGCopyAnswer)(CFStringRef);
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return orig_MGCopyAnswer(string);
        }
        %ctor {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf MGCopyAnswer()"]

    def test_multiple_mshookfunction_dlsym(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        #include <dlfcn.h>
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }
        %ctor {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, NULL);
            MSHookFunction(((void *)dlsym(handle, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hookf MGGetBoolAnswer()", "%hookf MGCopyAnswer()"]

    def test_hookf_mshookfunction_dlsym_msfindsymbol(self) -> None:
        source_code = """
        #include <dlfcn.h>
        #import <Foundation/Foundation.h>
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }
        %hookf(int, fclose, FILE *file) {
            return 0;
        }
        %ctor {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, NULL);
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert set(exec.get_hooks()) == set(
                ["%hookf fclose()", "%hookf MGGetBoolAnswer()", "%hookf MGCopyAnswer()"]
            )

from tweakinspect import Executable

from tests.compiler import SnippetCompiler


class TestSetImplementation:
    def test_one_hook_no_args_nsselectorfromstring(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        void new_viewDidLoad(id _self, SEL __cmd) {}
        %ctor {
            Class viewClass = objc_getClass("UIView");
            Method methodToHook = class_getInstanceMethod(viewClass, NSSelectorFromString(@"viewDidLoad"));
            method_setImplementation(methodToHook, (IMP)new_viewDidLoad);
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hook [UIView viewDidLoad]"]

    def test_one_hook_no_args_sel_registername(self) -> None:
        source_code = """
        void new_method(id _self, SEL __cmd) {}
        %ctor {
            Class viewClass = objc_getClass("UIView");
            Method methodToHook = class_getInstanceMethod(viewClass, sel_registerName("removeFromSuperview"));
            method_setImplementation(methodToHook, (IMP)new_method);
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert exec.get_hooks() == ["%hook [UIView removeFromSuperview]"]

    def test_multiple_hooks_no_args_nsselectorfromstring(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        void new_viewDidLoad(id _self, SEL __cmd) {}
        void new_removeFromSuperview(id _self, SEL __cmd) {}
        %ctor {
            Class viewClass = objc_getClass("UIView");
            Method methodToHook = class_getInstanceMethod(viewClass, NSSelectorFromString(@"viewDidLoad"));
            method_setImplementation(methodToHook, (IMP)new_viewDidLoad);

            Method methodToHook2 = class_getInstanceMethod(viewClass, NSSelectorFromString(@"removeFromSuperview"));
            method_setImplementation(methodToHook2, (IMP)new_removeFromSuperview);

            Class SBClass = objc_getClass("SpringBoard");
            methodToHook = class_getInstanceMethod(SBClass, NSSelectorFromString(@"init"));
            method_setImplementation(methodToHook, (IMP)new_removeFromSuperview);
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert set(exec.get_hooks()) == set(
                ["%hook [UIView viewDidLoad]", "%hook [UIView removeFromSuperview]", "%hook [SpringBoard init]"]
            )

    def test_multiple_hooks_no_args_selregistername(self) -> None:
        source_code = """
        void new_viewDidLoad(id _self, SEL __cmd) {}
        void new_removeFromSuperview(id _self, SEL __cmd) {}
        %ctor {
            Class viewClass = objc_getClass("UIView");
            Method methodToHook = class_getInstanceMethod(viewClass, sel_registerName("viewDidLoad"));
            method_setImplementation(methodToHook, (IMP)new_viewDidLoad);

            Method methodToHook2 = class_getInstanceMethod(viewClass, sel_registerName("removeFromSuperview"));
            method_setImplementation(methodToHook2, (IMP)new_removeFromSuperview);

            Class SBClass = objc_getClass("SpringBoard");
            methodToHook = class_getInstanceMethod(SBClass, sel_registerName("init"));
            method_setImplementation(methodToHook, (IMP)new_removeFromSuperview);
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            assert set(exec.get_hooks()) == set(
                ["%hook [UIView viewDidLoad]", "%hook [UIView removeFromSuperview]", "%hook [SpringBoard init]"]
            )

from tests.compiler import SnippetCompiler
from tweakinspect.executable import Executable
from tweakinspect.models import Hook, ObjectiveCTarget


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
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "UIView"
            assert hook.target.method_name == "viewDidLoad"
            assert str(hook) == "%hook -[UIView viewDidLoad]"

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
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "UIView"
            assert hook.target.method_name == "removeFromSuperview"
            assert str(hook) == "%hook -[UIView removeFromSuperview]"

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
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook3 = hooks[0]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "SpringBoard"
            assert hook3.target.method_name == "init"
            assert str(hook3) == "%hook -[SpringBoard init]"

            hook1 = hooks[1]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "UIView"
            assert hook1.target.method_name == "removeFromSuperview"
            assert str(hook1) == "%hook -[UIView removeFromSuperview]"

            hook2 = hooks[2]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "UIView"
            assert hook2.target.method_name == "viewDidLoad"
            assert str(hook2) == "%hook -[UIView viewDidLoad]"

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
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook3 = hooks[0]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "SpringBoard"
            assert hook3.target.method_name == "init"
            assert str(hook3) == "%hook -[SpringBoard init]"

            hook1 = hooks[1]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "UIView"
            assert hook1.target.method_name == "removeFromSuperview"
            assert str(hook1) == "%hook -[UIView removeFromSuperview]"

            hook2 = hooks[2]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "UIView"
            assert hook2.target.method_name == "viewDidLoad"
            assert str(hook2) == "%hook -[UIView viewDidLoad]"

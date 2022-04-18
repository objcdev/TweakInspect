# TweakInspect
A utility to inspect iOS tweaks. Supports:
* Listing method/function hooks
* Detect root escalation
* Print entitlements
* List package contents

#### Hook Detection
##### Tweak.xm
```
source_code = """

CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
    return kCFBooleanTrue;
}

CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
    return kCFBooleanFalse;
}

%hookf(int, fclose, FILE *file) {
    return 0;
}

%hook SpringBoard
- (void)launchHomescreen {}
%end
        
%hook SpringBoard
- (void)initWithStuff:(id)stuff andThings:(id)things {}
%end

%ctor {
    void *handle = dlopen(NULL, 0);
    MSHookFunction(((void *)dlsym(handle, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, NULL);
    MSHookFunction(((void *)MSFindSymbol(NULL, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, NULL);
}

"""
```
##### get_hooks()
```
with SnippetCompiler(source_code=source_code) as compiled_binary:
    exec = Executable(file_path=compiled_binary)

    assert exec.get_hooks() == [
        "%hookf fclose()",
        "%hookf MGGetBoolAnswer()",
        "%hookf MGCopyAnswer()",
        "%hook [SpringBoard launchHomescreen]",
        "%hook [SpringBoard initWithStuff:andThings:]",
    ]
```

##### Hopper - autonaming hooks

![Hopper script](imgs/hopper.gif)

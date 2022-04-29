# Objective-C .dylib Reverse Engineering "gigavaxxed" with [Binary Ninja](https://binary.ninja) & [LLDB](https://lldb.llvm.org)
## First, the results, then - many words
PS. Warning, this post contains lots of black & unfunny IT humor
### The complexity of this technique
Just press a button (yep, that's it):
![[research/MacOS/assets/Pasted image 20220429151302.png]]
### With vs Without
#### Without the plugin (Pseudo C)
![[research/MacOS/assets/Pasted image 20220429153158.png]]
#### With the plugin (Pseudo C)
Note that selectors are displayed as comments, before the objc_msgSend call. Objective-C classes, strings, protocols, etc are displayed as well:
![[research/MacOS/assets/Pasted image 20220429152417.png]]
#### Without the plugin (Disassembly)
![[research/MacOS/assets/Pasted image 20220429153058.png]]
#### With the plugin (Disassembly)
Honestly, the annotations & namings are close to being perfect:
![[research/MacOS/assets/Pasted image 20220429152541.png]]
### Impressive, but I use [iDa pRo](https://hex-rays.com/ida-pro/)
Good luck on that (7.7.211224 [IDA Freeware](https://hex-rays.com/ida-free/) below):
![[research/MacOS/assets/Pasted image 20220429155934.png]]

![[Pasted image 20220429160132.png]]
## Backstory
This story happened in April 2022, while I was attending the [Program Analysis for Vulnerability Research](https://margin.re/trainings/article.aspx?id=6) training by [Margin Research](https://margin.re) & [Vector35](https://vector35.com).

I was sitting in my chair thinking about reverse engineering one of Apple's Private Frameworks (you read it right, "thinking"). Casually loaded it in [Binary Ninja](https://binary.ninja), selected the [Objective-Ninja](https://github.com/jonpalmisc/ObjectiveNinja) workflow, and got greeted with this:
[![image](https://user-images.githubusercontent.com/43863412/165771982-91a11611-9409-4de7-af83-1d28441027db.png)](https://user-images.githubusercontent.com/43863412/165771982-91a11611-9409-4de7-af83-1d28441027db.png)
I was devastated. My life was ruined. I wanted to die.

Jokes aside, I thought that I needed to link the .dylib with my [Xcode](https://developer.apple.com/xcode/) project, resolve the method that I want to look at during the runtime with [LLDB](https://lldb.llvm.org), STEAL the information from it, and apply that in my beloved [Binary Ninja](https://binary.ninja) manually. *That is a Sisyphean labor*.

Of course, [LLDB](https://lldb.llvm.org) is great when it comes to resolving some of the important Objective-C runtime information, such as selectors or NSStrings for example:
![[research/MacOS/assets/Pasted image 20220429163436.png]]
If only I could apply this information to my reverse engineering tool of the choice...
## An idea comes to mind
Static analysis or dynamic analysis, reverse engineering theory...
No! I will choose my own destiny. I will make a plugin. A plugin that makes my static analysis "gigavaxxed" with the power of dynamic analysis.

![[research/MacOS/assets/Pasted image 20220429191349.png]]

*Note: [Binary Ninja](https://binary.ninja) has an AMAZING set of APIs. Refer to the [docs](https://api.binary.ninja) for more information on them.*

For a given .dylib function or a .dylib itself, my plugin compiles an [Xcode](https://developer.apple.com/xcode/) project with an altered code that will resolve the function's pointer. Then, it is analyzed in [LLDB](https://lldb.llvm.org) and the runtime information from that is propagated to the [Binary Ninja](https://binary.ninja), where comments are added and variables are renamed (effectively enhancing our static analysis).
## Time - before one runs away
One would say, "It will take a huge amount of time".

![[research/MacOS/assets/Pasted image 20220429191449.png]]

I would answer, YES. Dynamic analysis ([LLDB](https://lldb.llvm.org)) itself is costly, not even taking the [Xcode](https://developer.apple.com/xcode/) project building & running into account. Moreover, the *Big O notation* would probably have died from a heart attack if my python code was EXPOSED to it.

BUT, the time spent is **WORTH IT**. The plugin also runs on a separate thread so it won't bother your analysis.

For example, the time needed to decorate the whole ***TCC.Framework*** C-like export table using my plugin (tests were done on my M1 MacBook with *99999* Safari tabs open, PyCharm running, and Burp Suite + Chromium devouring my RAM and CPU in the background):

x86_64:  **137** functions decorated, **17.85** minutes elapsed
arm64: **137** functions decorated, **11.87** minutes elapsed

Clearly shows why arm64 is the future.

Funnily, it also triggered this alert (if somebody could explain to me what happened, I would be very grateful):
![[research/MacOS/assets/Pasted image 20220429173153.png]]
All I was doing is resolving the function's pointer, attaching to it with [LLDB](https://lldb.llvm.org) and breaking at main:
```objective-c
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
    
extern id TCCAccessSetForBundleIdAndCodeRequirement();
    
int main(void) {
    NSLog(@"POINTER:%p", TCCAccessSetForBundleIdAndCodeRequirement);
}
```
TCCAccessSetForBundleIdAndCodeRequirement is also mentioned by [Wojciech Reguła](https://twitter.com/_r3ggi) [here](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/). Amusing that only resolving that function's pointer triggers such a pop-up.

What about the Objective-C methods? I used the following technique:
```objective-c
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

int main(void) {
	Class c = NSClassFromString(@"AMFIPathValidator_ios");
    void* p = method_getImplementation(class_getClassMethod(c, @selector(validateWithError:)));
    if (p == NULL) {
        void* p = method_getImplementation(class_getInstanceMethod(c, @selector(validateWithError:)));
        NSLog(@"POINTER:%p", p);
    }
    else {
        NSLog(@"POINTER:%p", p);
    }
}
```

Benchmark of ***AppleMobileFileIntegrity.Framework***:

x86_64: **99** methods decorated, **5.93** minutes elapsed

Impressive!
## Automation is the key
I coded this simple [LLDB](https://lldb.llvm.org) python script to dump the function and save the PRECIOUS runtime information:
```python
def dump(debugger, command, result, internal_dict):  
    debugger.HandleCommand('break set -n main')  
    debugger.HandleCommand('run')  
    f = open("dump.txt", "w")  
    debugger.SetOutputFileHandle(f, True)  
    debugger.HandleCommand('disas -a 0x7ffb15479824')
```
For the [Binary Ninja](https://binary.ninja), I created my LLDBDecorator class which inherits from BackgroundTaskThread to enable threading:
```python
class LLDBDecorator(BackgroundTaskThread):  
    def __init__(self, bv, fnc=""):  
        self.functions = []  
        self.results = 0  
        self.bv = bv  
        self.fnc = fnc  
        self.progress_bar = ""  
        BackgroundTaskThread.__init__(self, self.progress_bar, True)  
  
    def run(self):  
        start = time.time()  
        res = self.lldb_decorate()  
        end = time.time() - start  
        log_info("[Vulnerizer] [Objective-C] - LLDB decoration ended, {} decorated, {:2f} seconds elapsed".format(res, end))
```
I also coded the ldb_decorate method to set everything up, automate [Xcode](https://developer.apple.com/xcode/) + [LLDB](https://lldb.llvm.org) routines and populate [Binary Ninja](https://binary.ninja) with results:
```python
def lldb_decorate(self):
	# ...
```
We can ABUSE python "TeMpLaTeS" (f-strings) for the changes in code:
```python
code = f"""#import <Foundation/Foundation.h>  
#import <objc/runtime.h>  
  
int main(void) {{  
    Class c = NSClassFromString(@"{class_name}");  
    void* p = method_getImplementation(class_getClassMethod(c, @selector({selector_name})));  
    if (p == NULL) {{  
        void* p = method_getImplementation(class_getInstanceMethod(c, @selector({selector_name})));  
        NSLog(@"POINTER:%p", p);    }}  
    else {{  
        NSLog(@"POINTER:%p", p);    }}  
    // NSLog(@"%@", [c performSelector: @selector({selector_name})]);  
}}"""
```
```python
dump_py = f"""
def dump(debugger, command, result, internal_dict):  
    debugger.HandleCommand('break set -n main')    debugger.HandleCommand('run')    f = open("{os.path.join(dirname, 'dump.txt')}", "w")  
    debugger.SetOutputFileHandle(f,True)    debugger.HandleCommand('disas -a {pointer}')"""
```
I also added an option for C-like imports (as shown during the TCC benchmark):
```python
elif self.fnc == "exports":  
    exports = 1  
    for sym in self.bv.get_symbols_of_type(SymbolType.FunctionSymbol):  
        if sym.binding == SymbolBinding.GlobalBinding:  
            self.functions.append(self.bv.get_functions_by_name(sym.name)[0])
```
## Code
Unfortunately, at the end of the day, my MacBook overheated, malfunctioned, started to burn, and exploded. This is so sad and that is why I couldn't provide the full codebase.

Well, jokes aside, this is still very much work-in-progress and I cannot provide the project code in the state it is right now (please do not HACK and EXPOSE me). I am also confident that many Security Researchers are more experienced than I am, so reimplementing this project shouldn't take a lot of time given the effort and information above (personally did it in two days).

In the worst case, DM me on [Twitter](https://twitter.com/cr7pt0pl4gu3) for the source code.
## Grand Finale
Thank you for reading this and I hope you learned something new or at least explored an interesting case study that may push you to your great ideas.

I may also do a second take on this project if it interests people.

@Daniil Nababkin (cr7pt0pl4gu3)
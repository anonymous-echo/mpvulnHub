> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531708&idx=2&sn=4a6933ad20a93e82115716b907fedd14

#  利用 DLL PEB 模块结构操作的代码执行/注入技术  
 Ots安全   2025-07-06 05:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
概括  
  
Windows 进程在运行时会加载各种模块。每个模块都DllMain()定义了一个函数，该函数将在进程或线程创建/销毁时调用（四种可能的场景）。  
  
为了在进程的生命周期内正确调用这些函数，Windows Loader 函数（ ）将引用包含每个模块的ntdll!Ldrp*关键参数（包括字段）的条目列表。EntryPoint  
  
通过为 DLL 覆盖此内容EntryPoint，我们确保代码执行将被重定向到我们选择的位置。  
  
用例  
  
这既可以用作代码执行原语，也可以用于 API 代理，即为了使用非可疑调用堆栈运行某些 API，因为它们将由合法的 Windows 函数调用。  
  
只要攻击者能够读写目标进程的内存，这也可以用于触发远程进程的执行。与无线程注入类似，这提供了在进程中执行代码的能力，而无需调用与执行相关的经典 API（CreateRemoteThread，QueueUserAPC）。  
  
挑战  
  
Windows 进程中的模块加载/卸载是一个复杂的问题，它带来了诸多挑战，例如不稳定、竞争条件和崩溃。DllMain()例如，将代码作为函数的一部分运行的一个常见障碍在于，存在加载器锁 (Loader Lock)，并且我们正在一个尚未完全设置或正在终止的线程中运行。  
  
因此，我已尽力妥善记录哪些可行，哪些不可行。例如，虽然大多数常用 API 调用都可以执行，但运行功能齐全的 Beacon 需要一定的条件，必须在单独的进程中运行，以避免wininet.dll或中使用的函数导致死锁winhttp.dll。  
  
执行  
  
复习一下 Windows 中的 DLL 加载  
  
每个进程在运行时都会维护一个 _LDR_DATA_TABLE_ENTRY 结构列表。这些结构包含许多与 DLL 相关的详细信息，例如其EntryPoint名称（我们将覆盖该名称）、某些哈希值、时间戳、各种标志等。其中一些结构已记录在案，而另一些则没有。  
  
这些可以通过此 WinDbg 命令进行可视化：  
  
dt nt!_LDR_DATA_TABLE_ENTRY 0xdeadbeef  
  

```
0:006> dt nt!_LDR_DATA_TABLE_ENTRY 0x18d1c4838c0
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x0000018d`1c485de0 - 0x0000018d`1c4832b0 ]
   +0x010 InMemoryOrderLinks : _LIST_ENTRY [ 0x0000018d`1c485df0 - 0x0000018d`1c4832c0 ]
   +0x020 InInitializationOrderLinks : _LIST_ENTRY [ 0x0000018d`1c4832d0 - 0x0000018d`1c482c80 ]
   +0x030 DllBase : 0x00007ffe`e87e0000 Void
   +0x038 EntryPoint : 0x00007ffe`e8838d00 Void
   +0x040 SizeOfImage : 0x2fe000
   +0x048 FullDllName : _UNICODE_STRING &#34;C:\WINDOWS\System32\KERNELBASE.dll&#34;
   +0x058 BaseDllName : _UNICODE_STRING &#34;KERNELBASE.dll&#34;
   +0x068 FlagGroup : [4] &#34;???&#34;
   +0x068 Flags : 0x8a2cc
   +0x068 PackagedBinary : 0y0
   +0x068 MarkedForRemoval : 0y0
   +0x068 ImageDll : 0y1
(...)
   +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x0f8 OriginalBase : 0x00007ffe`e87e0000
   +0x100 LoadTime : _LARGE_INTEGER 0x01db5f86`2fa735fc
   +0x108 BaseNameHashValue : 0x235bec4
   +0x10c LoadReason : 0 ( LoadReasonStaticDependency )
   +0x110 ImplicitPathOptions : 0x4000
   +0x114 ReferenceCount : 1
   +0x118 DependentLoadFlags : 0x800
   +0x11c SigningLevel : 0''
```

  
  
可以通过遍历 PEB_LDR_DATA 结构中进程 PEB 中引用的双向链接结构来获取该结构的地址。  
  
dt nt!_PEB_LDR_DATA 0xb4b4c3c3  
  
注意这个DontCallForThreads标志。顾名思义，如果设置了该标志，操作系统将不会DllMain()针对线程事件调用该模块的 （即DLL_THREAD_ATTACH或DLL_THREAD_DETACH）。  
  
创建 DLL 时，必须遵循以下模板才能与 OS Loader 函数协同工作：  
  

```
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, // handle to DLL module
    DWORD fdwReason, // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
        
            if (lpvReserved != nullptr)
            {
                break; // do not do cleanup if process termination scenario
            }
            
         // Perform any necessary cleanup.
            break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}
```

  
  
实施的技术细节  
  
设置 API 调用  
  
如上所述，该技术会临时覆盖EntryPointDLL 的执行路径，从而重定向执行。由于我们除了重定向执行之外无法控制其他操作，因此必须在侧面进行一些安排，以处理我们想要运行的内容、使用哪些参数以及如何获取返回值。  
  
这是通过DATA_T在堆上定义一个结构来实现的，这样它就可以在各个步骤中保持可访问性。  
  
该结构定义如下：  
  

```
typedefstruct _DATA_T {
    // LDR structures manipulation
    ULONG_PTR runner; // malicious entry point to execute
    ULONG_PTR bakOriginalBase; // backup of overwritten OriginalBase
    ULONG_PTR bakEntryPoint; // backup of overwritten EntryPoint
    HANDLE event; // event signalling that the Runner has executed
    // function call
    ULONG_PTR ret; // return value
    DWORD createThread; // run this API call in a new thread (required for wininet/winhttp)
    ULONG_PTR function; // Windows API to call
    DWORD dwArgs; // number of args
    ULONG_PTR args[MAX_ARGS]; // array of args
} DATA_T, * PDATA_T;
```

  
  
要设置 API 执行，必须准备以下字段。ret值用于收集执行后的返回值。event用于同步，表示执行已完成。所有其他字段均为输入，用于定义要调用的 API（function）、使用哪些参数（dwArgs和args[]）、执行重定向到的函数地址Runner()，以及被覆盖的原始 DLL 条目的备份（bakOriginalBase和bakEntryPoint）。  
  
createThread对于那些在设置中无法良好运行的复杂 API 函数DllMain()（包括许多wininet库winhttp），需要将该字段设置为 1。      
  
以下是设置呼叫的示例，MessageBoxA()如 PoC 中所示：  
  

```
pDataT->dwArgs = 4;
 pDataT->runner = (ULONG_PTR)Runner;
 pDataT->function = (ULONG_PTR)MessageBoxA;
 pDataT->args[0] = (ULONG_PTR)0;
 pDataT->args[1] = (ULONG_PTR)&#34;Hello&#34;;
 pDataT->args[2] = (ULONG_PTR)&#34;LDRSHUFFLE&#34;;
 pDataT->args[3] = (ULONG_PTR)MB_OKCANCEL;
 pDataT->event = CreateEventA(NULL, FALSE, FALSE, &#34;ExecEvt&#34;);
```

  
  
修改_LDR_DATA_TABLE_ENTRY  
  
该UpdateLdr()函数负责在目标模块中执行正确的修改_LDR_DATA_TABLE_ENTRY。  
  
RestoreLdr()将在稍后阶段恢复这些更改（由 调用Runner()）。  
> 这些函数本质上是定位 PEB 并遍历模块结构以识别正确的 DLL 及其字段。在头文件中，我重用了 Batsec 在其DarkLoadLibrary中使用的定义，我鼓励读者查看这个项目以及相关的 MDSec 博客文章，以便从他在 Windows 模块加载内部机制方面所做的出色工作中受益。  
  
> https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/  
  
  
注意：此 PoC 会加载一个牺牲 DLL（SACRIFICIAL_DLL_NAME），并对该 DLL 执行上述更改。然而，修改已加载的 DLL 也是完全可行的。这实际上是跨进程注入所采用的方法。出于稳定性考虑，我建议避免接触重要的 DLL，例如ntdll或kernel32，因为这些 DLL 也往往受到安全解决方案的严格审查。  
  
执行  
  
在线程创建或销毁时，执行将被重定向到，该函数充当模块的Runner()伪装。然后，该函数将：DllMain()  
- 在堆上定位用于运行调用/获取返回值的数据结构（PDATA_T结构）  
  
- 将 PEB 恢复RestoreLdr()到原始状态  
  
- 执行正常DllMain()调用（本质上代理正常的 DLL 调用）。  
  
至此，“正常”操作系统执行已完成。然后继续执行我们的有效载荷：  
  
根据DATA_T结构体中存储的值和参数，执行我们的恶意 API 调用。如果此 API 已标记为在新线程中运行（createThread = 1），则此调用将在新线程中执行。  
- 最后，发出一个事件信号（pDataT->event），以便我们的主代码知道调用已经执行。  
  
- 当 Windows 最终调用我们的伪造函数EntryPoint（即Runner()函数地址）时，调用堆栈如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrSfPgpLPaOuibMPnfp9ibI76ibQbJnC6rcUtyxxqI61ygBjdBIIZu7PSOg/640?wx_fmt=png&from=appmsg "")  
  
API 代理示例  
  
提供的 PoC 包含一个调用的示例MessageBoxA()。  
  
它还包含使用 进行 HTTP 下载的演示wininet。定义HTTP变量以启用该代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrpRbeiamCYhl3Obx5YnyxQyq6rGUQJ0U2dpxhyzcQUfI2jr0ib7amAfKg/640?wx_fmt=png&from=appmsg "")  
  
跨进程注入示例  
  
上述原理可以归结为在进程内存空间中进行读写操作，以便在未来的任意时间点执行代码。  
  
通过一些调整，这些读写操作可以应用于远程进程，以覆盖其某个 DLL EntryPoint。  
  
前提条件是能够在进程内存空间中读写，即：  
  
OpenProcess(PROCESS_VM_READ, FALSE, dwPid)和OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, PID)  
  
PoC 中有一个额外的项目，名为LdrInject，演示了如何执行这些步骤。简而言之，它执行以下操作：  
- 在 中ReadPEB()，它会遍历_LDR_DATA_TABLE_ENTRY目标进程中的列表，以识别合适的 DLL 进行覆盖。请注意，此 DLL 必须包含DontCallForThreads == 0，因为我们希望 Windows 在线程创建时调用该 DLL EntryPoint。我们也不会选择列表中的第一个 DLL，因为它们往往会受到安全产品的严格审查（ntdll.dll，kernel32.dll...）。  
  
- 该 DLL 的详细信息存储在PEBINJ_DATA数据结构中。  
  
- shellcode（在本例中为信标）在远程进程空间中写入InjectShellcodeToRemoteProcess()  
  
- 两次WriteProcessMemory()调用覆盖 DLLEntryPoint并将其备份，OriginalBase以便以后可以恢复。  
  
此时，下一个DLL_THREAD_ATTACH或DLL_THREAD_DETACH事件将导致shellcode被调用。这在运行信标的上下文中存在一些限制和注意事项，将在下一节中详细介绍。  
  
Cobalt Strike信标  
  
这种技术会导致在非常特殊的情况下执行shellcode。加载程序锁处于活动状态（因为操作系统认为它正在加载/卸载DLL）；线程正在被创建或销毁；一般来说，存在线程同步问题、死锁等潜在问题。  
  
在测试过程中，我们发现了两个挑战：  
- wininet.dll运行典型的 Cobalt Strike 信标会在使用或中的 API 时导致死锁winhttp.dll。  
  
- 在线程销毁时运行会导致稳定性问题，因为我们正在一个正在被销毁的线程中运行。  
  
为了提高稳定性，我们必须：  
- 确保信标将在新线程中运行。因此，UDRL 将CreateThread在调用常规 Cobalt Strike 反射 DLL 入口点之前运行。  
  
- 仅在正在创建的线程中运行，而不是正在消亡的线程中运行。为此，我们确保当EntryPoint操作系统调用时，调用的原因是fdwReason == DLL_THREAD_ATTACH：  
  

```
winApi.CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)&runner, (LPVOID)&ct_data, 0, &dwThId);
```

  
  
而不是通常的  
  

```
((DLLMAIN)entryPoint)((HINSTANCE)loaderStart, 4, NULL);
```

  
  

```
ULONG_PTR __cdecl ReflectiveLoader(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
        // only run for a Thread creation event
        
        if (fdwReason != DLL_THREAD_ATTACH) {
            return TRUE;
        }

        ...
    }
```

  
  
这两个额外的步骤已经嵌入到 UDRL 的演示中。  
  
项目地址：  
  
https://github.com/RWXstoned/LdrShuffle  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

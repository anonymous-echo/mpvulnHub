> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531218&idx=2&sn=21b822e0433fe3eada8864c6b7ab9bde

#  Dirty Vanity：代码注入和 EDR 绕过的新方法  
 Ots安全   2025-06-23 11:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
这一技术利用Windows操作系统的forking机制，通过复制目标进程的内存空间（包括预植入的恶意载荷）来规避端点检测与响应（EDR）系统的监控。根据2023年Deep Instinct的研究显示，78%的EDR系统无法有效检测基于fork的注入攻击，这一发现揭示了传统安全防御机制的显著漏洞。  
  
Dirty Vanity的核心在于利用RtlCreateProcessReflection API对目标进程（如Explorer.exe）进行远程fork操作，并执行预先写入的shellcode。这种方法巧妙地绕过了传统EDR对“分配/写入/执行”序列的监控模式，这一点与MITRE ATT&CK框架中关于进程注入（T1055）的记录相呼应。该技术的灵感来源于Windows遗留的POSIX子系统，通过现代API重新激活其功能，暴露了进程隔离机制中意想不到的安全缺陷。正如2022年Black Hat会议上展示的fork-based凭据窃取案例所示，这种技术不仅创新性强，还对现有安全假设提出了挑战。  
  
本文将深入探讨Dirty Vanity的实现原理、潜在影响以及对未来EDR开发提出的新要求，帮助读者理解这一新兴威胁并提升防御能力。  
  
Dirty Vanity 是一种新型代码注入技术，它利用了 Windows 操作系统中鲜为人知的分叉机制 (fork)。在本文中，我们将深入研究分叉机制，探索其合法用途，并展示如何通过注入恶意代码将其操纵成盲视 EDR。  
  
实现一种新的代码注入技术通常遵循一个简单的公式，这使得防御这些攻击变得易于管理。偶尔，一种新的、古怪的技术会被引入，而常规协议无法缓解。例如：Dirty Vanity。  
  
分叉背景  
  
进程分叉 (fork) 是指从调用进程创建新进程的行为。“fork”这个名称源自 UNIX 进程创建的系统调用——“fork”和“exec”。  
  
Dirty Vanity 是对 Windows 中合法分叉机制的滥用。  
  
Windows 分支  
  
Windows 本身并不使用 fork 和 exec 来创建进程。然而，它在其旧版 POSIX 子系统（自 1993 年 Windows NT 第一版起就已包含）中支持这些功能，该子系统旨在支持基本的 UNIX 二进制执行。POSIX 子系统早已被取代（首先是Windows XP 中的Windows UNIX 服务(SFU)，后来又被当前的Windows Linux 子系统(WSL)）但其代码至今仍影响着 Windows。  
  
下面是 psxdll.dll，它是该子系统的核心部分，导出了基本的 UNIX API：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGowibP9Bvy2btic7r18Tw9TBtE8AGezWj8qZnMya2f0GcSXOlS15e8O1g/640?wx_fmt=png&from=appmsg "")  
  
图 1：分叉起源  
  
我们可以看到，这个 _fork 是在内部通过调用 Ntdll 的 RtlCloneUserProcess 来实现的，而 RtlCloneUserProcess 则负责实际的分叉。  
  
在上面的例子中，我们看到了 Windows Fork 的起源，并且以下机制至今仍在使用分叉：  
  
进程反射- 一种分叉机制，其目标是允许对应该持续提供服务的进程进行分析。WDI（Windows 诊断基础结构）使用进程反射来实现以下目的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapG4pXQzJ6HGS39Qpz9wl1pYaoyHLTicc1P68rTk0HIjl8CUbiakZdiaeVjQ/640?wx_fmt=png&from=appmsg "")  
  
图 2：流程反思  
  
进程快照- 让您能够捕获部分或全部进程状态。它可以使用 Windows 内部 POSIX fork clone 功能高效地捕获进程的虚拟地址内容。  
  
恶意用例示例：  
  
通过分叉进行凭据转储 - 在凭据转储领域，许多防御措施都集中在 LSASS.exe 上，该程序存储已登录的用户凭据。对于利用前面提到的分叉机制之一对 LSASS 进行分叉并访问受保护程度较低的分叉内容的防御措施，存在一种分叉绕过方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGVA3GHcVuOI4aoibLh37RibMpSw4AOibs1tsJNnJRCr2PibFUxYFCn3xFicQ/640?wx_fmt=png&from=appmsg "")  
  
图 3：通过分叉进行凭证转储  
  
总而言之，Windows 的 fork 功能与其最初旨在支持的传统 UNIX fork 功能类似，但它却揭示了一个不同且更强大的远程 fork 选项。利用 Windows 中的这种远程 fork 功能，我们可以操纵防御措施，就像上面提到的恶意 LSASS 转储用例中看到的那样。在 Dirty Vanity 的案例中，我们将演示如何进一步滥用它。  
  
分叉 API  
  
在介绍 Dirty Vanity 如何滥用远程 fork 之前，我们将先介绍一下可以调用 fork 的 Windows API。首先，我们先来了解一下支持 POSIX 基本 fork 的 API：  
  

```
RtlCloneUserProcess（ 
  ULONG ProcessFlags，
  PSECURITY_DESCRIPTOR ProcessSecurityDescriptor，
  PSECURITY_DESCRIPTOR ThreadSecurityDescriptor，
  HANDLE DebugPort，
  PRTL_USER_PROCESS_INFORMATION ProcessInformation）;
```

  
  
RtlCloneUserProcess 本质上是 NtCreateUserProcess 的包装器，调用相同的功能  
  

```
NtCreateUserProcess（
  PHANDLE ProcessHandle，
  PHANDLE ThreadHandle，
  ACCESS_MASK ProcessDesiredAccess，
  ACCESS_MASK ThreadDesiredAccess，
  POBJECT_ATTRIBUTES ProcessObjectAttributes，
POBJECT_ATTRIBUTES ThreadObjectAttributes，
ULONG ProcessFlags，
ULONG ThreadFlags，
PVOID ProcessParameters，
PPS_CREATE_INFO CreateInfo，
PPS_ATTRIBUTE_LIST AttributeList）；
```

  
  
NtCreateUserProcess 是一个系统调用。它通过在 PPS_ATTRIBUTE_LIST AttributeList 参数中设置 PS_ATTRIBUTE_PARENT_PROCESS 来公开进程分叉，如下所示：  
  

```
NTSTATUS NtForkUserProcess()
{
  HANDLE hProcess = nullptr, hThread = nullptr;
  OBJECT_ATTRIBUTES poa = { sizeof(poa) };
  OBJECT_ATTRIBUTES toa = { sizeof(toa) };
  PS_CREATE_INFO createInfo = {sizeof(createInfo)};
  createInfo.State = PsCreateInitialState;
// Add a parent handle in attribute list
  PPS_ATTRIBUTE_LIST attributeList;
  PPS_ATTRIBUTE attribute;
  UCHAR attributeListBuffer[FIELD_OFFSET(PS_ATTRIBUTE_LIST, Attributes) + sizeof(PS_ATTRIBUTE) * 1];
memset(attributeListBuffer, 0, sizeof(attributeListBuffer));
  attributeList = reinterpret_cast<PPS_ATTRIBUTE_LIST>(attributeListBuffer);
  attributeList->TotalLength = FIELD_OFFSET(PS_ATTRIBUTE_LIST, Attributes) + sizeof(PS_ATTRIBUTE) * 1;
  attribute = &attributeList->Attributes[0];
  attribute->Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
  attribute->Size = sizeof(HANDLE);
  attribute->ValuePtr = GetCurrentProcess();

  NtCreateUserProcessFunc const NtCreateUserProcess = reinterpret_cast<NtCreateUserProcessFunc>(GetProcAddress(LoadLibraryA(&#34;ntdll.dll&#34;), &#34;NtCreateUserProcess&#34;));
  NTSTATUS res = NtCreateUserProcess(&hProcess, &hThread, 0, 0, nullptr, nullptr, PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT | PROCESS_CREATE_FLAGS_INHERIT_HANDLES, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, nullptr, &createInfo, attributeList);
auto pid = GetProcessId(hProcess);
return res;
}
```

  
  
正如我们所得出的结论，Windows fork 的更强大变体是远程 fork，但如果我们尝试用不同的句柄替换此示例中的 attribute->ValuePtr = GetCurrentProcess();：attribute->ValuePtr = someOtherHandle;我们将失败，STATUS_INVALID_PARAMETER==0xC000000D，这意味着此 API 无法进行远程 fork。  
  
远程分叉  
  
我们现在将探索进程反射和进程快照背后的 API ，因为这些是在 Windows 中提供远程分叉的机制。  
  
进程快照由 Kernel32!PssCaptureSnapshot 调用，如果我们沿着调用链往下走，我们会看到 Kernel32!PssCaptureSnapshot 调用 ntdll!PssNtCaptureSnapshot，然后又调用 ntdll!NtCreateProcessEx。  
  
让我们看一下 NtCreateProcessEx 及其旧版本 NtCreateProcess  
  

```
NtCreateProcessEx(PHANDLE ProcessHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes ,
  HANDLE ParentProcess,
  ULONG Flags,
  HANDLE SectionHandle,
  HANDLE DebugPort,
  HANDLE ExceptionPort,
  BOOLEAN InJob);
NtCreateProcess(
  PHANDLE ProcessHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  HANDLE ParentProcess,
  BOOLEAN InheritObjectTable,
  HANDLE SectionHandle,
  HANDLE DebugPort,
  HANDLE ExceptionPort);
```

  
  
NtCreateProcess[Ex] 是两个遗留的进程创建系统调用，它们提供了另一种访问分叉机制的途径。然而，与较新的 NtCreateUserProcess 不同，可以通过将 HANDLE ParentProcess 参数设置为目标进程句柄来使用它们分叉远程进程。  
  
使用 RtlCreateProcessReflection 调用进程反射  
  

```
RtlCreateProcessReflection（
  HANDLE ProcessHandle，
  ULONG Flags，
  PVOID StartRoutine，
  PVOID StartContext，
  HANDLE EventHandle，
  T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation）；
```

  
  
RtlCreateProcessReflection 将分叉由 HANDLE ProcessHandle 代表的进程。  
  
它执行以下操作：  
1. 创建共享内存部分。  
  
1. 用参数填充共享内存部分。  
  
1. 将共享内存部分映射到当前进程和目标进程。  
  
1. 通过调用 RtlpCreateUserThreadEx 在目标进程上创建一个线程。该线程将在 ntdll 的 RtlpProcessReflectionStartup 函数中开始执行。  
  
1. 创建的线程调用 RtlCloneUserProcess，并传递从与启动进程共享的内存映射中获取的参数。如前所述，RtlCloneUserProcess 包装了 NtCreateUserProcess，将当前进程 fork 到新的目标进程。  
  
1. 在内核模式下，NtCreateUserProcess 执行的代码路径与创建新进程时的大部分代码路径相同，但调用 PspAllocateProcess（用于创建进程对象和初始线程）时，会调用 MmInitializeProcessAddressSpace，并使用一个标志指定地址应该是目标进程的写时复制副本，而不是初始进程地址空间。  
  
1. 如果 RtlCreateProcessReflection 的调用者指定了一个 PVOID StartRoutine，RtlpProcessReflectionStartup 会在关闭之前将执行权移交给该程序。如果提供了 PVOID StartContext，它还会将其作为参数提供。  
  
您可能已经猜到了，PVOID StartRoutine 在 Dirty Vanity 中扮演着关键角色。  
  
大多数分叉繁重的工作都是在内核模式下完成的，其中最有趣的部分是它将所有目标进程地址空间复制到分叉进程，包括动态分配和运行时修改，这将我们带到了 Dirty Vanity。  
  
代码注入和端点检测与响应 (EDR)  
  
让我们简单介绍一下传统注射的步骤。  
  
为了在目标进程中启动并运行注入的代码，注入器将执行以下操作：  
- 步骤 1：为要注入的 shellcode 分配空间或为其找到代码洞。  
  
- 步骤 2：使用各种写入原语将 shellcode 写入步骤 1 中创建的空间。  
  
- 写入进程内存  
  
- NtMapViewOfSection  
  
- 全局添加原子  
  
- 步骤 3：使用各种执行原语执行步骤 2 中编写的 shellcode。  
  
- 设置上下文线程  
  
- NtQueueApcThread  
  
- IAT Hook 和调用钩子  
  
注入器可以选择任何分配、写入和执行原语组合，调用它们并创建注入。  
  
由于注入原语的动态特性，大多数 EDR 会尝试通过钩住它们所识别的所有原语来应对注入。以下是这种方法的一个示例，其中 Injector.exe 对 Explorer.exe 执行了最简单的注入：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGzxFEHktkZgABSF0BJdHb9Q2AfYZw5og20yLPwXzpLTt9P8giaEEQ9aA/640?wx_fmt=png&from=appmsg "")  
  
图4：对Explorer.exe的简单注入  
  
当 EDR 监视系统时，它会监视同一目标上的所有原语，并在 Explorer.exe 上捕获所有这三个原语：  
- 分配 = VirtualAllocEx  
  
- 将内容写入分配=WriteProcessMemory  
  
- 执行写入的内容=CreateRemoteThread  
  
当监控最终执行原语时，EDR 将检测/阻止此注入尝试。  
  
肮脏虚荣的体现  
  
Dirty Vanity 滥用了前面描述的 Windows 远程 fork 机制，将其作为注入领域的新原语——Fork。其背后的概念很简单，包含以下步骤：  
  
1.初始写入步骤：以任何首选方式分配并将有效载荷写入目标进程，即：  
- VirtualAllocEx 和 WriteProcessMemory  
  
- NtCreateSection 和 NtMapViewOfSection  
  
- 任何其他首选方式  
  
2.分叉和执行步骤：在目标进程上执行远程分叉，并将进程起始地址设置为有效载荷（分叉到同一位置），使用：  
- RtlCreateProcessReflection（PVOID StartRoutine = 指向克隆的 shellcode）  
  
- NtCreateProcess[Ex] + 克隆的 shellcode 上的任何执行原语  
  
我们将这些步骤应用到前面的例子：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGMvIpfpRp98ZTK2J4zdicLRDuzgNFiaE2JNQfpz2xaBCicZ3L4rfibALJ2A/640?wx_fmt=png&from=appmsg "")  
  
图 5：脏污虚荣流  
  
Injector.exe 通常会先通过 VirtualAllocEx 启动，然后再通过 Explorer.exe 执行 WriteProcessMemory 操作。监控此系统的 EDR 会关联这些操作，并等待第三个执行原语将此操作标记为注入。  
  
在 Dirty Vanity 中，这个预期的执行原语不会发生，而是我们恢复到远程 fork API。  
  
Explorer.exe 现在分叉为其自身的副本，分叉的结果进程包含 Explorer.exe 地址空间的副本，包括从初始写入步骤加载到相同地址并使用相同内存保护的有效载荷。  
  
通过将分叉进程的起始地址设置为我们的有效载荷，它将执行。这可以通过以下方式实现：  
1. RtlCreateProcessReflection（PVOID StartRoutine = 指向克隆的 shellcode）  
  
1. NtCreateProcess[Ex] + 在克隆的 shellcode 上执行原语  
  
完成这些步骤后，我们分叉的 Explorer.exe 包含我们的有效载荷并执行它。  
  
Dirty Vanity 背后的新颖之处在于 fork 所创建的分离：虽然分配和写入阶段通常在目标进程上完成，但它们不会被捕获，因为实际执行阶段（对于 EDR 视角的注入至关重要）是由分叉的目标进程执行的。  
  
从 EDR 的角度来看，新分叉的 Explorer.exe 从未被写入过，并且对其的执行与写入尝试无关。  
  
由于这种独特的执行方式，Dirty Vanity 避开了常见的 EDR 检测方法。  
  
运行 Dirty Vanity 的先决条件  
  
为了调用 Dirty Vanity，我们需要一个具有以下访问权限的目标进程句柄：  
- RtlCreateProcessReflection 变体：PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |PROCESS_DUP_HANDLE  
  
- NtCreateProcess[Ex] 变体：PROCESS_CREATE_PROCESS  
  
为了完整实现，目标进程句柄应包含这些访问权限和适合您选择的初始写入步骤的访问权限的组合。  
  
通过 RtlCreateProcessReflection 进行肮脏的虚荣  
  
本博客背后的研究重点是采用 RtlCreateProcessReflection 方法的 POC。  
  
下面是用它执行 Dirty Vanity 的代码片段：  
  

```
unsignedchar shellcode[] = {0x40, 0x55, 0x57, ...}; 
size_t bytesWritten = 0; 

// 使用适当的权限打开 fork 目标
HANDLE victimsHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE, TRUE, victimsPid); 

// 在目标内分配 shellcode 大小
DWORD_PTR shellcodeSize = sizeof(shellcode); 
LPVOID baseAddress = VirtualAllocEx(victimHandle, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 

// 写入 shellcode 
BOOL status = WriteProcessMemory(victimHandle, baseAddress, shellcode, shellcodeSize, &bytesWritten); 
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002 
HMODULE ntlib = LoadLibraryA(&#34;ntdll.dll&#34;); 
Rtl_CreateProcessReflection RtlCreateProcessReflection = (Rtl_CreateProcessReflection)GetProcAddress(ntlib, &#34;RtlCreateProcessReflection&#34;); 
T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 }; 

// Fork 目标并在克隆中执行 shellcode 库
NTSTATUS ret = RtlCreateProcessReflection(victimHandle, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, baseAddress, NULL, NULL, &info);
```

  
  
第一次尝试这个 POC 时，我们使用了一个基本的 MessageBoxA shellcode，它导致了访问冲突异常：  
  

```
1:002> g
(6738.da4): Access violation - code c0000005 (first chance)

First-chance exceptions are reported before any exception handling.

This exception may be expected and handled.
USER32!GetDpiForCurrentProcess+0x14:

00007ff8`8b75719c 0fb798661b0000 movzx ebx,word ptr [rax+1B66h] ds:000002d3`6ef92ba6=????
1:002> k
# Child-SP RetAddr Call Site
00000000da`df9ffb10 00007ff8`8b7570c2 USER32!GetDpiForCurrentProcess+0x14
01000000da`df9ffb40 00007ff8`8b75703b USER32!ValidateDpiAwarenessContextEx+0x32
02000000da`df9ffb70 00007ff8`8b7bc2da USER32!SetThreadDpiAwarenessContext+0x4b
03000000da`df9ffba0 00007ff8`8b7bc0d8 USER32!MessageBoxTimeoutW+0x19a
04000000da`df9ffca0 00007ff8`8b7bbcee USER32!MessageBoxTimeoutA+0x108
05000000da`df9ffd00 000002d3`71bf0050 USER32!MessageBoxA+0x4e
06000000da`df9ffd40 00007ff8`8c210000 0x000002d3`71bf0050
```

  
  
该 shellcode 被有效地分叉并执行，但 USER32!MessageBoxA 的内部功能却无法在分叉过程中运行。  
  
简而言之，USER32!MessageBoxA 需要将 user32!gSharedInfo 结构映射到进程。  
  
我们的分叉进程缺少它，因为 user32!gSharedInfo 使用 ViewUnmap 设置明确映射到每个进程：  
  
“ViewUnmap：视图将不会映射到子进程中”  
  
这意味着，ViewUnmap 数据（例如 user32!gSharedInfo ）对克隆的子进程是隐藏的。为了克服这一障碍，我们的 POC 采取的方法是使用仅包含 NTDLL 的 Shellcode，它是完全独立的，因此在这些部分中没有任何依赖关系。  
  
我们使用https://github.com/rainerzufalldererste/windows_x64_shellcode_template作为模板来创建基于 ntdll 的自定义 shellcode，其功能如下：  
1. 从 LDR 检测 Ntdll API  
  
1. 使用 RtlInitUnicodeString、RtlAllocateHeap 和 RtlCreateProcessParametersEx 创建参数  
  
1. 调用NtCreateUserProcess  
  
- 进程：C:\Windows\System32\cmd.exe  
  
- 命令行：/k msg * “来自 Dirty Vanity 的问候”  
  
完整源代码：https://github.com/deepinstinct/Dirty-Vanity  
  
总结一下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGiaBkrgltRaRg6t3DZPj6sms1iaXRHYCKeZyvXl73hX3OLDicnUeCR6b2Q/640?wx_fmt=png&from=appmsg "")  
  
图 6：通过 Explorer 的 PID 调用 Dirty Vanity  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGgwxiaenHXuBWFELicdZJkiawzer2UzwKq670TBkAyZudazhPsmsgQFgzw/640?wx_fmt=png&from=appmsg "")  
  
  
图 7：结果进程树，其中分叉的 Explorer 子进程执行我们的 shellcode。  
  
概括  
  
为了检测代码注入，EDR 解决方案通常会监控并关联在同一进程上执行的“分配/写入/执行”操作。Fork API 引入了一种新的注入原语——Fork，这对传统的检测方法提出了挑战。  
  
Dirty Vanity 利用 fork 将所有分配和写入操作克隆到一个新进程。从 EDR 的角度来看，这个进程从未被写入过，因此在最终执行时不会被标记为注入：  
- 使用RtlCreateProcessReflection进行Fork&Execute，这是本研究的重点。  
  
- 在调用 RtlCreateProcessReflection 或 NtCreateProcess[Ex] 之后执行普通原语，这仍然是一条未探索的路径。  
  
Dirty Vanity 改变了我们看待注入防御的方式，因为分叉改变了操作系统监控的规则，并且 EDR 必须通过监控所有出现的分叉原语来做出响应，最终跟踪分叉的进程，并使用对其父进程的相同了解来对待它们。  
  
  
参考  
  

```
https://github.com/deepinstinct/Dirty-Vanity

https://i.blackhat.com/EU-22/Thursday-Briefings/EU-22-Nissan-DirtyVanity.pdf

https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/

https://gist.github.com/juntalis/4366916

https://gist.github.com/Cr4sh/126d844c28a7fbfd25c6 RtlCloneUserProcess 

https://gist.github.com/GeneralTesler/68903f7eb00f047d32a4d6c55da5a05c

https://github.com/hasherezade/pe-sieve/blob/master/utils/process_reflection.cpp

https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/

https://paper.bobylive.com/Meeting_Papers/BlackHat/USA-2011/BH_US_11_Mandt_win32k_Slides.pdf

https://github.com/rainerzufalldererste/windows_x64_shellcode_template
```

  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

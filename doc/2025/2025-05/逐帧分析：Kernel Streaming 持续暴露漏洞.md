#  逐帧分析：Kernel Streaming 持续暴露漏洞   
Angelboy  securitainment   2025-05-28 08:17  
  
> 【翻译】Frame by Frame, Kernel Streaming Keeps Giving Vulnerabilities   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNfEibVqDzKUiayG4BqGs4VdVHb9gmuDeWjvKNpbeFzUXWKbfvQxGEbibzQ/640?wx_fmt=png&from=appmsg "")  
  
这是一系列关于 Kernel Streaming 攻击面的研究。建议先阅读以下文章：  
- Windows Kernel 中的流媒体漏洞 - 内核代理 - 第一部分  
  
- Windows Kernel 中的流媒体漏洞 - 内核代理 - 第二部分  
  
欢迎阅读我关于 Windows 内核流媒体漏洞系列的第三部分。该研究也在 OffensiveCon 2025 上进行了展示。  
  
在过去的一年中，我们发现了一个被忽视的漏洞类别，称为 Proxying to Kernel  
（内核代理），它导致了严重的后果，使得在 Windows 内核中的利用变得直接。然而，这只是 Kernel Streaming 漏洞的冰山一角。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN3seOA2L8XP7IuVz35AcFVD7bn8Eob4UrZib3YMlib0NsnKTvehHicVy4Q/640?wx_fmt=png&from=appmsg "")  
  
在发现 Kernel Streaming 中的多个漏洞（包括与代理系列相关的漏洞）后，我们决定深入研究其内部机制。在 2023 年底到 2024 年底之间，我们识别了超过 20 个漏洞。其中大约 14 个与 AVStream 相关，大多数发生在帧处理过程中。在本文中，我将重点讨论这些与帧相关的问题。  
  
让我们来谈谈内核流媒体帧。  
## Kernel Streaming 帧概述  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNtia39rWEfiaonODSgbDTRG9NJHIicEfkIBgd8yF3g8Ulxw0okc7pOlmibA/640?wx_fmt=png&from=appmsg "")  
  
在 Kernel Streaming 中，当从设备读取数据时，Kernel Streaming 会分配 KS 帧来承载流媒体数据，如视频或音频。  
```
struct _KSPFRAME_HEADER
{
  _LIST_ENTRY ListEntry;
  _KSPFRAME_HEADER *NextFrameHeaderInIrp;
  void *Queue;
  _IRP *OriginalIrp;
  _MDL *Mdl;
  _IRP *Irp;
  KSPIRP_FRAMING_ *IrpFraming;
  KSSTREAM_HEADER *StreamHeader;
  void *FrameBuffer;
  KSPMAPPINGS_TABLE *MappingsTable;
  unsigned int StreamHeaderSize;
  unsigned int FrameBufferSize;
  void *Context;
  int RefCount;
  void *OriginalData;
  void *BufferedData;
  int Status;
  unsigned __int8 DismissalCall;
  _KSPFRAME_HEADER_TYPE Type;
  _KSPSTREAM_POINTER *FrameHolder;
  unsigned int OriginalOptionsFlags;
  _KSPMDLCACHED_STREAM_POINTER *MdlCaching;
};

```  
  
KS 帧中的帧缓冲区存储着实际的图像或音频数据。大多数帧缓冲区由 Memory Descriptor List (MDL) 描述，它映射了这些缓冲区的物理内存。如果您不熟悉 MDL 是什么，不用担心 —— 这里有一个快速概述。  
### MDL  
  
MDL (Memory Descriptor List)  
 是 Windows 内核模式下的一个结构体，用于描述虚拟内存缓冲区背后的物理页。它允许内核组件和驱动程序执行直接内存访问（DMA），并安全地在不同上下文之间共享缓冲区。MDL 在 Windows 内核中被广泛使用，通常与 IRP 结合用于 Direct I/O，以及在文件系统和网络驱动程序中进行数据传输操作。  
  
MDL (Memory Descriptor List)  
 结构体定义如下：  
```
typedef struct _MDL {
  struct _MDL      *Next;
  CSHORT           Size;
  CSHORT           MdlFlags;
  struct _EPROCESS *Process;
  PVOID            MappedSystemVa;
  PVOID            StartVa;
  ULONG            ByteCount;
  ULONG            ByteOffset;
  ULONG64          PFN[];  // Variable-length array of page frame numbers

} MDL, *PMDL;
```  
  
这是一个可变大小的结构体，其中 **PFN (Page Frame Numbers，页帧号)**数组存储在 MDL 的末尾。每个 PFN 对应 MDL 描述的虚拟缓冲区所对应的物理页。  
  
在 Kernel Streaming 中，MDL 描述了一个同时映射到用户空间和内核空间的缓冲区，这两个映射都指向相同的物理内存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN5HJqUQhboLPSiaYDI3kjBcmVOzKMjdpu6fiaJ3mtGrjQiavjmIm4kIGcg/640?wx_fmt=png&from=appmsg "")  
  
因此，当从设备读取数据时，数据会同时写入用户模式和内核模式的缓冲区。  
  
让我们快速了解一下 MDL 的典型用法。  
#### MDL 的基本使用  
  
当内核需要访问用户模式内存时——特别是在提升的 IRQL 级别（如 DISPATCH_LEVEL  
）或 DPC（Deferred Procedure Call，延迟过程调用）中——它通常依赖 MDL 来安全地描述和锁定该内存。通常，这个过程会调用下图所示的一组 API。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNDiacJtTZAcPI5I28MAWoNKQYP5raD31KTupSsF8fguWp8I5sATRibZsg/640?wx_fmt=png&from=appmsg "")  
#### IoAllocateMDL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN0l9Gz1hkoiaDZY9SFkIRUVCERoAQULH7dFbBViaMnkMbrp66mO31P85g/640?wx_fmt=png&from=appmsg "")  
  
首先，内核调用 IoAllocateMdl  
 来分配一个 MDL 结构体，根据提供的虚拟地址和长度初始化它来描述一个缓冲区。**但它不会初始化 MDL 中的 PFN（Page Frame Number，页帧号）数组。**  
#### MmProbeAndLockPages  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNgnicdQlgiaxhEicXmV3q7cysaXkyFic50ZEf2pwjeCLiaEtfOOIojGXgltw/640?wx_fmt=png&from=appmsg "")  
  
接下来，内核调用 MmProbeAndLockPages  
 来锁定与虚拟地址范围对应的物理页，并填充 MDL 内部的 PFN（Page Frame Number，页帧号）数组。  
#### MmMapLockedPagesSpecifyCache  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNucibMTibNFgLiaJdCyU9KjicCtSQGow6Ce6YzIWzvnatPPeODa8MvC6cbw/640?wx_fmt=png&from=appmsg "")  
  
当内核需要访问内存时，它会调用 MmMapLockedPagesSpecifyCache  
 来**使用 MDL 中存储的 PFN**  
 映射一个新的虚拟地址。  
  
顺便说一下，也可以使用这个 API 将内核缓冲区映射到用户空间。  
#### MmUnlockPages/IoFreeMdl  
  
内核使用完通过 MDL 映射的缓冲区后，必须调用 MmUnlockPages  
 来释放锁定的物理页。最后，应该使用 IoFreeMdl  
 释放 MDL 本身。  
  
就本文而言，理解 Kernel Streaming 使用 MDL 来管理用户空间和内核空间之间共享的帧缓冲区就足够了。  
  
如果您对 MDL 的更多细节感兴趣，这里有一些有用的参考资料：  
- Using MDLs  
  
- Understanding Memory Descriptor Lists (MDLs) for Windows Vulnerability Research & Exploit Development  
  
接下来，让我们看看一个典型的应用程序如何从网络摄像头读取数据——以及 Kernel Streaming 在底层如何实现这一功能。  
### 如何从网络摄像头读取流  
  
以下是使用 Kernel Streaming 从网络摄像头读取视频流的简化工作流程：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNqPxZsOia0CCmBHSTMEHv31kJ7WvbCAgC2DmjS0V0ibkPqfSMOK323q5g/640?wx_fmt=png&from=appmsg "")  
1. 打开设备以获取网络摄像头设备的句柄。  
  
1. 使用此设备句柄在此过滤器上创建 Pin 的实例并获取 Pin 句柄。  
  
1. 使用 IOCTL_KS_PROPERTY 将 Pin 的状态设置为 RUN  
。当 Pin 进入 RUN 状态时，网络摄像头的指示灯通常会亮起，表示设备已激活并准备好进行流传输。  
  
1. 最后，您可以使用 IOCTL_KS_READ_STREAM 从此 Pin 读取数据。在发送 IOCTL 读取流时，我们需要提供一个 KSSTREAM_HEADER 结构体作为输入以指定必要的信息。  
  
```
typedef struct {
  ULONG    Size;
  ULONG    TypeSpecificFlags;
  KSTIME   PresentationTime;
  LONGLONG Duration;
  ULONG    FrameExtent; //Buffer Size
  ULONG    DataUsed; 
  PVOID    Data; // point to image Buffer
  ULONG    OptionsFlags;
  ULONG    Reserved;
} KSSTREAM_HEADER, *PKSSTREAM_HEADER;
```  
  
内核将使用此结构将数据从设备复制到内存中。最重要的字段是 Data  
（指向用户空间缓冲区）和 FrameExtent  
（指示缓冲区大小）。Kernel Streaming 将基于这些值映射帧缓冲区，并将图像数据写入提供的内存区域。此外，您还可以使用 OptionsFlags  
 字段来描述帧的属性。  
### Kernel Streaming 中的流读取  
  
让我们简要介绍 ks 如何实现帧读取。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN4D1bW6z2ibuvoh0yanfHgfPXu4ak2G0WYaMTaycnLGohd6PdmOgod8g/640?wx_fmt=png&from=appmsg "")  
  
首先，必须在用户空间分配一个缓冲区来存储传入的图像数据。然后，准备一个包含缓冲区地址和大小的 KSSTREAM_HEADER  
 结构，并通过 IOCTL_KS_READ_STREAM  
 传递给内核。当此 IOCTL 发送到网络摄像头设备时，将由 ksthunk.sys  
 和 ks.sys  
 处理。如果请求不是来自 WoW64 进程，它将被传递给 ks.sys  
 进行进一步处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNE57mZV1jTV2icsCS3ukiaRagibBIXeibe3uK40fleIT7SsiaibvzZQRrFNaA/640?wx_fmt=png&from=appmsg "")  
  
ks.sys  
 收到请求后，会解 KSSTREAM_HEADER  
，根据提供的缓冲区和大小创建 MDL（内存描述符列表），并将其插入 IRP（I/O 请求包）。然后通过此 MDL 将用户空间缓冲区映射到内核空间作为帧缓冲区。此时，用户缓冲区和帧缓冲区都指向相同的物理内存，实现了用户空间和内核空间之间的高效零拷贝数据传输。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNLeFUnoPvw91hFngpLTd7r6Lux4wicicPDqIkvj46hib4XhFvylojolAdQ/640?wx_fmt=png&from=appmsg "")  
  
最后，ks.sys  
 在内核中分配一个 KS Frame (_KSPFRAME_HEADER)  
。此结构包含关联的 MDL、指向帧缓冲区的指针、缓冲区大小以及用于管理流操作的其他元数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNA3LwTmCjich2UdfpYiabxqEVXFaqBRYticDCjQ7ZibRx0qT5EicZI2OicAVg/640?wx_fmt=png&from=appmsg "")  
  
KS FRAME  
 随后被放入内部队列，等待填充数据。接下来，Kernel Streaming 工作线程从队列中取出一个 KS FRAME  
，并开始将设备中的图像数据捕获到关联的帧缓冲区中。队列中剩余的 KS FRAME  
 结构将按照入队顺序依次处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNwCeG6jb8j72QLdN9GSQprH1ibfB5jP9kjbTBVFgSls4mZ5d1bp8t0qw/640?wx_fmt=png&from=appmsg "")  
  
顺便说一下，也可以在单个 IOCTL 调用中提交多个 KSSTREAM_HEADER  
 结构以请求多个帧。在这种情况下，ks.sys  
 将根据输入缓冲区中提供的 KSSTREAM_HEADER  
 数组按顺序处理每个帧请求。每个帧都与一个 KSSTREAM_HEADER  
、一个 MDL 和一个 KS FRAME  
 存在一一对应关系。  
  
在了解了架构和帧读取的基础知识后，我们现在可以从攻击者的角度来审视这些内容。  
### 攻击者视角  
  
那么，我们应该关注哪些方面呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNXdib29Ndfd6wOyXLDk8EKSiaycMITn9F9toZXVHdYzcH8msiaEOUtADag/640?wx_fmt=png&from=appmsg "")  
  
第一个也是最直观的目标是 ksthunk.sys  
 和 ks.sys  
 之间的转换层。当 32 位请求转换为 64 位时，对用户控制的 KSSTREAM_HEADER  
 结构的处理不当可能导致内存损坏——例如，CVE-2024-38054 就是这样一个案例。此转换层还可能引入一致性问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNDwPxlDnZIL1TscYLaN5J2NSzGYGBEibS4VJ78VVWKrNYrxDW4ibn22icA/640?wx_fmt=png&from=appmsg "")  
  
另一个有趣的目标是 ks.sys  
 如何管理帧缓冲区。如果在帧缓冲区处理过程中**误用**  
了 MDL，可能会导致各种形式的内存损坏。我们稍后将研究这些问题的一些示例。  
  
在我们的 Kernel Streaming 研究中，我们发现了几个值得注意的新漏洞类别。  
## Kernel Streaming 中的新漏洞类别  
  
我们发现的第一个漏洞类别是 MDL 不匹配。  
### MDL 不匹配  
  
当 ksthunk.sys  
 收到 32 位请求时，它不仅会将请求转换为其 64 位等效项，还会预分配一个 MDL 来描述帧缓冲区。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNoh8HQYTXibh2SYwh5fYDReibDNKHicIeo1Vu6A3MCmfplaFSKwfBXVib1g/640?wx_fmt=png&from=appmsg "")  
  
如图所示，当发出 32 位请求时，ksthunk.sys  
 首先处理它。在此步骤中，它会设置 MDL 并执行帧缓冲区的映射。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNyL6sWLE1USBkgbzYtvHmian0TPTV5sRvpwq7wdjoIyMMoesVtKiaX7mQ/640?wx_fmt=png&from=appmsg "")  
  
ksthunk.sys  
 完成预处理后，将 IRP 传递给 ks.sys  
 进行进一步处理。由于 MDL 已经由 ksthunk.sys  
 创建，ks.sys  
 将**不会**  
分配新的 MDL。此时，会分配一个 KS FRAME  
 来表示 Kernel Streaming 框架中的帧。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNV77DK6xTAiaLd70tjVmzibfaVA3JTSdqVTjjS3ibEL1OOjuJ05xRByzKw/640?wx_fmt=png&from=appmsg "")  
  
此外，如果在单次调用中请求了多个帧，ksthunk.sys  
 将预分配所有必要的 MDL 并执行相应的帧缓冲区映射。  
  
但是，如果 OptionsFlags 字段设置为 KSSTREAM_HEADER_OPTIONSF_PERSIST_SAMPLE (0x8000)  
，ksthunk.sys  
 将跳过正常的 MDL 分配过程。此标志实际上是 Kernel Streaming 的 MDL 缓存机制的一部分。虽然我们不会在此详细介绍，但重要的是要理解启用此标志**会导致 ksthunk 跳过该帧的 MDL 分配**  
。  
  
此外，由于每个帧都是独立处理的，因此可以在提交多个帧的单个请求中，通过为特定帧设置 KSSTREAM_HEADER_OPTIONSF_PERSIST_SAMPLE  
 标志，故意将其标记为缓存。  
  
让我举个例子：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNKlOgJbVt5kCmVMHqNt9F6BZO5xQ0YAoYZVDzHhYXKRtDCqLHtA3Xkg/640?wx_fmt=png&from=appmsg "")  
  
假设我们提交了两个帧，第二个帧被标记为缓存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNIFVI2AvxVBic77QC5MdvYKTsreR1J8HcqPvhibV1NBJPXTlaxibU1eXbQ/640?wx_fmt=png&from=appmsg "")  
  
ksthunk.sys  
 将检查每个帧的 OptionsFlags  
 字段。如果未设置缓存标志，它会分配一个 MDL 并相应地映射帧缓冲区。由于第二个帧**设置了**  
缓存标志，ksthunk.sys  
 将跳过该帧的 MDL 分配。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNpicEAUzPXCUvl0KS4oj181ISoNEo3VUh9o3waCAUJNBNib4yKMiaDcIRw/640?wx_fmt=png&from=appmsg "")  
  
之后，IRP 被传递给 ks.sys  
，它将再次检查每个帧的 OptionsFlags  
 字段。然而，这里的逻辑与 ksthunk.sys  
 相反。  
- 对于第一帧——因为它没有缓存标志——ks.sys 假设 MDL 已经由 ksthunk 分配，因此跳过 MDL 分配。  
  
- 对于第二帧，由于设置了缓存标志，ks.sys  
 将分配一个新的 MDL 并映射帧缓冲区。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNeKnsrpFV9tKw1IdgCibxVSEh4Z94ib7mykTjRarXO2icrR0PWAsibUXibEQ/640?wx_fmt=png&from=appmsg "")  
  
ks.sys  
 然后根据 **KSSTREAM_HEADER 条目的顺序**  
创建 KS FRAME  
。每个 KSFRAME 都与其对应的 MDL 一一配对，帧被放入内部队列，等待工作线程拉取和处理。  
> 但是...这真的安全吗？  
  
  
似乎存在一些不一致。**让我们滥用 MDL 链！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNdWZgK7qSrAka17HNg87MdtnEcd4qyCvYGb5OqaojRCYFMsjEQXzicFQ/640?wx_fmt=png&from=appmsg "")  
  
假设我们提交了两个帧：  
- 对于第一帧，我们将缓冲区大小设置为 0x1000  
 并启用缓存标志。  
  
- 对于第二帧，我们将缓冲区大小设置为 0x20000  
，但不设置缓存标志。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNv7QSQ9vQykb3uxmk6ES5WYAnia399Xh4fibh9PbaNRGVrnWh8bI3khmw/640?wx_fmt=png&from=appmsg "")  
  
ksthunk.sys  
 像往常一样检查每个流头。对于第一帧，由于**设置了缓存标志**  
，它**跳过**  
了 MDL 分配。对于第二帧，由于未设置缓存标志，ksthunk 分配了一个新的 MDL 并相应地映射了帧缓冲区。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNmvw7ibfYgocxYF4nFeaFNibUQ1I2lyQfnfOIDnGt6sgy4wO4xVicHMvHg/640?wx_fmt=png&from=appmsg "")  
  
之后，IRP 被传递给 ks.sys  
，它将再次检查每个帧的 OptionsFlags  
 字段。  
- 对于第一帧，由于设置了缓存标志，ks.sys  
 将分配一个新的 MDL，映射帧缓冲区，并将其插入 MDL 链。  
  
- 对于第二帧，未设置缓存标志，因此 ks.sys  
 假设 MDL 已经由 ksthunk 分配，因此跳过分配。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNGBffLjwk9cRLtIy3KEpftP0WQ8jibfFn3ejoP6niagdqdwa8E5oEVg1w/640?wx_fmt=png&from=appmsg "")  
  
最后，ks.sys  
 根据 MDL 链和相应的 KSSTREAM_HEADER  
 条目创建 KS FRAME  
。每个头中的 FrameExtent  
 字段被存储到关联的 KS FRAME  
 中，定义了预期的帧大小。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNUwVxPRN0H4hTUVWfMVsQjMLVFfficSnfc6TzIicSUfbThiaSkueVyibFXQ/640?wx_fmt=png&from=appmsg "")  
  
如图所示，第一帧将存储大小为 0x1000，而第二帧将存储大小为 0x20000。  
  
**你注意到问题了吗？**  
 当我们运行它时...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNkicV4Y9M76qzQQ6NIQs8v9mUSAJx2HZibicEKHS4SrWKPaibVoco1eVGEA/640?wx_fmt=png&from=appmsg "")  
> 为什么？  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN1wkGbuGLaWrWCicgdaYVHGHTPHcEBJBGY7Y0qjeVxF6jPZaB0IPjG6w/640?wx_fmt=png&from=appmsg "")  
  
此问题的根本原因是每个 KSSTREAM_HEADER  
 与其对应的 MDL 之间的不匹配。例如，第一个 KSSTREAM_HEADER  
 与第二帧的 MDL 配对，而第二个 KSSTREAM_HEADER  
 最终链接到第一帧的 MDL。  
> 实际影响是什么？  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNopWicwqWBiaRmz1icglUJF2cm0BshwJ5NyqBeozhELVE377UNTE2TBIfQ/640?wx_fmt=png&from=appmsg "")  
  
当工作线程从设备复制数据时，它依赖于每个 KS FRAME  
 中存储的缓冲区地址和大小来执行复制操作。两个帧的处理方式相同——工作线程参考 KS FRAME  
 结构体来确定复制的位置和数据量。然而，问题就出在这里...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNnYajZkeJs848snvnm9CHa1A0JeQ9XwPQ1h8sXnsFACOVFdKjPuweibw/640?wx_fmt=png&from=appmsg "")  
  
对于第二个 KS FRAME  
，实际分配的缓冲区只有 0x1000  
 字节，但结构体中的 FrameExtent  
 字段却指示大小为 0x20000  
。结果，工作线程尝试将 0x20000  
 字节复制到一个**小得多的缓冲区**  
中，导致缓冲区溢出。  
  
事实上，我们发现的几个漏洞都源于这个问题。只要攻击者能够创建 KSSTREAM_HEADER  
 与其对应 MDL 之间的不匹配，就会导致缓冲区溢出。  
- CVE-2024-38237  
  
- CVE-2025-21375  
  
- ...  
  
我们要讨论的第二个漏洞类别被称为 MDL 中的遗忘锁  
——一种涉及 MDL 错误处理的漏洞模式。  
  
这个漏洞类别有些特殊  
### 遗忘锁  
  
实际上，这是 MDL 中的一个**未初始化问题**  
。  
  
在讨论这个问题之前，让我们先看看开发者在处理 MDL 时常见的一些错误。  
#### MDL 的安全风险  
  
第一个是最近常见的问题——我在之前的文章中也提到过。  
> MmProbeAndLockPages  
 中错误的 access mode  
 标志  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNJGtkKoJ0GjqI3hWru3TXiciaZQ6YOTmapFxwnar1ExVbPcqwA7rvUibzQ/640?wx_fmt=png&from=appmsg "")  
  
当内核调用 MmProbeAndLockPages  
 锁定用户提供的内存缓冲区时，可能会错误地设置 access mode  
 标志。这个错误导致内核跳过验证目标地址是否属于用户空间的检查。结果，用户模式进程可以提供内核模式地址，导致内核空间中的任意内存写入。  
  
更多细节，请参考 Synacktiv 在 HITB 2023 HKT 的演讲和 Nicolas Zilio(@Big5_sec) 的博客文章。  
> I/O 完成中的双重释放  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN2pDvyG8SnDgP1ickc10HxibicRkpfmKm2pCib5cdYNFJ4NJ4SjgAXia945g/640?wx_fmt=png&from=appmsg "")  
  
另一个常见问题是内核驱动程序释放 MDL 时没有清除 IRP 中对应的 MDL 指针。随后，当 IRP 完成时，系统会尝试再次释放 MDL，导致在 IoCompleteRequest 期间发生双重释放漏洞。这种模式也可以在 Kernel Streaming 中找到 (CVE-2025-24046)。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNib4A8IQdPQ2iaTkB1EtibFic69R3NYAMvLFfSGDEWTpdpxW7jnJIia3lutw/640?wx_fmt=png&from=appmsg "")  
  
当帧分配失败时，ks.sys  
 会释放 MDL 链中的 MDL，但没有清除存储在 IRP 中的 MDL 指针。结果，当 IRP 完成时，MDL 被再次释放——导致双重释放。  
  
这两种漏洞模式相当常见，还有许多被忽视的问题。  
  
让我们以 Microsoft 驱动程序安全指南中的一个例子为例。  
  
在该文档中，Microsoft 警告说，如果开发人员使用 MmMapIoSpace  
 而没有正确验证物理地址，可能会导致任意物理内存被映射到虚拟地址空间——可能引发严重的安全问题。  
  
为了说明安全用法，Microsoft 提供了以下安全编码示例：  
```
Func ConstrainedMap(PHYSICAL_ADDRESS paAddress)
{
    // expected_Address must be constrained to required usage boundary to prevent abuse
    if(paAddress == expected_Address && qwSize == valid_Size)  //-----[1]
    {
        lpAddress = MmMapIoSpace(paAddress, qwSize, ...);   
        pMdl = IoAllocateMdl( lpAddress, ...); //----------[2]
        MmMapLockedPagesSpecifyCache(pMdl, UserMode, ... ); //-------------[3]
    }
    else
    {
        return error;
    }
}
```  
  
首先，在 [1] 处验证物理地址。然后，在 [2] 处分配一个 MDL（Memory Descriptor List）来描述映射的内存区域。最后，在 [3] 处调用 MmMapLockedPagesSpecifyCache  
 将物理内存映射到用户空间的虚拟地址。  
> 现在...你可能会注意到一些奇怪的地方。  
  
  
正如我们前面提到的，在典型用法中，分配 MDL 后，应该先调用 MmProbeAndLockPages  
 来锁定底层物理页。然而，在这个例子中，代码直接调用了 MmMapLockedPagesSpecifyCache  
，而没有先锁定页面。这会导致未定义行为，因为 MDL 可能无法正确描述有效或可访问的物理内存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNUZK292XVADJfpoVb4x9GdIjYGVTcHULA5PibTFzibUkNK4evhYt8lBNg/640?wx_fmt=png&from=appmsg "")  
  
如上图所示，IoAllocateMdl  
 用于分配 MDL 结构并初始化一些基本元数据。然而，如果我们立即调用 MmMapLockedPagesSpecifyCache  
 而没有先锁定页面，该函数仍会尝试访问 MDL 内部的 PFN（Page Frame Number）数组。这可能导致未定义行为，或者更糟，导致可控的内存损坏。在许多情况下，这会直接导致蓝屏死机（BSoD）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNibpDzqeAvBdJhlicBIsLdtaBckVfwF3ibvcLiaICguGfzRallbSuNoLqlg/640?wx_fmt=png&from=appmsg "")  
  
然而，这种错误在 Kernel Streaming 中普遍存在。在下一节中，我将分析 CVE-2024-38238，它清楚地展示了这个问题在实际中的表现。  
#### CVE-2024-38238  
  
我们再次构建两个 KSSTREAM_HEADER  
 结构——这次两个帧的大小相同。第一个帧设置了缓存标志，而第二个帧没有。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNfYUP3ZoscjAfgYVdRHLhRmg2STXibWr22ffyWtlFd4iciaba3K9Wq7gcg/640?wx_fmt=png&from=appmsg "")  
  
如前所述，ksthunk.sys  
 只会为没有设置缓存标志的帧分配并锁定 MDL。完成后，IRP 会被传递给 ks.sys  
 进行进一步处理。  
  
现在，让我们仔细看看 ks.sys  
 如何处理这个帧。  
```
__int64  CKsMdlcache::MdlCacheHandleThunkBufferIrp(...)
{
  ...
  while(TotalSize >= sizeof(KSSTREAM_HEADER)){ //-------[4]
      ...
      if(OptionsFlag & 0x8000 == 0) //-------[5]
        return KsProbeStreamIrp(irp, a3, 0); //-------[8]
      IoAllocateMdl(header->Data,header->FrameExtent,...,Irp); //-------[6]
  }
  ...
  for(i = irp->MdlAddress;i;i = i->Next){
      MmProbeAndLockPages(i, irp->RequestorMode, IoWriteAccess); //-------[7]
  }
}

```  
  
观察 ks!CKsMdlcache::MdlCacheHandleThunkBufferIrp  
 函数中的 while 循环 [4]，我们可以看到它会遍历每个 KSSTREAM_HEADER  
 结构，并在 [5] 处检查 OptionsFlag  
 标志以确定是否需要分配 MDL（Memory Descriptor List）。  
  
如果设置了缓存标志，程序会在 [6] 处分配一个新的 MDL。在 WOW64 环境下，如果 MDL 已经被分配（例如由 ksthunk 分配），KS（Kernel Streaming）随后会在 [7] 处调用 MmProbeAndLockPages  
 来锁定内存页。  
  
然而，在我们的特定案例中：  
- 第一个帧设置了缓存标志  
  
- 第二个帧没有设置缓存标志  
  
因此，当 KS 开始处理第二个帧时，它会转向 [8] 处的 KsProbeStreamIrp 路径。此时，IRP（I/O Request Packet）中的 MDL 链情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNDGDFxdRS4KiaP1KHgZ5EjiadibRWFSkwFibZcyHoYZVCgJ35c46uOSyQ6g/640?wx_fmt=png&from=appmsg "")  
  
第一个 MDL 已经被正确锁定，但第二个 MDL 完全没有被锁定。  
  
之后，ks!KsProbeStreamIrp  
 会处理帧缓冲区的映射：  
```
NTSTATUS KsProbeStreamIrp(PIRP Irp, ULONG ProbeFlags, ULONG HeaderSize){
 ...
 MDL = Irp->MdlAddress;
 if ( (MDL->MdlFlags & is_locked_and_nonpaged) != 0 ) { //----[9]
    while ( MDL ) 
    {
        if ( (MdlFlags & 5) != 0 )
        MappedSystemVa = MDL->MappedSystemVa;
        else
        MappedSystemVa = MmMapLockedPagesSpecifyCache(MDL, 0, MmCached, 0LL, 0, 0x40000010u); 

        MDL = MDL->Next;
    }
 }
}


```  
  
如上所示，该函数使用 MmMapLockedPagesSpecifyCache  
 通过每个 MDL 映射帧缓冲区。如果 MDL 被标记为已锁定，函数会直接映射它。然而，这里存在一个关键缺陷：它在 [9] 处仅检查 MDL 链中的第一个 MDL，并假设整个链已经被锁定。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swND1yyoWiabdFJcPlXJBnZdS4KCzfm6ExhVurZxicH6JiaWEBP2c6TTPlhA/640?wx_fmt=png&from=appmsg "")  
  
当在第二个 MDL 上调用 MmMapLockedPagesSpecifyCache  
 时，它会尝试基于未初始化的 PFN（Page Frame Number，页帧号）列表映射内存。  
> 不可利用？  
  
  
好消息是 IoAllocateMdl  
 从 NonPagedPoolNx 分配内存时不会进行零初始化。这意味着位于 MDL 结构末尾的 PFN 数组将包含残留的内存数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNhOpdlibfN5GNzdoviaZVyWdH55gClDMnrCatYr384TN4vlErIS2qGP1g/640?wx_fmt=png&from=appmsg "")  
  
如上图所示，当 IoAllocateMdl 分配内存时，它使用了 POOL_FLAG_UNINITIALIZED 标志，并且不会初始化 MDL 中的 PFN 数组。这种行为允许我们应用池喷射（pool spraying）技术来部分或完全控制 MDL 内部的 PFN 值。  
  
通过计算 MDL 结构的确切大小——包括基于帧大小的 PFN 数量——我们可以使用 Named Pipes 进行池喷射，用精心构造的数据填充 NonPagedPoolNx  
 内存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN9Gf0wLqibFQZdjAibEJf77Mw1icticjZr09iatPibHxayBtfHIXR36M7pGjQ/640?wx_fmt=png&from=appmsg "")  
  
当 IoAllocateMdl  
 重用这些内存而不进行零初始化时，残留的值将被解释为有效的 PFN，从而使攻击者能够控制物理到虚拟的映射。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNiaJRnXYIsDUBwlUBhDqN9EKgZXFNhuTWcCJwvRKcnhElaXw34bALjeg/640?wx_fmt=png&from=appmsg "")  
  
如上图所示，当随后调用 MmMapLockedPagesSpecifyCache  
 时，它会将攻击者控制的 PFN 视为有效的物理页映射，并使用它们来映射帧缓冲区。  
  
最后，当工作线程从设备复制图像数据时，它会直接写入攻击者指定的物理地址，从而产生一个强大的任意物理内存写入原语。  
  
实际上，并非所有 PFN 都可以被映射——它们必须是有效的，例如 ResidentPage  
。但对于我们的目的来说，这已经足够了。  
  
下一步是使用任意物理内存写入原语实现权限提升（EoP，Elevation of Privilege）。但这引出了一个问题：  
> 我们应该写入哪里？  
  
  
在对多个 Windows 24H2 进行测试时，我们观察到一个一致的行为：ntoskrnl.exe  
 的物理基地址通常固定在 0x100400000。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNKiadzMV1twiaJ3N2xzVl1NJodFap3HFNYo03NDrI3oMNoPLtqApJQBpQ/640?wx_fmt=png&from=appmsg "")  
  
我们在 Hyper-V 和 VMware 上进行了测试。这个值可能在更新的版本中有所变化，但在许多情况下仍然可能保持固定。这种行为也可能取决于设备或硬件配置。  
> 那么...这是否意味着我们可以直接写入 nt 并接管内核？  
  
  
这里有一个问题......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNrLmlgTM7J9mGs6liaUNluEqAfKd36ZkpzS2GMrnmOSNW9Rnm310E2mw/640?wx_fmt=png&from=appmsg "")  
  
我们无法控制被写入的数据，因为它直接来自网络摄像头设备。  
  
最初，我们似乎陷入了困境。但拥有如此强大的原语——稳定且可重复的任意物理内存写入——我们知道一定有办法继续前进。  
  
于是我们回过头，仔细审查了整个 Kernel Streaming 的工作流程，最终发现了一个新的攻击角度。  
> 缓冲模式  
  
  
Kernel Streaming 提供了一个称为缓冲模式（buffered mode）的功能。当使用 **缓冲标志（KSSTREAM_HEADER_OPTIONSF_BUFFEREDTRANSFER）**  
 创建 KS FRAME  
 时，ks.sys  
 会在内核空间分配一个额外的中间缓冲区。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN0hVXpqDnFQtEY2tVvmF3wHKSoWEDicgcLh0BQia6fXrum1C1gYDm1UvQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNfHTWy8j9CSM0m9ns7KicwvbYQbEgiakuxfvHIGYgLZJfoloMDl7EFBUg/640?wx_fmt=png&from=appmsg "")  
  
在流传输过程中，原始图像缓冲区的内容首先被复制到这个中间缓冲区。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNcBhus7Nria3BGlpemibqYtrb48aVy3pOjle9wngXmp94MCBdicv3s6hSg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNS0DUTeu1BiaGIib4iaXCxqsspqe41CmeA5zicoicfcCZQqdI8U2xWk3iaHUg/640?wx_fmt=png&from=appmsg "")  
  
如上图所示，在设备完成数据写入后——或者传输过程中发生错误时——ks.sys  
 会将缓冲内存的内容复制到帧缓冲区。然而，在我们的案例中，这个帧缓冲区已经被映射到 ntoskrnl.exe  
 映像的物理地址。换句话说，我们现在拥有了一个具有完全控制数据的 **任意物理内存写入原语**  
。这为直接修改内核代码打开了大门。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNabdFIWYichTztg0CApq327ugzl3J2L7hcwSva49zicamCGDovibywFsSA/640?wx_fmt=png&from=appmsg "")  
  
在我们的漏洞利用中，我们选择覆盖 PsOpenProcess 中的一个安全检查。具体来说，我们将 SeDebugPrivilege  
 的检查替换为 SeChangeNotifyPrivilege  
。结果，任何普通用户都可以打开高权限进程（除了 PPL）。有关用 SeChangeNotifyPrivilege  
 替换检查的技术的更多细节，您可以参考 我的前一篇文章。  
  
在 Kernel Streaming 中，有多种方式可以导致这个问题：  
- CVE-2024-38238  
  
- CVE-2024-38241  
  
- CVE-2025-24066  
  
- ...  
  
只要找到一种方法让它忘记锁定，就可能导致任意物理内存写入。  
  
我们要分享的最后一个问题是 **帧缓冲区错位**  
。  
### 帧缓冲区错位 (CVE-2024-38245)  
  
在深入探讨之前，我们首先需要介绍 Kernel Streaming 中的一个关键对象：KS Allocator。KS Allocator 负责预分配一组可以在流操作期间重用的帧缓冲区。这显著减少了运行时动态内存分配的开销。通常，一个分配器对象与一个 pin 相关联，第三方驱动程序也可以实现自己的自定义分配器。Kernel Streaming 还提供了一个默认分配器，在没有自定义实现时使用。  
  
通常，可以使用 KsCreateAllocator API 创建 KS Allocator，并通过称为 KSALLOCATOR_FRAMING 的结构进行配置。该结构允许您指定参数，例如帧缓冲区的数量、每个缓冲区的大小，甚至每个帧缓冲区的对齐要求。  
```
typedef struct {
  union {
    ULONG OptionsFlags;
    ULONG RequirementsFlags;
  };
#if ...
  POOL_TYPE PoolType;
#else
  ULONG     PoolType;
#endif
  ULONG     Frames;
  ULONG     FrameSize;
  union {
    ULONG FileAlignment;
    LONG  FramePitch;
  };
  ULONG     Reserved;
} KSALLOCATOR_FRAMING, *PKSALLOCATOR_FRAMING;
```  
  
**注意：**  
 要指定帧缓冲区的对齐方式，您必须在分配器配置期间提供对齐掩码。  
  
创建 KS Allocator 后，我们可以将其附加到 Pin 上。在从 Pin 读取数据之前，需要将其状态设置为 **KSSTATE_RUN**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNtgpsZmLqymrNAFMmqPsGdXFJaBmoDI4IwyumTP3H7lsUzmOrSuGGMg/640?wx_fmt=png&from=appmsg "")  
  
此时，分配器将根据之前提供的配置预分配帧缓冲区。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNRqMJMib4HJoQRfXLXXTB4WSSdzv1JGJr376OffUfwH9VyXtlYg7Fxgg/640?wx_fmt=png&from=appmsg "")  
  
从这时起，数据将从设备流式传输到预分配的帧缓冲区中。同时也会分配相应的 KS FRAME  
 结构。当我们发送 IOCTL_KS_READ_STREAM  
 来读取数据时，过程将如前所述开始。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNq1wxr09Bh9HfwTApJdERuwXkNQI44Sva0EW7cy4MzibuyyEjWKiaXcog/640?wx_fmt=png&from=appmsg "")  
  
然而，与每次从设备读取数据不同，工作线程将从分配器管理的预分配帧缓冲区中复制数据。在接下来的部分中，我们将重点讨论默认分配器如何管理这些预分配缓冲区。  
  
让我们深入了解 **DefaultAllocator**  
。  
  
ks!KsCreateDefaultAllocatorEx ![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNzNJ6Uz3O2dibzkcuJ5yIBOIxqzLVPWRyiaqPhg3HXUnibo6SCJcQtPH1g/640?wx_fmt=png&from=appmsg "")  
  
  
当我们调用 KsCreateAllocator  
 时，Kernel Streaming 会创建一个默认分配器，并使用我们提供的参数对其进行初始化。在内部，ks.sys  
 实现了自己的自定义分配例程 - DefAllocatorAlloc  
 和 DefAllocaorFree  
，并利用 LookasideList 来高效管理缓冲区的分配和重用。  
  
分配函数非常简单：  
```
char *__fastcall DefAllocatorAlloc(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Alignment)
{
    ...
    if ( Alignment >= FILE_OCTA_ALIGNMENT )
        FileAlignment = Alignment;
    ...
    buffer = ExAllocatePoolWithTag((PoolType | 0x400), v8, 'adSK');//-----[10]
    if ( buffer )
    {
        padding = (~FileAlignment & (buffer + FileAlignment + 4)) - buffer;
        buffer += padding;
        *(buffer - 1) = padding; //-------[11]
    }

}

```  
  
它直接调用 ExAllocatePoolWithTag 在 [10] 处分配内存。如果指定了对齐方式，ks.sys  
 会在帧缓冲区前记录所需的填充大小，如 [11] 处所示。  
  
在释放例程中：  
```
void __fastcall DefAllocatorFree(unsigned int *Buffer)
{
  __int64 padding; 
  ...
  if ( (Buffer & 0xFFF) != 0 )
    padding = *(Buffer - 1); //---------------[12]
  else
    padding = 0LL;
  ExFreePoolWithTag(Buffer - padding, 0);
}

```  
  
KS 使用这个填充大小来计算 ExAllocatePoolWithTag 在 [12] 处返回的原始指针。  
  
如下图所示，内存池的布局如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNVP7fnzmdOJUgLDvxgNMibdE0ibBwRUtyARlf4hj549PIDJng5EY2owRw/640?wx_fmt=png&from=appmsg "")  
  
紫色区域代表填充部分，蓝色区域对应帧缓冲区本身。帧缓冲区前面的 4 个字节用于存储填充大小。在正常情况下，对齐掩码应该是 2 的幂减一（例如 0x3F、0xFFF 等）。  
  
然而，这里存在一个问题：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNB48iaFiaajdLIKOCAJE3GWzFO8ndX5JEJB9WTNKl4TEgBdQnkJvWICkQ/640?wx_fmt=png&from=appmsg "")  
  
KS 只检查对齐掩码是否大于 0xFFF。如果小于 0xFFF，它会接受任何值，即使这不是一个有效的对齐方式。  
> 无用的漏洞？  
  
  
乍一看，这可能像是一个无害的漏洞——只是一个内存对齐的小问题。但是当这个未对齐的缓冲区遇到 LookasideList  
 时会发生什么？  
#### LookasideList  
  
LookasideList  
 是针对固定大小内存块优化的每处理器缓存。它们不使用通用的池分配器，而是维护一个简单的单向链表以实现快速分配和释放。**分配和释放操作总是先检查链表，然后再使用通用池，链表按照后进先出（LIFO）的顺序操作。**  
 一个重要的约束是存储在 LookasideList  
 中的条目**需要对齐到 0x10 字节**  
。可以参考 SLIST_ENTRY  
。  
  
正如你在 ExAllocateFromNPagedLookasideList  
 中看到的：  
```
PSLIST_ENTRY ExAllocateFromNPagedLookasideList(...){
    ...
    ReturnChunk = ListHead->FreeChunk & 0xFFFFFFFFFFFFFFF0;
    ListHead->FreeChunk = ReturnChunk->Next;
    ListHead->Depth-- ;
    ...
}

```  
  
分配逻辑在将内存块返回给调用者之前，会将其地址对齐到 0x10 字节（16 字节对齐）。  
```
PSLIST_ENTRY ExFreeToNPagedLookasideList(...,PSLIST_ENTRY Chunk){
    ...
    NextChunk = ListHead->FreeChunk & 0xFFFFFFFFFFFFFFF0
    Chunk->Next = NextChunk;
    ListHead->FreeChunk = Chunk;
    ListHead->Depth++;
    ...
}
```  
  
同样地，当内存被释放回 LookasideList  
 时，它也会对齐内存块。如上文代码片段所示，释放例程会对链表中的第一个条目进行对齐。  
> 非 0x10 字节对齐的帧缓冲区 + LookasideList  
  
  
那么，如果一个没有 0x10 字节对齐的帧缓冲区被插入到 LookasideList  
 中会发生什么？  
#### 让我们玩转帧缓冲区  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNJ9BQu4UJGGPnriciaXGgibTToeibnibDibYEIEmiaUlLyCH9AInfrfaCDTKpw/640?wx_fmt=png&from=appmsg "")  
  
我们编写了一个脚本来列出所有可能的对齐掩码和填充大小。在这个案例中，我们使用了一个导致 8 字节填充的对齐掩码。然后，我们配置分配器预先分配 4 个帧缓冲区。结果，每个缓冲区都将遵循相同的布局——由于 8 字节填充，最终的帧缓冲区地址都以 0x08 结尾。  
  
缓冲区将如下图所示：![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNf79JVt2oyLSqcJE3YQECUghLCwdNdLOvdFCic6D2KFIMXyuyNOFpyrQ/640?wx_fmt=png&from=appmsg "")  
  
  
之后，分配器返回四个缓冲区——A、B、C 和 D——由于应用的填充，它们的地址都以 0x8 结尾。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNDSLCePxcyqotQYbgwTsV7lubLfx41ZDohc6o8kDTgIFiamLebZoiczyQ/640?wx_fmt=png&from=appmsg "")  
  
当这些缓冲区被释放时，ks.sys  
 会逐个释放它们，并按顺序将它们插入 LookasideList  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNW9eYy5MFCDOTkZrewsGTRyk97RptjVBgfqibNl3DsN3XWVRZXVRFsww/640?wx_fmt=png&from=appmsg "")  
  
如上图所示，我们首先释放 Frame A  
，它被顺利插入到 LookasideList  
 中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNibVgias1pThsAcRVuo1ZMDyI78mNAn8bXPlPLSm7vsicFvpVzeExXhoSw/640?wx_fmt=png&from=appmsg "")  
  
当 Frame B  
 被释放时，分配器首先对齐当前链表头（Frame A  
）的地址以满足 0x10 字节对齐要求。**然后将这个对齐后的地址存储在 Frame B 的 next 指针字段中**  
，并将 Frame B 插入到 LookasideList  
 的头部。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNeib1XKBlVv5fCnUDMQS99OAiaVyiaH2hEGMzGYjjs6yjc4yo8wIrfcgtw/640?wx_fmt=png&from=appmsg "")  
  
我们继续释放 Frame C  
 和 Frame D  
，它们都遵循与之前相同的模式。最终，LookasideList  
 将如上图所示的布局。  
> 你发现问题了吗？  
  
  
问题在于 Frame D  
 的 **next 指针**  
。由于对齐，**next 指针最终指向了池块的起始位置，而不是实际的帧缓冲区**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNXO2AUVuUXy6lSGgoyDPbkTHS4C4Mhk2fYK3viaQyxrJrkDdGHcLUplQ/640?wx_fmt=png&from=appmsg "")  
  
如上图所示，你会注意到 Frame C  
 的 next 指针指向了填充区域，该区域包含存储的填充大小，而不是预期的链表条目结构。当被解释为 64 位值时，这个指针变成了类似 0x800000000  
 的值——这属于用户空间地址范围。  
  
我们的计划是在 0x800000000  
 处分配一个内存页，从而获得对 LookasideList  
 的控制。然后，我们将链表中的最后一个节点配置为指向我们期望的目标地址。之后，当设备执行读取操作时，ks.sys  
 会将传入的数据写入这些帧缓冲区——包括指向我们选择地址的那个缓冲区。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN5R0r8dP540ic9SicMREBZxDTgWk0AKIic10uXOVkWia0H1FVL7uuyurjXg/640?wx_fmt=png&from=appmsg "")  
> 理论上，这给了我们一个任意内存写入原语，对吗？  
  
  
然而，我们仍然面临与之前相同的限制：我们无法控制被写入的内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNo0vDKpCdEbichhIAwWycian8KqRiciaqtAMbqXLib3oAYA8QHnn7XmsKfxg/640?wx_fmt=png&from=appmsg "")  
  
此外，我们无法在此场景中使用 buffered flag  
，这意味着我们只能使用设备发送的任何数据——这使得精确利用变得更加困难。  
  
此时，我们再次陷入了困境。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNxFmX6fnvRW11UMRl6NIU29NeV9rWcPR7edpqNIOh7bsCO7dCQmWWvQ/640?wx_fmt=png&from=appmsg "")  
  
但在再次思考后，我们找到了另一种前进的方法。  
#### 让 LookasideList 再次伟大  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNXZCtPWwv3nK7SnneENVtw1ZUUvn7c2IiaZf1E4CQLJjr0icIroqYCNIw/640?wx_fmt=png&from=appmsg "")  
  
如上图所示，我们首先在用户空间构建一个虚假的链表。地址 0x41410000  
 代表一个用户控制的内存区域，我们用它来构建一个有效的 LookasideList  
 条目。然后，我们继续分配帧缓冲区，这导致分配器遍历我们构建的虚假链表。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swN0C8A2IuwOnQjcVRBicLia4T8cGu4aRib3mwMj1U6e7pfiayvnkmkiaHySDA/640?wx_fmt=png&from=appmsg "")  
  
在 ExAllocateFromNPagedLookasideList  
 中，分配器首先对齐内存块，然后更新链表头。然而，由于未对齐，对齐逻辑错误地**将 Frame D 的起始位置解释为 next 指针**  
——导致 LookasideList  
 的遍历错误。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNnYbxIZCmaKhf0JPP0CXFP4y3pAha4eOUerG2mCgJIatt92bTVlx8Dg/640?wx_fmt=png&from=appmsg "")  
  
一旦第一个块从链表中弹出，链表就会转变为上图所示的状态。接下来，我们从 LookasideList  
 中分配所有剩余的块。我们还配置分配器使用较小的帧缓冲区，这导致网络摄像头**进入等待状态——它不再从设备读取数据**  
。然后，我们触发 STOP 以释放所有帧缓冲区。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNhUM8JQeZphCIHBDkSNjjiaxiaE7OOXtf90ul5I9lhg9JZog9ULmnJV4A/640?wx_fmt=png&from=appmsg "")  
  
帧缓冲区将如上图所示。此时，ks.sys  
 开始逐个将缓冲区返回到 LookasideList  
。首先，它释放 Frame D  
。然后，它释放位于 0x800000000  
 的恶意块。之后，它释放位于 0x41410000  
 的虚假块。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNxNQolLg8AXaPoMx5j8I8a65EwI7geVOlxrOuib4Em1gt8rwdrxNfibDQ/640?wx_fmt=png&from=appmsg "")  
  
一旦这三个块被释放，LookasideList  
 的结构就会转变为上图所示的布局。最终，分配器将释放我们的目标地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNq4T7bdRiaSChctFNRibGzSAPw5yyajOqqAtd8xkibrdfWod1KsPBUNWoA/640?wx_fmt=png&from=appmsg "")  
  
**这将导致目标地址的 next 指针指向 0x41410000**  
。这个值可以是攻击者控制的任何用户空间地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCONGARUn8hs4eofU6WL9swNiaqULF0KicEZxBXbepQdyecF2Y6eO7wSdNdiaibDhtzUwf1Gs6DNkV7Yhw/640?wx_fmt=png&from=appmsg "")  
  
换句话说，我们现在拥有了一个强大的任意内存写入原语。  
  
在 Windows 23H2 上获得任意内存写入能力后，我们可以使用 NtQuerySystemInformation 来泄露线程对象的地址。有了这个地址，我们翻转 token 结构中的必要位以提升权限。从这里，我们可以应用任何众所周知的 EoP 技术来实现完整的权限提升。顺便说一句，一旦你实现了任意内存写入，**别忘了将 LookasideList 恢复到有效状态**  
——否则，系统可能会在后续分配期间崩溃。  
  
我们成功地将一个看似无害的漏洞变成了一个严重的漏洞。  
## 下一步与总结  
  
这种漏洞模式可能不仅限于 Kernel Streaming。通过更密切地关注 MDL 相关问题，你可能会在其他驱动程序中发现更多漏洞。Kernel Streaming 仍然是一个引人入胜的研究目标，其表面之下可能还隐藏着许多未被发现的漏洞。  
  
深入了解 Windows API 的实现——并认识到其误用的风险——对于发现新漏洞和构建有效的利用技术至关重要。  
> 记住这些模式——它可能是你的下一个漏洞。  
  
## 参考  
- 使用 MDLs  
  
- Windows 内核安全 - Pwn2Own 演示的两个漏洞的深入分析  
  
- CVE-2023-29360 分析  
  
- 简单的本地 Windows 内核利用  
  
## Resources  
  
<table><thead><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><th style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;font-weight: bold;background-color: #f0f0f0;min-width: 85px;"><section><span leaf="">Hyperlink</span></section></th><th style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;font-weight: bold;background-color: #f0f0f0;min-width: 85px;"><section><span leaf="">Info</span></section></th></tr></thead><tbody><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">https://devco.re/blog/2025/05/17/frame-by-frame-kernel-streaming-keeps-giving-vulnerabilities-en/</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">Angelboy</span></section></td></tr></tbody></table>  
  

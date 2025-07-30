#  Windows驱动程序暴整数溢出漏洞可致权限提升   
 计算机与网络安全   2024-11-30 01:57  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5OTk4MDE2MA==&mid=2655258303&idx=1&sn=4d377c24c73e9ba8409a738277dfe59d&chksm=bc839b508bf4124687c99bd20724b623e26fad9cc3452dc559afefba3a92e8aa5822cefa9b4f&scene=21#wechat_redirect)  
  
进网络安全行业群  
  
微信公众号 **计算机与网络安全**  
  
回复   
**行业群**  
  
  
一名独立研究员近期发现了Windows操作系统中ksthunk.sys驱动程序的严重漏洞，该驱动程序负责32位与64位进程间的通信，此漏洞允许攻击者通过整数溢出实现权限提升。该研究员近日在TyphoonPWN 2024大赛中演示了该漏洞的利用，斩获大赛第二名。  
  
  
该漏洞存在于  
  
CKSAutomationThunk::ThunkEnableEventIrp函数中，该函数用于在内核中分配缓冲区以处理输入和输出数据。然而，由于在缓冲区大小对齐计算时缺乏整数溢出的验证，导致分配的缓冲区尺寸不正确，进而触发堆内存溢出。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb59WoxddDT09tshuu9wz6Wabo6qIwR3ROktdwrdXiaSBTTcoNicWiaVibL8E9JP7Q8gJIzUN4N9XIWy7A/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
漏洞代码关键点如下：  
```
// Only Called when the calling process is 32bit.
__int64 __fastcall CKSAutomationThunk::ThunkEnableEventIrp(__int64 a1, PIRP a2, __int64 a3, int * a4) {
        ...
        inbuflen = CurrentStackLocation -> Parameters.DeviceIoControl.InputBufferLength;
        outbuflen = CurrentStackLocation -> Parameters.DeviceIoControl.OutputBufferLength;
        // [1]. Align the length of output buffer
        outlen_adjust = (outbuflen + 0x17) & 0xFFFFFFF8;
        if (a2 -> AssociatedIrp.MasterIrp)
            return 1 i64;

        if ((unsigned int) inbuflen < 0x18)
            ExRaiseStatus(-1073741306);

        ProbeForRead(CurrentStackLocation -> Parameters.DeviceIoControl.Type3InputBuffer, inbuflen, 1 u);
        if (( * ((_DWORD * ) CurrentStackLocation -> Parameters.DeviceIoControl.Type3InputBuffer + 5) & 0xEFFFFFFF) == 1 ||
            ( * ((_DWORD * ) CurrentStackLocation -> Parameters.DeviceIoControl.Type3InputBuffer + 5) & 0xEFFFFFFF) == 2 ||
            ( * ((_DWORD * ) CurrentStackLocation -> Parameters.DeviceIoControl.Type3InputBuffer + 5) & 0xEFFFFFFF) == 4) {
            // [2]. Validate the Length
            if ((unsigned int) outbuflen < 0x10)
                ExRaiseStatus(-1073741306);
            if (outlen_adjust < (int) outbuflen + 16 || outlen_adjust + (unsigned int) inbuflen < outlen_adjust)
                ExRaiseStatus(-1073741306);

            // [3]. Allocate the buffer to store the data
            // 0x61 == POOL_FLAG_USE_QUOTA | POOL_FLAG_RAISE_ON_FAILURE POOL_FLAG_NON_PAGED
            a2 -> AssociatedIrp.MasterIrp = (struct _IRP * ) ExAllocatePool2(
                0x61 i64,
                outlen_adjust + (unsigned int) inbuflen,
                1886409547 i64);
            a2 -> Flags |= 0x30 u;
            ProbeForRead(a2 -> UserBuffer, outbuflen, 1 u); // [*] 
            data = (__int64) a2 -> AssociatedIrp.MasterIrp;
            ...
            // [4]. Copy the Data
            if ((unsigned int) outbuflen > 0x10)
                memmove((void * )(data + 0x20), (char * ) a2 -> UserBuffer + 16, outbuflen - 16);
            memmove(
                (char * ) a2 -> AssociatedIrp.MasterIrp + outlen_adjust,
                CurrentStackLocation -> Parameters.FileSystemControl.Type3InputBuffer,
                inbuflen);
            ...
        }
```  
  
  
SSD Secure Disclosure技术团队指出：  
  
  
在代码片段[1]处，outlen_adjust的计算缺乏整数溢出验证，这可能导致分配过小的缓冲区。  
  
  
在[4]处，当数据被复制到不正确的内存位置时，会触发堆内存溢出，最终导致内核内存损坏并允许进一步利用。  
  
  
研究员展示了一种详细的利用方法，通过以下步骤实现权限提升：  
  
  
内存操控：在内核非分页池中创建间隔，以便利用溢出攻击命名管道对象。  
  
任意内存访问：通过破坏邻近内存对象（如命名管道），获取任意读写权限。  
  
令牌覆盖：修改当前进程的令牌，将权限提升为SYSTEM，从而完全控制目标机器。  
  
  
微软已收到该漏洞的通知，但回应称这是一个已经被修复的重复问题。然而，研究员在Windows 11 23H2中发现漏洞仍可利用。至今，微软尚未分配CVE编号，也未提供详细的修复信息。  
  
  
内核级漏洞的存在为高级威胁行为者提供了便捷的攻击途径。该漏洞通过对分配缓冲区大小的精确操控，加上容易利用的内存破坏特性，攻击难度相对较低，适合作为后续攻击链中的关键环节。  
  
  
专家建议，开发者在内核代码中应严格执行整数溢出的验证，特别是在内存分配和使用时，确保分配大小的安全性。系统管理员则需限制驱动访问，仅允许经过验证的驱动加载，以减少潜在的攻击面。此外，企业和个人用户应部署安全工具实时监控内核异常行为，并及时应用系统更新和补丁，以最大程度降低漏洞被利用的风险。面对权限提升漏洞的威胁，这些防护措施将是保护系统安全的关键环节。  
  
  
更多技术细节及漏洞利用的PoC代码可参见SSD Secure Disclosure的官方公告。  
  
  
**|**  
 来源：安全客  
  

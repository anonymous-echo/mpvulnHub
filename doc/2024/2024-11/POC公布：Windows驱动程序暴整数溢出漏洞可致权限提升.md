#  POC公布：Windows驱动程序暴整数溢出漏洞可致权限提升   
 安全客   2024-11-29 10:32  
  
一名独立研究员近期发现了Windows操作系统中ksthunk.sys驱动程序的严重漏洞，该驱动程序负责32位与64位进程间的通信，此漏洞允许攻击者通过整数溢出实现权限提升。该研究员近日在TyphoonPWN 2024大赛中演示了该漏洞的利用，斩获大赛第二名。  
  
  
该漏洞存在于  
  
CKSAutomationThunk::ThunkEnableEventIrp函数中，该函数用于在内核中分配缓冲区以处理输入和输出数据。然而，由于在缓冲区大小对齐计算时缺乏整数溢出的验证，导致分配的缓冲区尺寸不正确，进而触发堆内存溢出。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb59WoxddDT09tshuu9wz6Wabo6qIwR3ROktdwrdXiaSBTTcoNicWiaVibL8E9JP7Q8gJIzUN4N9XIWy7A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
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
  
  
文章参考：  
  
https://securityonline.info/integer-overflow-vulnerability-in-windows-driver-enables-privilege-escalation-poc-published/  
  
  
**推荐阅读**  
  
  
  
  
  
<table><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:17.classicTable1:0"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:17.classicTable1:0.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>01</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787474&amp;idx=1&amp;sn=849c75157b64bc5027ef6186f490c805&amp;scene=21#wechat_redirect" textvalue="星巴克遭供应链攻击被迫回归纸笔时代" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2"><span style="font-size: 12px;">星巴克遭供应链攻击被迫回归纸笔时代</span></a><span style="font-size: 12px;"></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:17.classicTable1:1"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:17.classicTable1:1.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>02</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><span style="font-size: 12px;"><a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787467&amp;idx=1&amp;sn=a415a569eadfb841c7db9ab18a3b9dee&amp;scene=21#wechat_redirect" textvalue="财富1000强企业的API暴露风险与漏洞挑战" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2" style="outline: 0px;color: var(--weui-LINK);cursor: default;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;letter-spacing: 1px;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;">财富1000强企业的API暴露风险与漏洞挑战</span></a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:17.classicTable1:2"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:17.classicTable1:2.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>03</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><span style="font-size: 12px;"><a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787441&amp;idx=1&amp;sn=dbc4fcc0a87e9e439ff0c365baac33ec&amp;scene=21#wechat_redirect" textvalue="合法安全驱动程序武器化" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2" style="outline: 0px;color: var(--weui-LINK);cursor: default;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;letter-spacing: 1px;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;">合法安全驱动程序武器化</span></a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb59WoxddDT09tshuu9wz6WauWhEbgUONSMsCMEJcVwumvp8Fr0kABgVSdPw3wdLCOTibr73Ev6RBaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb59WoxddDT09tshuu9wz6WaUSoiczqXTnbrN6eH4YKfia7QCeoQv9WRCgI6ScwKbHG3leDdXzvkbjug/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  

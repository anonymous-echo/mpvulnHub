#  Realtek爆出关键漏洞，影响多款网络设备   
 关键基础设施安全应急响应中心   2022-08-18 14:39  
  
Bleeping Computer 网站披露，Realtek 爆出严重漏洞，该漏洞影响到数百万台采用 Realtek RTL819x 系统芯片(SoC)的网络设备。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibgrsTb0b4AEztZe0X5ZMacOn1mU1F8OmAE3xoj3hia6HwmPpv2wXDxlb2cIic0zKSycv5bSRrkztxA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
该漏洞被追踪为 CVE-2022-27255，远程攻击者可以利用其破坏来自各种原始设备制造商 (OEM) 的易受攻击设备。  
  
**无需身份验证**  
##   
  
据悉，CVE-2022-27255 漏洞由阿根廷网络安全公司 Faraday Security 的研究人员在 Realtek 的开源 eCos 操作系统 SDK 中发现，并在 DEFCON 黑客大会上披露了详细的技术细节。  
  
CVE-2022-27255是一个基于堆栈的缓冲区溢出漏洞，其严重程度为 9.8 分(满分10分)，远程攻击者可以使用带有恶意 SDP 数据的特制 SIP 数据包任意执行代码，这个过程完全无需身份验证。此外，攻击者还可以通过 WAN 接口利用漏洞。  
  
早在 3 月份，Realtek 已经解决这一漏洞问题，并指出了漏洞主要影响rtl819x-eCos-v0.x 系列和 rtl819x-eCos-v1.x 系列产品。  
  
来自 Faraday Security 的四位研究人员为 CVE-2022-27255 开发了概念验证(PoC)利用代码，该代码可用于 Nexxt Nebula 300 Plus 路由器。研究人员还分享了一段视频，展示了即使远程管理功能被关闭，远程攻击者也可能破坏设备。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibgrsTb0b4AEztZe0X5ZMacy1ibYz7VG719txKicp7giaXtxUyvoueJkfj27sOEmXJb3CKN1h0mxNNsQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**视频链接：**  
  
https://vimeo.com/740134624?embedded=true&source=video_title&owner=52361365  
  
最后，研究人员指出攻击者利只需有漏洞设备的外部 IP 地址，就可以 利用CVE-2022-27255 漏洞，意味着不需要与用户交互。  
  
注：发现漏洞的四名研究人员分别是来自布宜诺斯艾利斯大学的计算机科学学生Octavio Gianatiempo, Octavio Galland, Emilio Couto, Javier Aguinaga。  
  
**存在几道防线**  
  
SANS 研究部主任 Johannes Ullrich 表示，远程攻击者可以利用 CVE-2022-27255 漏洞进行以下操作：  
> 导致设备崩溃  
> 执行任意代码  
> 建立持久性的后门  
> 改变网络流量的路线  
> 拦截网络流量  
  
  
另外，尽管 Realtek 在3 月已经发布了一个补丁，但 Ullrich 强调该漏洞影响到数百万设备，修复补丁很难被推广到所有待修复的设备，如果 CVE-2022-27255 漏洞变成了蠕虫病毒，可以在短短几分钟内扩散到互联网上。  
  
多家供应商将易受攻击的 Realtek SDK 用于基于 RTL819x SoC 的设备，其中许多供应商尚未发布固件更新。目前还不清楚有多少网络设备使用 RTL819x 芯片，但 RTL819xD 版本的 SoC 出现在 60 多个供应商的产品中，其中包括华硕、贝尔金、Buffalo、D-Link、Edimax、TRENDnet 和 Zyxel。  
  
研究人员的观点：  
> 使用 2022 年 3 月之前围绕 Realtek eCOS SDK 构建的固件的设备存在漏洞，易受攻击；  
> 即使用户不暴露任何管理界面功能，也容易受到攻击；  
> 攻击者可以使用单个 UDP 数据包到任意端口来利用该漏洞；  
> 此漏洞可能对路由器影响最大，但一些基于 Realtek SDK 的物联网设备也可能受到影响。  
  
  
安全专家建议用户应尽快检查其网络设备是否存在漏洞，一经发现，应立即安装供应商发布的固件更新。除此以外，企业可以尝试阻止未经请求的 UDP 请求。  
  
**参考链接：**  
  
  
https://www.bleepingcomputer.com/news/security/exploit-out-for-critical-realtek-flaw-affecting-many-networking-devices/  
  
  
  
原文来源  
：FreeBuf  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  

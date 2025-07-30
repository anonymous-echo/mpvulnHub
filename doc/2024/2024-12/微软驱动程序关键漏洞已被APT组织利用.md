#  微软驱动程序关键漏洞已被APT组织利用   
老布  FreeBuf   2024-12-04 11:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibkORq5ywCEzeVImYWSYHCJfkkRiaIWO9NWia8icd1qArZtgEiby1WURK19k6GlaaOsSWQqUWIWelhcOA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
近日，微软被曝Windows AFD.sys漏洞（编号：CVE-2024-38193）正在被黑客组织利用。该漏洞被归类为自带易受攻击驱动程序（BYOVD）漏洞，可影响Windows套接字的注册I/O（RIO）扩展，并允许攻击者远程接管整个系统。  
  
  
漏洞影响版本包括Windows 11（ARM64、x64，多个版本）、Windows 10（ARM64、x64、32位，多个版本）、Windows Server 2008、2012、2016、2019、2022（多个版本）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibkORq5ywCEzeVImYWSYHCJiaUpyluhl5G4FMq4nN4STkUzvgpjZRKksdaP0gMqv9TLibU0XIs9qUug/640?wx_fmt=jpeg&from=appmsg "")  
  
  
目前，已有迹象表明黑客组织正在利用该漏洞发起攻击，例如朝鲜黑客组织Lazarus就是其中之一，其安装名为FUDModule的根工具包（rootkit），可在目标系统上获得最高权限。2024年8月，微软发布安全更新已经修复该漏洞，强烈建议组织及时进行修复。  
##   
  
**漏洞概述**  
  
  
## 漏洞成因  
  
  
CVE-2024-38193漏洞存在于Windows辅助功能驱动程序（AFD.sys）中。AFD.sys是Winsock协议栈的关键组件之一，处理底层网络调用，并在内核模式下执行操作。漏洞的根本原因是AFD.sys在处理特定系统调用时缺乏适当的边界检查，导致攻击者可以构造恶意输入，触发内存溢出或其他未定义行为，从而绕过安全检查，提升权限。由于AFD.sys在所有Windows系统中广泛部署，这使得该漏洞特别危险。  
###   
### 漏洞利用过程  
  
****  
**漏洞触发**  
  
攻击者首先通过恶意应用程序或远程代码执行方式，向AFD.sys驱动程序发送恶意构造的系统调用请求。通过精心构造的输入，攻击者可以让AFD.sys在内核模式下执行越权操作。  
  
这种攻击方式利用了Windows内核的漏洞，能够在用户态和内核态之间绕过安全边界，执行未授权的操作。  
  
****  
**权限提升**  
  
一旦漏洞触发，攻击者可以利用漏洞执行任意代码，并获得SYSTEM权限。通过这种方式，攻击者能够完全控制受影响的设备，部署恶意软件或修改系统配置。获得SYSTEM权限后，攻击者可以执行一系列高级操作，包括禁用安全软件、修改系统文件和执行其他恶意活动。  
  
****  
**FUDModule根工具包的安装**  
  
获得SYSTEM权限后，攻击者会安装FUDModule根工具包。FUDModule是一种专门设计用于隐藏攻击痕迹、绕过安全监控的复杂恶意软件。通过关闭Windows的监控功能，FUDModule可以让攻击者在受害者系统中保持长期隐蔽。FUDModule的存在使得攻击者能够在不被发现的情况下持续控制目标系统，增加了防御的难度。  
##   
  
**修复建议**  
  
  
## 微软已经发布了针对CVE-2024-38193的安全补丁，覆盖了多个Windows版本。建议所有用户和组织尽快应用补丁，避免系统遭到利用。及时应用补丁是防止漏洞利用的最有效手段之一，用户应确保系统和应用程序都安装了最新的安全更新。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
> https://cybersecuritynews.com/windows-driver-use-after-free-vulnerability/  
  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651308240&idx=1&sn=96d32c8e6fa90561c84164ed75f4dca0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21&token=734903441&lang=zh_CN#wechat_redirect)  
  

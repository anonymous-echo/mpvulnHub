#  利用Windows漏洞，攻击者能降级系统组件恢复漏洞   
Zicheng  FreeBuf   2024-10-28 21:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
据Hackread消息，在最近的一项研究中，SafeBreach Labs 研究员揭露了一种新的攻击技术，能够操纵Windows 11系统在更新时降级关键系统组件，从而让一些漏洞修复补丁失效。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39SSBibMdY1f8LYyuJgCOBpjdSwK9l1go4ZGBaImjEBeNQxaPaib6AxFPtQ6TX7KUq9icOVeO2wUibvGg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该攻击原理最初于  
2024 年 8 月在Black Hat USA 2024上披露，而现在研究人员公布了更多细节，以加强公众对这次攻击的了解。  
  
  
这种被称为 Windows Downdate 的技术利用的其中一个漏洞是“ItsNotASecurityBoundary”驱动程序签名强制 （DSE） 绕过，能允许攻击者加载未签名的内核驱动程序，将经过验证的安全目录替换为恶意版本，从而能够加载未签名的内核驱动程序。  
  
  
比如，攻击者可以针对特定组件，例如解析安全目录所必需的“ci.dll”模块，并将它们降级到易受攻击的状态，从而能够利用此绕过并获得内核级权限。  
  
  
“ItsNotASecurityBoundary”DSE 绕过是一类名为“虚假文件不变性”（FFI）的新漏洞的一部分，利用了关于文件不可变性的错误假设，允许通过清除系统工作集来修改“不可变”文件。  
  
  
研究人员概述了在具有不同级别虚拟化安全（VBS）保护的 Windows 系统中可利用漏洞的步骤，发现了多种禁用 VBS 关键功能的方法，包括凭证防护和受管理程序保护的代码完整性（HVCI）等功能，甚至首次使用了 UEFI 锁。  
  
  
要利用没有 UEFI 锁的系统，攻击者必须通过修改注册表设置来禁用 VBS。一旦禁用，就可以将 ci.dll 模块降级到易受攻击的版本，并利用“ItsNotASecurityBoundary”漏洞。对带有 UEFI 锁和 "强制（Mandatory ）"标志的 VBS 是最安全的配置，即使锁被绕过，VBS 也不会被禁用。研究人员解释说，目前还没有已知的方法可以在没有物理访问的情况下利用具有这种保护级别的系统。  
  
  
总体而言，这种 Windows 更新接管功能允许攻击者加载未签名的内核驱动程序、启用自定义 rootkit 以解除安全控制、隐藏进程并保持隐蔽性，从而对企业构成了重大威胁。攻击者可以对关键操作系统组件（包括 DLL、驱动程序甚至 NT 内核）进行自定义降级。通过对这些组件进行降级，攻击者可以暴露以前修补过的漏洞，使系统容易被利用。  
  
  
为降低风险，企业应及时更新系统，打上最新的安全补丁，以解决漏洞问题，同时部署有效的端点检测和响应（EDR）解决方案，以检测和响应恶意活动，防止未经授权的访问和数据泄露。此外，使用 UEFI 锁定和 "强制 "标志启用 VBS 还能提供额外的保护。  
  
  
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
> https://hackread.com/hackers-downgrade-windows-exploit-patched-flaws/  
  
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
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

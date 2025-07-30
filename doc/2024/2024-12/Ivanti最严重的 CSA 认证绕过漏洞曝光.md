#  Ivanti最严重的 CSA 认证绕过漏洞曝光   
老布  FreeBuf   2024-12-11 12:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
12月11日，Ivanti 向客户发出警告，提醒其 Cloud Services Appliance (CSA)解决方案存在一个新的最高严重性的认证绕过漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibNpMuyUxR44GDNiceiau7eTsyCQjXiczqgQMdn4YXC6JBneOq5b0CROx9Vkdp0hQFgiaMAjx3TF545XA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这个安全漏洞（编号 CVE-2024-11639）能够使远程攻击者在运行 Ivanti CSA 5.0.2 或更早版本的易受攻击设备上获得管理员权限，而无需进行身份验证或用户交互，通过绕过认证，使用替代路径或通道。Ivanti 建议管理员根据提供的详细信息将易受攻击的设备升级到 CSA 5.0.3，详细信息可以在支持文档中找到。  
  
  
“我们目前尚未了解到在公开披露之前有任何客户受到这些漏洞的利用。这些漏洞是通过我们的负责任披露计划公开披露的。”  
  
  
Ivanti 今天还修补了 Desktop and Server Management (DSM)，Connect Secure and Policy Secure，Sentry 和Patch SDK 产品中的其他中等、高等和关键性漏洞。然而，正如周二发布的安全通告中所指出的，目前没有证据表明这些漏洞在野外被利用。  
  
  
CVE-2024-11639 是近几个月中修补的第六个 CSA 安全漏洞，之前的五个漏洞分别是：  
  
  
九月：CVE-2024-8190（远程代码执行）九月：CVE-2024-8963（管理员身份验证绕过）十月：CVE-2024-9379 、CVE-2024-9380 、CVE-2024-9381（SQL 注入、操作系统命令注入、路径遍历）  
  
  
在九月份，该公司还警告客户，CVE-2024-8190 和CVE-2024-8963 漏洞已经成为攻击目标。  
  
  
此外，它还提醒管理员，十月份修复的三个安全漏洞与 CVE-2024-8963 CSA 管理员绕过漏洞相结合，通过 SQL 注入运行 SQL 语句，绕过安全限制，并通过命令注入执行任意代码。  
  
  
这些被积极利用的漏洞连续出现，与此同时，Ivanti 表示，它正在加强测试和内部扫描能力，并改进其负责任披露流程，以更快地修复安全漏洞。  
  
  
今年早些时候，还有其他几个漏洞在广泛的攻击中作为零日漏洞被利用，攻击目标包括 Ivanti VPN 设备以及 ICS 、IPS 和ZTA 网关。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://www.bleepingcomputer.com/news/security/ivanti-warns-of-maximum-severity-csa-auth-bypass-vulnerability/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651308240&idx=1&sn=96d32c8e6fa90561c84164ed75f4dca0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

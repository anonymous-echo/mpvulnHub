#  官方强烈建议更新，关键漏洞影响GitHub Enterprise Server所有版本   
疯狂冰淇淋  FreeBuf   2024-08-24 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ic7NjnErCpyg76mFrm9yeNqLTCEgMaia3b7TMicZ68pbctl6k2jyf8jmXpBwdIXmrWKdHSLQpltSKBQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ic7NjnErCpyg76mFrm9yeNqZFz2BrhG6ePoDVkib2ibpfNIHwWiaQiadLxsMQ9RsjIFAldtCbSCLuj72g/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JcHHibmVqZbkgb4BbYvtCfRS2uGDIUgcmUHIjAz29TUNZIibLm2O56daMe4Y1KZ8q8cFI2Fez2bfiaJ/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JcHHibmVqZbkgb4BbYvtCfRS2uGDIUgcmUHIjAz29TUNZIibLm2O56daMe4Y1KZ8q8cFI2Fez2bfiaJ/640?wx_fmt=svg&from=appmsg "")  
  
  
  
近日，GitHub Bug Bounty 计划报告了一个影响 GitHub Enterprise Server（GHES）当前所有支持版本的关键漏洞（CVE-2024-6800），该漏洞可能允许攻击者获得对该实例内容的无限制访问。目前，漏洞已经解决，强烈建议管理员尽快更新，以确保系统安全。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic7NjnErCpyg76mFrm9yeNqB7dPhUwrg0BBUbfRibI5ccAecXBG6CTJNVia5JNHZ2XriacctymJnrjlg/640?wx_fmt=png&from=appmsg "")  
  
  
**关于 CVE-2024-6800**  
  
##   
  
GitHub Enterprise Server 是一个自托管的软件开发平台，通常是为了遵守需要对代码仓库有更多控制/安全性的特定法规。  
  
  
它以自包含的虚拟设备形式出现，安装在虚拟机上，运行 Linux 操作系统并配备自定义的应用程序堆栈。  
  
  
根据软件的发布说明，CVE-2024-6800 是一个 XML 签名包装漏洞，允许攻击者绕过身份验证，但只有在实例使用 SAML 单点登录（SSO）认证，并且与使用公开暴露的签名联合元数据 XML 的特定身份提供者结合。  
  
  
该漏洞允许具有对 GitHub Enterprise Server 直接网络访问权限的攻击者伪造 SAML 响应，以配置和/或获得具有站点管理员权限的用户访问。  
  
  
**安全更新建议**  
  
###   
  
建议在自己的基础设施上运行 GitHub Enterprise Server 实例并使用 SAML SSO 认证的组织升级到以下已修复的 GHES 版本之一：  
  
- 3.13.3  
  
- 3.12.8  
  
- 3.11.14  
  
- 3.10.16  
  
对于仍在使用 3.10 版本的企业，建议尽快升级到更新的版本，因为 3.10 版本将于 2024 年 8 月 29 日停止服务，届时将不再提供补丁或安全修复。  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://www.helpnetsecurity.com/2024/08/22/cve-2024-6800/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494753&idx=1&sn=a9ee1d680adf601e9ee212fc3841387f&chksm=ce1f16fef9689fe8ad2926bc3739025b04955e5c29fee949f44be9fe8262d8723110eb50b6b9&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494714&idx=1&sn=fe28fee45c1508a1645fd04c2b18ca82&chksm=ce1f16a5f9689fb3996529f7738a1b7dc3960f3fc5bd31c7d1505dbd3a179d5b3bfd6c66e5f3&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

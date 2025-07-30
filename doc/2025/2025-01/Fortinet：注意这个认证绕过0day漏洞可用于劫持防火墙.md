#  Fortinet：注意这个认证绕过0day漏洞可用于劫持防火墙   
Sergiu Gatlan  代码卫士   2025-01-15 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT6Mic1A719M4IWuW5MAaC06UibVULkfQcJ3cKXkjgZH2xNPOFUDib91WxNdGeNo1NfSRm8US6w3Yjjw/640?wx_fmt=gif&from=appmsg "")  
  
  
**攻击者正在利用位于 FortiOS和FortiProxy 中的一个认证绕过0day漏洞，劫持Fortinet 防火墙并攻陷企业网络。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT6Mic1A719M4IWuW5MAaC06UibVULkfQcJ3cKXkjgZH2xNPOFUDib91WxNdGeNo1NfSRm8US6w3Yjjw/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞的编号是CVE-2024-55591，影响 FortiOS 7.0.0至7.0.16、FortiProxy 7.0.0至7.0.19以及FortiProxy 7.2.0至7.2.12版本。成功利用该漏洞可导致远程攻击者向 Node.js 网络套接字模块发送恶意请求，获得超级管理员权限。  
  
Fortinet 公司表示，攻击者在野利用该0day漏洞，在受陷设备上创建随机生成的管理员或本地用户，并将他们增加到现有的SSL VPN用户群组或新增群组。攻击者还增加或修改防火墙策略和其它设置并通过此前创建的恶意账户登录到SSLVPN，“获得对内网的隧道”。  
  
虽然Fortinet 公司并未提供更多攻击详情，但网络安全公司 Arctic Wolf 在上周五发布包含IoC的报告提到，具有暴露到互联网的管理接口的Fortinet FortiGate 防火墙自11月中旬起就遭攻击。  
  
Arctic Wolf 实验室表示，“该攻击涉及越权管理员登录防火墙管理界面、创建新账户、通过这些账户进行SSL VPN认证以及其它配置变更。虽然初始访问向量并未确切证实，但很可能存在一个0day漏洞。组织机构应当尽快紧急禁用公开界面上的防火墙管理访问权限。”  
  
Fortinet 公司还在今天发布的安全公告中建议管理员禁用 HTTP/HTTPS 管理员界面，或者限制通过本地策略访问管理员界面的IP地址，缓解该漏洞。  
  
Arctic Wolf 公司还提供了该漏洞的大规模利用时间线，表示涉及四个阶段：  
  
1、漏洞扫描（2024年11月16日至11月23日）  
  
2、侦查（2024年11月22日至11月27日）  
  
3、SSL VPN配置（2024年12月4日至12月7日）  
  
4、横向移动（2024年12月16日至12月27日）  
  
Fortinet 公司提到，“虽然该攻击活动中所用的初始访问向量尚未得到证实，但Arctic Wolf Labs从受影响组织机构的时间线以及受影响固件版本来看，有较高把握认为该大规模攻击活动利用了一个0day漏洞。鉴于入侵活动之间的技术和基础设施之间存在细微不同，很可能多个个人或组织涉及其中，但他们通用jsconsole。”  
  
Fortinet公司和Arctic Wolf公司共享了几乎一致的 IOCs，表示用户可从日志中查看相关信息，判断设备是否受影响。登录后，日志会显示一个随机的来源IP和目的地IP。威胁行动者创建管理员用户后，将会随机生成用户名和来源IP地址，从而生成日志。Fortinet还提醒称攻击者通常会使用一些特定的IP地址。  
  
Arctic Wolf 公司表示已在2024年12月12日将攻击活动告知 Fortinet 公司，并在12月17日收到确认信息称该活动是已知活动且已经启动调查程序。  
  
今天，Fortinet 公司还发布了一个严重的硬编码密钥漏洞 (CVE-2023-37936)的安全补丁。该漏洞可导致拥有该密钥的远程未认证攻击者通过构造的加密请求运行越权代码。  
  
今年10月，Mandiant 公司披露了被称为 “FortiJump”（CVE-2024-47575）的FortiManager 漏洞自6月起就被以0day状态利用，攻陷50多台服务器。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Fortinet：注意FortiWLM漏洞，黑客可获得管理员权限](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521859&idx=1&sn=6aade83438190800942638166b046757&scene=21#wechat_redirect)  
  
  
[黑客称窃取 440GB 文件，Fortinet 证实数据遭泄露](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520799&idx=2&sn=d02acbabe690ef64658cea5df0e53131&scene=21#wechat_redirect)  
  
  
[Fortinet 修复 FortiOS 中的代码执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519734&idx=2&sn=e2956d27d020b75520e84dc6e02b483a&scene=21#wechat_redirect)  
  
  
[Fortinet 修复严重的 FortiClientLinux 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519274&idx=1&sn=0db6fdb46bf03ada98af3901110ee37b&scene=21#wechat_redirect)  
  
  
[Fortinet 提醒注意端点管理软件中的严重RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519060&idx=1&sn=bd31e9a884e83396402ed8ca25c23ecd&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-aviatrix-controller-rce-flaw-in-attacks/  
  
  
题图：  
Pexels   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

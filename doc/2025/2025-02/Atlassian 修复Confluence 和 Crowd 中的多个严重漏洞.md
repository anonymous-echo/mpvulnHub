#  Atlassian 修复Confluence 和 Crowd 中的多个严重漏洞   
Ionut Arghire  代码卫士   2025-02-21 10:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周，Atlassian 修复了位于 Bamboo、Bitbucket、Confluence、Crowd和Jira产品中的12个严重和高危漏洞。**  
  
  
该公司修复了位于Confluence Data Center and Server 和 Crowd Data Center and Server 中的五个严重漏洞，它们位于这两款产品使用的第三方依赖中。  
  
Confluence Data Center and Server 更新修复了位于 Apache Tomcat 中的两个严重漏洞CVE-2024-50379和CVE-2024-56337（CVSS评分9.8），它们可被未认证攻击者用于实现远程代码执行。  
  
Crowd Data Center and Server 中也修复了这两个漏洞。Apache Tomcat 中也修复了另外一个漏洞CVE-2024-52316（CVSS评分9.8），它可被未认证攻击者利用，导致认证绕过后果。  
  
Crowd 更新还修复了位于 ua-parser-js中的一个高危拒绝服务漏洞CVE-2022-25927。  
  
该公司还修复了位于 Bamboo Data Center and Server 中的两个高危DoS 漏洞，影响 Protocol Buffers (CVE-2024-7254) 和 XStream 库 (CVE-2024-47072)。另外该公司还修复了位于 Bitbucket Data Center and Server 中的一个高危漏洞 (CVE-2024-47561)，影响 Apache Avro 的 Java SDK。位于 Protocol Buffers 中的 DoS 漏洞也在 Jira Data Center and Server 中修复。  
  
Atlassian 公司并未提到这些漏洞是否已在其产品中遭利用，督促客户尽快更新。该公司提到，“要修复影响产品的所有漏洞，Atlassian 建议将实例更新至产品的最新版本或已修复版本。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Atlassian Bamboo Data Center and Server中存在RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520541&idx=1&sn=f403f1139228e0543f485dc49192281e&scene=21#wechat_redirect)  
  
  
[Atlassian 修复Confluence等产品中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520092&idx=2&sn=cc02ff9f6ef98e6d539f13b4c6c892c2&scene=21#wechat_redirect)  
  
  
[Atlassian Confluence 高危漏洞可导致代码执行](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519665&idx=2&sn=86259d3f96b173403f1a65b601fc1989&scene=21#wechat_redirect)  
  
  
[Atlassian 发布20多个漏洞，含严重的 Bamboo 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519117&idx=2&sn=c0c8035f5617c6f76c73e71b9e73f04f&scene=21#wechat_redirect)  
  
  
[Atlassian Confluence 远程代码执行漏洞(CVE-2023-22527)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518678&idx=1&sn=aedf682361f621f14474e78244d3242e&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/atlassian-patches-critical-vulnerabilities-in-confluence-crowd/  
  
  
题图：  
Pixabay   
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
  

#  Atlassian 和思科修复多个高危漏洞   
Ionut Arghire  代码卫士   2025-04-18 09:49  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周，Atlassian 和思科宣布修复多个高危漏洞，其中一些可导致远程代码执行后果。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTWEibOWyGpxJTM5MvVAXwIN2Wz1icd0NcEH1ia7oictLQb6jMKF4maLVkfeWYHHAzlB6VGy6WnL972SQ/640?wx_fmt=png&from=appmsg "")  
  
  
Atlassian 发布了7份更新，修复了影响 Bamboo、Confluence和 Jira 中第三方依赖的四个高危漏洞，其中一些漏洞早在近六年前就已披露。  
  
Netplex Json-smart 中存在一个拒绝服务漏洞，可在无需认证的情况下遭利用，已在 Bamboo Data Center and Server、Jira Data Center and Server 和 Jira Service Management Data Center and Server 中修复，该漏洞的编号是CVE-2025-57699。  
  
Jira 和 Jira Service Management 的安全更新还修复了可导致拒绝服务条件的XXE漏洞CVE-2021-33813。  
  
Confluence Data Center and Server 还修复了两个漏洞，其中一个是位于 Netty 应用框架中的 DoS 漏洞CVE-2025-24970，另外一个是位于 libjackson-json-java 库中的XXE漏洞CVE-2019-10172。  
  
Atlassian 公司并未说明这些漏洞是否已遭在野利用。  
  
本周三，思科也修复了位于 Webex App、Secure Network Analytics 和 Nexus Dashboard 中的三个漏洞。Webex App 修复了一个高危漏洞CVE-2025-20236，它可导致攻击者通过说服用户点击构造的会议邀请链接，远程执行任意代码并下载任意文件。  
  
Secure Network Analytics 7.5.0、7.5.1和7.5.2修复了一个中危漏洞，可导致认证攻击者通过 root 权限提取 shell 访问权限。思科还修复了Nexus Dashboard 中的一个中危漏洞，它可导致未认证的远程攻击者判断有效的LDAP 用户账号的用户名。  
  
思科表示尚未发现这些漏洞遭在野利用的迹象。该公司在安全公告页面分享了更多信息。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Atlassian 修复Confluence 和 Crowd 中的多个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522309&idx=2&sn=75d35854eb171a70fb22bd76ed1b2cf4&scene=21#wechat_redirect)  
  
  
[Atlassian Bamboo Data Center and Server中存在RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520541&idx=1&sn=f403f1139228e0543f485dc49192281e&scene=21#wechat_redirect)  
  
  
[Atlassian 修复Confluence等产品中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520092&idx=2&sn=cc02ff9f6ef98e6d539f13b4c6c892c2&scene=21#wechat_redirect)  
  
  
[思科智能许可证实用程序中的严重漏洞已遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522568&idx=2&sn=ec34401dbcb58be493c11352d5815bb6&scene=21#wechat_redirect)  
  
  
[CISA 提醒注意已遭利用的 Windows 和思科漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522399&idx=1&sn=f2a16f697c5c7d7824f2f78d5b4b6148&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/apple-fixes-two-zero-days-exploited-in-targeted-iphone-attacks/  
  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

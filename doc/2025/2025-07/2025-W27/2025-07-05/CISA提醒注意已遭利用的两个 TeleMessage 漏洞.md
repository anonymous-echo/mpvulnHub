> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523450&idx=2&sn=6fb767fa5ebe3a22a7b0a961be3c6df2

#  CISA提醒注意已遭利用的两个 TeleMessage 漏洞  
Ionut Arghire  代码卫士   2025-07-04 10:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**CISA 提醒注意位于消息应用 TeleMessage TM SGNL 中的两个漏洞，督促组织机构立即修复。**  
  
TeleMessage TM SGNL 应用可帮助用户归档通过 WhatsApp、Telegram和 Signal发送的消息，在特朗普政府前国家安全顾问 Mike Waltz 被看到在手机上使用后变得流行起来。之后，几十个政府员工被指也在使用该应用。  
  
不久之后，位于美国俄勒冈的通信公司 Smarsh（以色列公司 TeleMessage 的所有方）因为黑客演示了该应用缺乏加密而可被盗取聊天日志后暂停了所有 TeleMessage 服务。该漏洞是CVE-2025-47729（CVSS评分4.9），在5月中旬被CISA列入必修清单 KEV。  
  
当前，CISA表示 TeleMessage 服务中的另外两个漏洞CVE-2025-48927和CVE-2025-48928已遭黑客利用。NIST 发布安全公告提到，第一个漏洞存在的原因是监控工具 Spring Boot Actuator 被配置为一个被暴露的堆转储端点。NIST 解释称，第二个漏洞是因为TeleMessage 服务“基于一款JSP 应用，而其中堆内容几乎等同于一个‘核心转储’，之前通过 HTTP 发送的密码将被包含在该转储中。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA 提醒注意 Microsens 中的多个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523425&idx=1&sn=d86d65a64846ff68a79a294116423c60&scene=21#wechat_redirect)  
  
  
[CISA和FBI联合发布关于减少现代软件开发中内存安全漏洞的指南](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523387&idx=2&sn=51d9faa28849e3f10c23498b89c880d0&scene=21#wechat_redirect)  
  
  
[CISA 将TP-Link 路由器高危漏洞纳入KEV](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523309&idx=2&sn=d3e035c89c35c26ad0a1cad90861ac97&scene=21#wechat_redirect)  
  
  
[CISA将Erlang SSH 和 Roundcube 加入KEV清单](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523250&idx=2&sn=245cd6553dde79a725f1afe15893f164&scene=21#wechat_redirect)  
  
  
[CISA提醒注意已遭利用的 Commvault 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523124&idx=1&sn=1a8e46e871f1fae51bb1c752be774842&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/cisa-warns-of-two-exploited-telemessage-vulnerabilities/  
  
  
题图：  
Pixabay Licen  
se  
  
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
  

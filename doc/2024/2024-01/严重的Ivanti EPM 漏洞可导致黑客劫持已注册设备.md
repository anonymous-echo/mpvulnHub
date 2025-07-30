#  严重的Ivanti EPM 漏洞可导致黑客劫持已注册设备   
Sergiu Gatlan  代码卫士   2024-01-05 17:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Ivanti 公司修复了位于端点管理软件 (EPM) 中的一个远程代码执行 (RCE) 漏洞，可导致未认证攻击者劫持已登记设备或核心服务器。**  
  
  
  
Ivanti EPM 有助于管理运行大量平台的客户端设备，如 Windows、macOS、Chrome OS 和物联网操作系统等。该漏洞的编号是CVE-2023-39366，影响所有受支持的 Ivanti EPM 版本，已在版本2022 Service Update 5 中修复。  
  
有权限访问目标内网的攻击者可在无需权限或用户交互的低复杂度攻击中利用该漏洞。Ivanti 公司指出，“如漏洞遭利用，则有权限访问内网的攻击者可在无需认证的情况下，利用未指定SQL注入漏洞执行任意SQL查询并检索输出。之后攻击者可控制运行该 EPM 代理的机器。当核心服务器被配置为使用 SQL express 时，可能导致在核心服务器上执行RCE。”  
  
Ivanti 公司表示，目前尚无证据表明客户受利用该漏洞的攻击者影响。目前，该公司禁止访问包含所有详情的安全公告，可能是为了让客户有更多的时间加固设备安全，以防威胁行动者利用更多信息制造利用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRWCFK5SJLCT8kc9UjpvYicNksamRmURZM0bpeG10JibhEg7Y0Qrv7ic7UpibiaI6NerCgLa1B8YicrkW6Q/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRWCFK5SJLCT8kc9UjpvYicNaeabreGukW2xicymwicwnusYtCduTjicH5KnOUBKm8icd8Dr1wm4yZrAdQ/640?wx_fmt=png&from=appmsg "")  
  
**已遭在野利用的 0day 漏洞**  
  
  
7月份，国家黑客组织利用位于 Ivanti EPMM 中的两个漏洞CVE-2023-35078和CVE-2023-35081 渗透到挪威多个政府组织机构网络。  
  
CISA 当时提醒称，“移动设备管理系统备受攻击者欢迎，因为这些系统提供了数千台移动设备的提升权限，而APT 阻止此前曾利用过一个 MobileIron 漏洞。因此CISA和NCSC-NO 担心政府和私营网络遭大规模利用。”  
  
第三个0day漏洞 (CVE-2023-38035) 位于 Ivanti 的 Sentry 软件中，也在一个月之后遭利用。该公司还在8月和12月修复了位于 Avalanche 企业移动设备管理解决方案中的十几个严重漏洞。Ivanti 公司的产品客户遍布全球4万多家企业，帮助它们管理IT资产和系统。  
  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Ivanti 修复 Avalanche 中的13个严重 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518459&idx=2&sn=11cb31fa8a53f1561ec28a3e9a63da6e&chksm=ea94b991dde33087c9606baa5ebb64e71528283f676f497d3123ca31f84cc1ce1f3e971e8184&scene=21#wechat_redirect)  
  
  
[Ivanti 紧急修复 API 认证绕过0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517421&idx=1&sn=31756dd565b1bbd216e954def83c61dc&chksm=ea94b587dde33c91e83a737ae3eb0a14c48a427523b94dba12823b03eac1cecf97a890e21afa&scene=21#wechat_redirect)  
  
  
[挪威政府机构遭攻击，黑客利用的不止IT巨头 Ivanti的一个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517282&idx=1&sn=92bc54d50120e90cdb14ffdc9575e7e5&chksm=ea94b508dde33c1eb06b110c0e5f8a197bfcb980488faddce9fee996ea1be88dc50821b49082&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/ivanti-warns-critical-epm-bug-lets-hackers-hijack-enrolled-devices/  
  
  
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
  

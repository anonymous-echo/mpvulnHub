#  满分严重漏洞导致 MB-Gateway 设备易受远程攻击   
Eduard Kovacs  代码卫士   2025-05-22 09:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**由工业自动化公司 AutomationDirect 制造的 MB-Gateway 设备因受严重漏洞影响，易受远程攻击。**  
  
CISA 在本周二披露了该漏洞，并在安全通告中提到，易受攻击的 Modbus 网关产品的客户遍布全球，其中一些用于关键基础设施。  
  
该漏洞的编号是CVE-2025-36535，CVSS评分为10分，是因该产品的嵌入式webserver 中存在一个认证缺失问题导致的，可导致不受限制的远程访问后果。  
  
CISA 提到，该产品的硬件限制阻止了正确访问控制更新的实现，而AutomationDirect已建议用户通过 EKI-1221-CE 网关取代 MB-Gateway 产品。  
  
发现该漏洞的 Microsec 公司的研究员 Souvik  Kandar 提到，该漏洞可从互联网远程利用，超过100台暴露在网络的设备可能受影响。任何用于互联网访问权限的人员无需任何凭据即可访问配置面板。被暴露的界面泄露敏感设备参数如内部IP、固件版本、Modbus 配置和序列通信设置。他提到，该漏洞如遭利用可在某些工业环境中造成严重影响。  
  
攻击者可远程修改设备配置、破坏或操纵系统间的 Modbus 通信、获取详细的网络和系统信息用于横向移动，以及在某些配置下（取决于网关如何继承以及暴露了哪些功能），攻击者可执行任意代码。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[美国：黑客正在攻击油气组织机构的 ICS/SCADA](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522945&idx=2&sn=123314a88d77b291cc767bd9f0d2975e&scene=21#wechat_redirect)  
  
  
[NIST、CISA联合提出漏洞利用概率度量标准](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523082&idx=2&sn=4d5a25d58482d98bdb3b13320e03bb92&scene=21#wechat_redirect)  
  
  
[CISA：速修复已遭利用的 CentreStack 和 Windows 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522701&idx=2&sn=0b8f46ac41b6d62102b7ec1c02b25f60&scene=21#wechat_redirect)  
  
  
[OpenAI：伊朗国家黑客利用 ChatGPT 密谋 ICS 攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521056&idx=2&sn=99545ebc43462c5f2e8b1617494b75b4&scene=21#wechat_redirect)  
  
  
[mySCADA myPRO中存在多个严重漏洞，可导致攻击者接管工控系统](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522548&idx=1&sn=665e87c79bcffb3144bfddbfa30f4941&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/critical-flaw-allows-remote-hacking-of-automationdirect-industrial-gateway/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

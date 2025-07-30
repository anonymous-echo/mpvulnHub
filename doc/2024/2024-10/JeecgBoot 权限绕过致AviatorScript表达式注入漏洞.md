#  JeecgBoot 权限绕过致AviatorScript表达式注入漏洞   
Superhero  Nday Poc   2024-10-10 21:51  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
Jeecg Boot(或者称为 Jeecg-Boot)是一款基于代码生成器的开源企业级快速开发平台，专注于开发后台管理系统、企业信息管理系统(MIS)等应用。它提供了一系列工具和模板，帮助开发者快速构建和部署现代化的 Web 应用程序。  
  
  
**01******  
  
**漏洞概述**  
  
  
JeecgBoot 存在权限绕过漏洞，未经身份验证的远程攻击者可构造jmLink、sharetoken参数或JmReport-Share-Token请求头绕过权限认证访问后台接口，进一步深入利用可实现远程代码执行、木马植入，导致服务器失陷等问题。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
title=="JeecgBoot 企业级低代码平台" || body="window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/" || title="Jeecg-Boot 企业级快速开发平台" || title="Jeecg 快速开发平台" || body="'http://fileview.jeecg.com/onlinePreview'" || title=="JeecgBoot 企业级低代码平台" || title=="Jeecg-Boot 企业级快速开发平台" || title=="JeecgBoot 企业级快速开发平台" || title=="JeecgBoot 企业级快速开发平台" || title="Jeecg 快速开发平台" || title="Jeecg-Boot 快速开发平台" || body="积木报表" || body="jmreport"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJ4rfxS7FM43a2m4QBrofd9n6dUHA3wnplrjFjMpSDEsbge5Lxx9UcfoJv6KEjnMibABNyJENRm4Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
**03******  
  
**漏洞复现**  
  
1、写入恶意报表数据(Fastjson BCEL)，Dnslog验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJ4rfxS7FM43a2m4QBrofdVzN27gGXXN3Yncic88pw2qibkcCiaSb71NyP7zIhgL9ia4uhXXpv4txGXA/640?wx_fmt=png&from=appmsg "")  
  
2、提取id数据触发漏洞，实现RCE  
  
PS：text处写入的恶意类会执行，回显null  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJ4rfxS7FM43a2m4QBrofdcXbQoF2eqJJz0ed2lHlqRJspllOAuTu5LDO8DKjdloGTRRdW6X7jbg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJ4rfxS7FM43a2m4QBrofdic9RStY2Wz5ibrxkAkHQEqibZEpZicqm8ZMHO8GaBxHRia2qqxaNE2Kxeiaw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJ4rfxS7FM43a2m4QBrofdQIYue58aBq6WYiakXVRciaRgFzQr6ibLOnsjcKtfDjHfsicgZJ0lGlp2kw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJ4rfxS7FM43a2m4QBrofdVfMXMIKoH0jcaZVgGuRP5ibxrMfBOeFkmHaGK9ezibtftSsX8iaflqJBg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJ4rfxS7FM43a2m4QBrofdH3bLAFLuQOvM9IXuVgNbHvAyz0kIfF6Ylnibq5l7J0lUMc40Clq9GNg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、目前厂商已经发布了新版本以修复此安全问题，建议受影响用户升级至最新版本  
  
http://www.jeecg.com/  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保证每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  

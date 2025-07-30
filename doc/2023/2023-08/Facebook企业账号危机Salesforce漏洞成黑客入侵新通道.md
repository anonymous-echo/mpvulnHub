#  Facebook企业账号危机:Salesforce漏洞成黑客入侵新通道   
 网络安全应急技术国家工程中心   2023-08-08 15:09  
  
近期黑客挟持企业的facebook帐号的攻击行动，有不少是通过脸书广告，打着提供生成式AI机器人应用程序的名义，散布窃资软件来进行，但最近出现了更为复杂的手法。有人透过云端CRM平台Salesforce的漏洞下手，并将钓鱼网站架设于脸书脸书内嵌应用程序平台的域网域上，从而回避系统的侦测，并骗取受害组织的脸书帐号。  
  
云平台的系统管理工具有可能遭到滥用，因此成为黑客的“木马程序”, 研究人员揭露利用  
AWS EC2系统管理工具System Manager的攻击手法，攻击者有可能透过这项工具管理其他组织的AWS EC2实体。  
  
已被用于攻击Citrix NetScaler系统存在的零时差漏洞CVE-2023-3519，有研究人员揭露初步调查结果，他们找到640台服务器已被部署了后门，并强调这可能仅是受害范围的冰山一角。  
  
Guardio揭露CRM平台Salesforce的漏洞PhishForce，黑客借此漏洞绕过该CRM平台的寄件人验证措施，并滥用脸书内嵌应用程序平台，来大规模发送钓鱼邮件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6xrXyKk5X4nsMfksNaoWwHErFNNSqdFeCNrOS00AuzrmTCmxMlicoPYPNTVJXrvBTUv5CQicmAyibV1A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
研究人员指出，黑客滥用了Email-to-Case的功能，该功能主要是让组织能将客户  
寄入的电子信件转换为Salesfoce系统传递的处理工单，但黑客将其用来设置新的工作流程，进而控制Salesforce产生的电子邮件信箱，并产生 salesforce.com 域的内部信箱，且将其设置为组织全局的电子邮件信箱，然后用于发送钓鱼邮件， 而能绕过Salesforce的验证措施，以及组织设置的邮件安全系统。  
  
在其中一起攻击行动里，黑客假借Meta的名义，声称收信人的脸书帐号出现异常，一旦依照指示点选信中链接，就会被带往架设在脸书内嵌应用程序平台（apps.facebook.com）的钓鱼网页。  
  
对此，Salesforce获报后着手修补漏洞，Meta移除钓鱼网页，并着手调查黑客如何滥用该脸书内嵌应用程序平台。  
  
  
  
原文来源：E安全  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  

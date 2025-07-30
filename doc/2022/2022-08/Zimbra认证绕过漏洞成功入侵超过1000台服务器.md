#  Zimbra认证绕过漏洞成功入侵超过1000台服务器   
 关键基础设施安全应急响应中心   2022-08-15 14:26  
  
Zimbra是一套邮箱和协同办公平台，包括WebMail，日历，通信录，Web文档管理等功能，有140个国家的超过20万企业使用，其中包括超过1000个政府和金融机构。  
  
**CVE-2022-27925漏洞**  
  
Volexity研究人员发现了一个Zimbra认证绕过漏洞（CVE-2022-27925）被用于攻击Zimbra Collaboration Suite (ZCS)邮箱服务器。在调查一起Zimbra邮件服务器入侵事件过程中，Volexity发现ZCS远程利用是根本原因。检查入侵服务器的web日志发现，漏洞利用预之前写入webshell到硬盘的漏洞是一致的。示例web日志记录如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibr8xeLED2fiapExUuibduxDGBicfMibKyJvuTziamcb1Tp85CKztfhPzoEMReh3vvpCmXPcvTgLWTmUjQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
检查MailboxImport servlet源码发现，url访问时会调用“doPost”函数，会检查用户是否经过认证，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibr8xeLED2fiapExUuibduxDG0nFOxI8WEOarHxxJLBkLDTibACo9ibdXNeNpBrvxAnfWIJyUxq2dicOAQ/640?wx_fmt=png "")  
  
图 “MailboxImport” servlet函数  
  
代码的问题是对认证进行了检查，也设置了错误信息，但是并没有return描述。也就是说之后的代码会继续执行，与用户的认证状态无关。利用该函数，攻击者只需要在URL中设置正确的参数就可以利用该漏洞。  
  
**受影响的版本**  
  
受影响的版本包括：  
  
· Zimbra 8.8.15  
  
· Zimbra 9.0.0  
  
**在野漏洞利用**  
  
Volexity 发现攻击者滥用该漏洞的过程中结合了另一个认证绕过漏洞（CVE-2022-37042）。研究人员认为该漏洞与2021年初发现的微软Exchange 0-day漏洞利用基本一致。最初的时候只是被情报监控相关的攻击者利用，但之后被大规模利用。攻击者成功利用该漏洞可以在被入侵的服务器的特定位置部署web shell以实现驻留。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibr8xeLED2fiapExUuibduxDGcRslsTmf2bfeRKkSEdu8DHdWcltHJ3biaMQ05WNusyd1R4h1ibJ7Yibww/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
CISA在11日已经确认了这两个安全漏洞的在野利用。通过扫描发现，目前有超过1000台服务器存在后门或已经被入侵。涉及政府机关、军事结构、收入数十亿的跨国公司。由于扫描shell路径的限制，预计被入侵的服务器数量更多。  
  
**安全补丁**  
  
Volexity称，如果有漏洞的服务器在5月底前没有修复CVE-2022-27925漏洞，那就可以认为ZCS实例已经被入侵了，包括邮件内容在内的所有内容都可能被窃了。  
  
研究人员建议对可能的入侵事件进行分析，并使用最新的补丁重构ZCS实例。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/zimbra-auth-bypass-bug-exploited-to-breach-over-1-000-servers/  
  
  
  
原文来源  
：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  

#  超过12000个KerioControl防火墙暴露于被利用的RCE漏洞   
胡金鱼  嘶吼专业版   2025-02-20 06:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
KerioControl是一款面向中小企业的网络安全套件，主要用于vpn、带宽管理、报表监控、流量过滤、反病毒防护、入侵防御等。安全研究员发现，  
超过12000个GFI KerioControl防火墙实例暴露于一个关键的远程代码执行漏洞，跟踪为CVE-2024-52875。  
  
这个漏洞是由安全研究员Egidio Romano （EgiX）在12月中旬发现的，他向人们展示了一键式RCE攻击的潜在危险。  
  
GFI软件公司于2024年12月19日发布了9.4.5版本补丁1的安全更新，但三周后，根据Censys的说法，超过23800个实例仍然容易受到攻击。  
  
上个月初，Greynoise透露，它已经检测到利用Romano的概念验证（PoC）漏洞的活跃利用尝试，旨在窃取管理CSRF令牌。  
  
尽管有关于主动利用的警告，威胁监控服务Shadowserver表示，有12229台KerioControl防火墙暴露在利用CVE-2024-52875的攻击中。  
  
这些实例大多数位于伊朗、美国、意大利、德国、俄罗斯、哈萨克斯坦、乌兹别克斯坦、法国、巴西和印度。  
  
由于CVE-2024-52875的公共PoC的存在，利用的要求很低，即使是不熟练的黑客也可以加入恶意活动。  
  
Egidio Romano解释说：“在302 HTTP响应中用于生成“Location”HTTP头之前，通过“dest”GET参数传递到这些页面的用户输入没有得到正确的处理。”  
  
具体来说，应用程序不能正确过滤/删除换行（LF）字符。这可以用来执行HTTP响应分裂攻击，这反过来可能允许执行反射跨站脚本（XSS）和其他可能的攻击。”  
  
反射XSS向量可能被滥用来执行一键式远程代码执行（RCE）攻击。如果用户还没有进行安全更新，强烈建议安装2025年1月31日发布的KerioControl版本9.4.5 Patch 2，其中包含额外的安全增强功能。  
  
参考及来源：https://www.bleepingcomputer.com/news/security/over-12-000-keriocontrol-firewalls-exposed-to-exploited-rce-flaw/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29mrHabtLv6LE2a2Nf8koxj4vuU9U7HicDjatdy1drB2OicwV3H5qpqqwEKlOicWp2Aic9SemFibkp2JuQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29mrHabtLv6LE2a2Nf8koxjFqMSANb6d5YwH7aeCibL2TPibibr4V4aekmjUnUTNEsaib4F4Lg6Ejqwkw/640?wx_fmt=png&from=appmsg "")  
  
  

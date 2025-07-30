#  工控漏洞 | mySCADA myPRO或被攻击者掌控工业控制系统   
FreeBuf  商密君   2025-03-23 21:25  
  
网络安全研究人员披露了影响mySCADA myPRO系统的两个重大漏洞的细节。myPRO是一种广泛应用于工业技术（OT）环境中的监控与数据采集（SCADA）系统，这些漏洞可能使恶意攻击者控制易受攻击的设施。  
  
  
瑞士安全公司PRODAFT表示：“如果这些漏洞被利用，可能导致未授权访问工业控制网络，进而引发严重的运营中断和财务损失。”这些漏洞均被评为CVSS v4评分系统中的9.3分，具体包括：  
  
1. CVE-2025-20014 - 操作系统命令注入漏洞，攻击者可通过包含版本参数的特制POST请求，在受影响的系统上执行任意命令。  
  
2. CVE-2025-20061 - 操作系统命令注入漏洞，攻击者可通过包含电子邮件参数的特制POST请求，在受影响的系统上执行任意命令。  
  
  
成功利用其中任何一个漏洞，攻击者都可能注入系统命令并执行任意代码。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38XwTgRA48WDosoh2GoRypxLmPtH81McNicy4ahxoM5XAjJ0xVB3u5zuv9sDndEefibKAr0icvD90wHQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**漏洞成因与潜在风险**  
  
  
  
PRODAFT指出，这两个漏洞均源于未能对用户输入进行适当清理，从而导致命令注入的风险。公司强调：“这些漏洞凸显了SCADA系统中持续存在的安全风险，以及加强防御的必要性。利用这些漏洞可能会导致运营中断、财务损失甚至安全隐患。”  
  
  
**安全建议与应对措施**  
  
  
  
为了防止潜在的攻击，组织应尽快采取以下措施：  
  
1. 应用最新的安全补丁；  
  
2. 实施网络隔离，将  
SCADA系统与IT网络分开；  
  
3. 强制采用强身份验证；  
  
4. 监控可疑活动。  
  
  
通过这些措施，可以有效减少漏洞被利用的风险，保障工业控制系统的安全运行。  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源：FreeBuf  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  

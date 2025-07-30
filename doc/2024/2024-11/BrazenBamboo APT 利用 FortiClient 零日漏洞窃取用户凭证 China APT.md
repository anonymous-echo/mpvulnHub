#  BrazenBamboo APT 利用 FortiClient 零日漏洞窃取用户凭证 |China APT   
 李白你好   2024-11-18 00:00  
  
**免责声明：**由于传播、利用本公众号李白你好所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号李白你好及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
****  
  
**1**►  
  
**安全资讯**  
  
  
一个名为 BrazenBamboo 的威胁行为者发起了一场复杂的网络间谍活动。  
该组织正在利用 Fortinet 的 Windows FortiClient VPN 软件中未修补的漏洞窃取用户凭据，这是使用名为 DEEPDATA 的模块化恶意软件框架进行更广泛攻击的一部分。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAtkthHJSC4Dcdu3Q6RwKeYgspFbB1YWVsyhjibg0qNNmsClSth8cgibjXjia4sUuw4wic5iagEbYRYhuw/640?wx_fmt=png&from=appmsg "")  
  
该零日漏洞于 2024 年 7 月发现，攻击者可利用该漏洞从 FortiClient 进程的内存中提取 VPN 凭据。此漏洞甚至会影响发现时可用的最新版本的 FortiClient (v7.4.0)。  
  
BrazenBamboo 被认为是与中国政府有关的威胁行为者，开发了多个恶意软件家族，包括 DEEPDATA、DEEPPOST 和 LIGHTSPY。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAtkthHJSC4Dcdu3Q6RwKeYazhDsI9GTofLreicfvXusy1mOKsZwqOVz74GkfTVAHBOW6g53XFibnuQ/640?wx_fmt=png&from=appmsg "")  
  
DEEPDATA 框架由一个加载器（data.dll）和各种插件组成，旨在从受感染的 Windows 系统收集敏感信息。  
  
FortiClient 漏洞是通过名为“msenvico.dll”的插件实现的，该插件从 VPN 客户端内存中的 JSON 对象中提取用户名、密码、远程网关和端口。  
  
这种技术让人想起 2016 年发现的类似漏洞，但当前的漏洞影响的是 FortiClient 的较新版本。  
  
DEEPDATA 的功能不仅限于窃取凭证，还包括从流行的消息应用程序、浏览器和电子邮件客户端收集数据。该恶意软件还可以录制音频、捕获按键并从受感染的系统中窃取文件。  
  
Volexity 的分析显示，BrazenBamboo 拥有一套复杂的指挥和控制 (C2) 操作基础设施。该组织使用多台服务器托管恶意软件负载和管理应用程序，有证据表明他们正在不断开发工具。  
  
研究人员以中等可信度评估认为，BrazenBamboo 很可能是一家私营企业，为专注于国内目标的政府运营商提供功能。这一评估基于C2 基础设施中使用的语言、恶意软件开发中的架构决策以及尽管公开曝光但仍持续运行。  
  
Volexity 于 2024 年 7 月 18 日向 Fortinet 报告了 FortiClient 漏洞，Fortinet 于 2024 年 7 月 24 日承认了该问题。然而，截至 Volexity 报告时（2024 年 11 月），该问题仍未解决，也没有分配 CVE 编号。  
  
此次活动的发现凸显了资源丰富的 APT 组织所构成的持续威胁以及及时修补的重要性。建议使用 FortiClient VPN 的组织监控 Fortinet 的更新并实施额外的安全措施来保护敏感凭据。  
  
随着威胁形势的不断演变，网络安全专业人员必须对像 BrazenBamboo 这样经验丰富的攻击者保持警惕，他们能够利用广泛使用的安全软件中的零日漏洞。  
  
参考连接：https://cybersecuritynews.com/brazenbamboo-apt-forticlient-zero-day/  
  
**2**►  
  
**往期精彩**  
  
[ 资产收集常用工具以及思路总结 ](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509314&idx=1&sn=4e286a1c43f839e3b4d15a33eac58c5e&chksm=c09ad612f7ed5f047988b760b5ddca5fb55c14840d0c5ec35dc8e82e84a507889f298c05868c&scene=21#wechat_redirect)  

						  
  
  
[ Data Vigilante 泄露亚马逊、惠普等公司 800 万份员工记录 ](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509256&idx=1&sn=134a4e29aff1a604833511d606ae4eef&chksm=c09ad658f7ed5f4e0c2228a859f754115714bf9820596c2c497539f698949230482b61aa9c1c&scene=21#wechat_redirect)  

						  
  
  
[ Vcenter图形化漏洞利用工具 ](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509243&idx=1&sn=9ca7cfa1e2f26bde8862d28ddb4cf3a5&chksm=c09ad7abf7ed5ebdc94cc4c247010a12e466b9179001bb8d223d3a1c0ba9aba8d564831649c1&scene=21#wechat_redirect)  

						  
  
  
  

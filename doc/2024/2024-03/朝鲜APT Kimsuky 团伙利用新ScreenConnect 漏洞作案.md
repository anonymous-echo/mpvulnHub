#  朝鲜APT Kimsuky 团伙利用新ScreenConnect 漏洞作案   
原创 紫队  紫队安全研究   2024-03-09 11:58  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sj5DXqXIANFJUHn0dR0ZmgWOczkE1ia3YCaiaOtxISCEYv3I7tlMZurPqm1OWXqMicYB3C6thWfSVGQ/640?wx_fmt=png&from=appmsg "")  
  
黑客正在利用最近披露的 ScreenConnect 漏洞来部署先前与朝鲜威胁组织  
Kimsuky  
相关的恶意软件菌株的新变种。  
  
这种新恶意软件被 Kroll 的研究人员称为 ToddlerShark，与  
Kimsuky（也称为 APT43、Emerald Sleet 和 Velvet Chollima）使用的侦察工具  
ReconShark 和 BabyShark重叠。  
  
ConnectWise  
上个月  
披露了两个漏洞  
，并发布了其 ScreenConnect 远程桌面和访问软件的安全修复程序。其中一个漏洞是一个身份验证绕过漏洞，编号为  
CVE-2024-1709  
，CVSS v3 的最高严重性评分为 10。  
  
自这些漏洞曝光以来，它们已被多个威胁组织利用，其中包括使用  
Play、LockBit 和其他勒索软件的  
攻击者。  
## ToddlerShark 玩捉迷藏  
  
在  
3 月 5 日的分析  
中，Kroll 研究人员 Keith Wojcieszek、George Glass 和 Dave Truman 表示，Kroll Responder 团队发现并阻止了一次表现出 Kimsuky 特征的妥协尝试。  
  
“威胁行为者通过利用 ScreenConnect 应用程序的暴露设置向导获得了对受害者工作站的访问权限。然后，他们利用现在的“手动键盘”访问权限，使用 cmd.exe 来执行 mshta.exe，其中包含基于 Visual Basic (VB) 的恶意软件的 URL。”  
  
攻击中部署的 ToddlerShark 恶意软件“以更改代码中的身份字符串、通过生成的垃圾代码更改代码位置以及使用唯一生成的 C2 URL 的形式表现出多态行为元素，这可能使该恶意软件在某些环境中难以检测” ，”研究人员说。  
  
“因此，修补 ScreenConnect 应用程序势在必行。”  
## Kimsuky 提高其信息窃取技能  
  
ToddlerShark 的信息窃取功能使其能够窃取数据，包括主机、用户、网络和安全软件信息，以及已安装的软件和正在运行的进程。  
  
Kroll 研究人员表示：“一旦该工具收集了所有这些信息，它就会使用内置的 Windows 命令 certutil 将被盗信息编码到隐私增强邮件 (PEM) 证书中，然后将其渗透到 C2 Web 应用程序中。”  
  
“利用 PEM 文件中隐藏的数据来窃取数据是 Kimsuky 之前使用过的一种技术。”  
  
在分析中，Kroll 建议 ScreenConnect 客户应采取多项行动，以保护其系统免受 Kimsuky 和其他利用新漏洞的威胁组织的攻击。  
  
所有运行 ScreenConnect 版本 23.9.7 或更早版本的用户都应假定自己已受到损害，并按照  
ConnectWise 公告中的  
指导立即修补。  
  
除了修补之外，克罗尔还建议受影响的用户对其系统进行独立的威胁搜寻/妥协评估，以确保在修复之前不会发生可疑活动，并且不会插入恶意软件。  
  
研究人员还建议使用端点检测和响应 (EDR) 解决方案或配置为对 Webshell 进行系统扫描的下一代防病毒 (NGAV) 工具，同时实施 Web 应用程序防火墙 (WAF) 或其他 Web 流量监控系统来分析潜在的利用。  
  
  

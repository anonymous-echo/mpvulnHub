#  Windows TCP/IP RCE漏洞曝光，影响所有启用IPv6的系统   
FreeBuf  商密君   2024-08-17 14:15  
  
本周二（8月13日），微软警告客户立即修补一个严重的TCP/IP远程代码执行（RCE）漏洞，该漏洞被利用的可能性增加，会影响所有使用默认启用IPv6的Windows系统。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icqks1s5Is6QNT7fmvNRVKG8IR5guibzws5NIxFyNtPszDPFSOYrDib0UJCSlfIAJTqrTicuonbDxrVA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
该安全漏洞由昆仑实验室的研究人员发现，并被追踪为CVE-2024-38063，它是由整数下溢漏洞引起的，攻击者可以利用该漏洞触发缓冲区溢出，从而在易受攻击的Windows 10、Windows 11和  
Windows Server系统中执行任意代码。  
  
  
「考虑到它的危害性，短期内我不会披露更多细节。」这位安全研究员在推特上补充说，在本地  
Windows防火墙上阻止IPv6并不能阻止漏洞的利用，因为漏洞在被防火墙处理之前就被触发了。  
  
  
正如微软在其周二的公告中解释的那样，未经身份验证的攻击者可以通过重复发送包含特制的IPv6数据包，在低复杂性攻击中远程利用该漏洞。  
  
  
微软还分享了对这一关键漏洞的可利用性评估，将其标记为「更有可能被利用」，这意味着威胁行为者可以创建利用代码，「在攻击中持续利用该漏洞」。  
  
  
此外，过去曾有此类漏洞被利用的实例，这使得它成为攻击者的理想目标，更有可能被开发出相应的利用手段。  
  
  
对于已经审查过安全更新并确定其在环境中适用性的客户应将此作为更高的优先级来对待。而那些无法立即安装本周 Windows 安全更新的用户，微软建议禁用 IPv6 以消除攻击面，作为一种缓解措施。  
  
  
不过，IPv6网络协议栈是「 “Windows Vista和Windows Server 2008及更新版本的强制组成部分」，如果关闭IPv6或其组件，可能会导致某些Windows组件停止工作。  
  
  
趋势科技「零日计划」（Zero Day Initiative）威胁意识主管  
Dustin Childs也将CVE-2024-38063漏洞列为微软本周「补丁星期二」修复的最严重漏洞之一，并将其标记为可蠕虫漏洞。  
  
  
Childs说：「最严重的可能是TCP/IP中的漏洞，它允许远程、未经身份验证的攻击者通过向受影响的目标发送特制的IPv6数据包来获得高级代码执行权限。意味着它是可蠕虫攻击的。你可以禁用IPv6来防止这种漏洞，但IPv6在几乎所有设备上都是默认启用的。」  
  
  
虽然微软和其他公司警告Windows用户尽快给他们的系统打补丁，以阻止利用CVE-2024-38063漏洞的潜在攻击，但这并不是第一个，也很可能不会是最后一个可利用IPv6数据包的  
Windows漏洞。  
  
  
在过去四年中，微软已修补了多个其他 IPv6 问题，包括两个 TCP/IP 漏洞，即 CVE-2020-16898/9（也称为 Ping of Death），这些漏洞可利用恶意 ICMPv6 路由器广告数据包进行远程代码执行（RCE）和拒绝服务（DoS）攻击。  
  
  
此外，一个 IPv6 分片漏洞（CVE-2021-24086）使所有 Windows 版本容易受到 DoS 攻击，而一个 DHCPv6 漏洞（CVE-2023-28231）使利用特制调用获得 RCE 成为可能。  
  
  
尽管攻击者尚未利用这些漏洞对所有支持 IPv6 的 Windows 设备进行大范围攻击，但由于 CVE-2024-38063 被利用的可能性增加，建议用户立即应用本月的 Windows 安全更新。  
  
  
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
  

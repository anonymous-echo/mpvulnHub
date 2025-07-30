#  影响Windows 和 macOS平台，黑客利用 Adobe CF 漏洞部署恶意软件   
 关键基础设施安全应急响应中心   2023-09-05 15:04  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogtialVjWdaeOSnBFhhruViaf7hibrI8uNbEoqy1HF4mYKUbT9RQzVPASqY3ibRJG4dSk5B85EUIkbvu6g/640?wx_fmt=jpeg "")  
  
FortiGuard 实验室的网络安全研究人员发现了几个影响 Windows 和 Mac 设备的 Adobe ColdFusion 漏洞。  
- 远程攻击者可利用Adobe ColdFusion 2021中的验证前RCE漏洞，获取受影响系統的控制权力。  
  
- Adobe 已发布安全补丁来解决这些漏洞，但攻击者仍在利用这些漏洞。  
  
- 攻击活动涉及多个阶段，包括探测、反向外壳和部署恶意软件。  
  
- 目前已发现四种不同的恶意软件：XMRig Miner、Satan DDoS/Lucifer、RudeMiner 和 BillGates/Setag 后门。  
  
- 建议用户及时升级系统并部署保护机制，以挫败正在进行的攻击。  
  
由于 Adobe ColdFusion 存在漏洞，Windows 和 macOS 平台的众多用户目前都面临风险。该软件套件是网络应用程序开发的热门选择，最近由于远程攻击者发现并利用了认证前远程代码执行（RCE）漏洞而受到攻击。这些漏洞使攻击者有能力夺取受影响系统的控制权，从而将危险系数提升到了严重级别。  
  
这些攻击的核心目标是 Adobe ColdFusion 2021 中的 WDDX 反序列化过程。虽然Adobe迅速回应了安全更新（APSB23-40、APSB23-41和APSB23-47），但FortiGuard实验室仍观察到持续的攻击尝试。  
  
从对攻击模式的分析，研究人员发现了威胁行为者执行的一个过程。他们使用 "interactsh "等工具发起探测活动，以测试漏洞利用的有效性。观察到这些活动涉及多个域，包括 mooo-ngcom、redteamtf 和 h4ck4funxyz。探测阶段让攻击者深入了解了潜在漏洞，并为更多的恶意行动的做好铺垫。  
  
攻击活动的复杂性还体现在反向外壳的使用上。通过对有效载荷进行 Base64 编码，攻击者试图在未经授权的情况下访问受害者系统，从而实现远程控制。  
  
值得注意的是，分析揭示了一种多管齐下的方法，包括部署各种恶意软件变种。攻击是从不同的 IP 地址发起的，这引起了人们对该活动影响范围之广的担忧。恶意软件有效载荷以 Base64 编码，在解码前隐藏了其真实性质。研究人员发现了四种不同的恶意软件：XMRig Miner、Satan DDoS/Lucifer、RudeMiner 和 BillGates/Setag 后门。  
  
XMRig Miner 主要与 Monero 加密货币挖矿有关，被用来劫持系统处理能力。通过利用 6.20.0 版本，攻击者设法利用被入侵的系统获取经济利益。  
  
Lucifer是一个混合型机器人，结合了加密劫持和分布式拒绝服务（DDoS）功能，是一个强大的实体。该恶意软件变种不仅展示了其挖矿能力，还展示了其在指挥和控制操作、通过漏洞传播以及复杂的 DDoS 攻击方面的能力。  
  
与 "Lucifer "相连的 RudeMiner 携带着以前的 DDoS 攻击遗产。它在当前威胁环境中的参与表明了它的持久性和适应性，使其成为一个重大隐患。  
  
BillGates/Setag 后门之前与 Confluence 服务器漏洞有关，在此背景下再次出现。表明它具有多方面的能力，包括系统劫持、C2 通信和多种攻击方法，其中包括基于 SYN、UDP、ICMP 和 HTTP 的攻击。  
  
尽管有安全补丁可用，但攻击的持续不断，也突显了采取行动的紧迫性。我们强烈建议用户及时升级系统并部署保护机制，包括防病毒服务、IPS 签名、网络过滤和 IP 信誉跟踪，以遏制持续不断的攻击。  
  
**参考资料：**  
  
https://www.hackread.com/hackers-adobe-coldfusion-vulnerabilities-malware/  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  

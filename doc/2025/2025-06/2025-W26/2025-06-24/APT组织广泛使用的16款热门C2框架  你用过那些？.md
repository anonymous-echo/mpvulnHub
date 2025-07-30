> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247512915&idx=1&sn=980ee53bc8be3e28be4df58f190231b5

#  APT组织广泛使用的16款热门C2框架 | 你用过那些？  
网安情报攻防站  李白你好   2025-06-24 00:02  
  
**免责声明：**  
由于传播、利用本公众号李白你好所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号李白你好及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
# C2框架  
  
“请记住，有效的红队行动更多的是关于方法论、经验和战略思维，而不是任何特定的工具——但拥有正确的工具肯定有助于取得更好的成果。”  
## 1.Sliver  
  
作者： Bishop Fox（@BishopFox）  
>   
> “一个开源的跨平台对手模拟/红队框架。”  
  
  
描述：  Sliver 是红队成员和渗透测试人员的绝佳工具。相信我们，我们非常了解。它适用于任何规模的组织。其植入程序支持 MacOS、Windows 和 Linux，因此用途广泛。此外，植入程序可以通过各种渠道与服务器通信，例如 mTLS、HTTPS、DNS 等。  

```
https://github.com/BishopFox/sliver

```

## 2.PoshC2  
  
作者： Nettitude（@nettitude）  
>   
> “代理感知 C2 框架用于帮助红队进行后期利用和横向移动。”  
  
  
描述： PoshC2 为红队攻击提供了一个高度灵活且可扩展的框架，主要使用 Python3 构建。它为各种操作系统和编程语言提供了丰富的即用型植入体和有效载荷，从而确保了广泛的兼容性。此外，其操作安全性和隐身性也是其关键特性，例如包含 AMSI 绕过和 EW 修补的 Shellcode、自动生成的用于代理的 Apache Rewrite 规则以及完全加密的通信。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAg3Py86HKiaIMOCoBO5XtiaEZg1cfgxOMkcDEVtUxQdZOK4uw9YLHmNprOUkRuXfud1XIKqIBQ19NQ/640?wx_fmt=png&from=appmsg "")  

```
https://github.com/nettitude/PoshC2

```

## 3.Cobalt Strike  
  
维护者：（@Fortra）  
>   
> “专为红队和渗透测试人员设计的网络安全工具，用于在网络环境中进行高级威胁模拟和侦察。”  
  
  
描述： Cobalt Strike 通过使用隐蔽的通信通道和高度可配置的“Beacon”植入物（这些植入物可与正常网络流量混合），帮助安全团队模拟复杂的网络攻击。凭借丰富的后漏洞利用模块和自定义脚本，它专为逼真、全面的红队行动而打造。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAg3Py86HKiaIMOCoBO5XtiaE67cIysTmaqOy6ibSbKmQ45MoicH86onc1dtrRc0Kics3PPibed5WoicLZ2w/640?wx_fmt=png&from=appmsg "")  

```
https://www.imperva.com/learn/application-security/cobalt-strike/

```

## 4.Nighthawk  
  
作者： MDSec Consulting Ltd  
  
“这是一个先进的红队工具包，在构建时充分考虑了操作安全性，其中包括一个规避性的命令和控制框架。” 描述：夜鹰之所以脱颖而出，是因为其以操作安全和规避为核心原则，使其高度规避的信标能够绕过现代安全控制。它还提供了不为公众所知的独特功能，从而能够更有效地进行事后利用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAg3Py86HKiaIMOCoBO5XtiaEYAKibxq59q3SN85KwJfAXHsRib6wB6zkypnFRxbJPMHNYuOz2NtIrbBQ/640?wx_fmt=png&from=appmsg "")  

```
https://nighthawkc2.io/about/

```

## 5. Mythic  
  
作者： Cody Thomas（@its-a-feature）  
>   
> “跨平台、后漏洞利用的红队框架旨在为操作员提供协作且用户友好的界面。”  
  
  
描述： Mythic 是一款“关怀”运维人员的工具。抛开所有玩笑不谈，它确实让红队成员更容易维护特工，拥有强大的数据分析能力（追踪所有操作，包括谁在何时、使用何种工具执行了什么操作），从而实现更好的实时分析，并且支持自定义。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAg3Py86HKiaIMOCoBO5XtiaE1iarQbh3ydbibQFpPp35wNyJEIfvcrSRvYEfRngLicX57JAu4cCTtsicww/640?wx_fmt=png&from=appmsg "")  

```
https://docs.mythic-c2.net/

```

## 6.Metasploit  
  
作者： Rapid7（@rapid7）  
>   
> “世界上使用最广泛的渗透测试框架。”  
  
  
描述： Metasploit 提供了大量预构建的漏洞利用工具，方便渗透测试人员查找和发现漏洞。它功能多样，允许用户自动执行渗透测试任务、开发自定义漏洞利用工具以及执行各种漏洞利用后活动。大多数（即使不是全部）道德黑客，从初学者到经验丰富的黑客，都会使用此工具。  

```
https://github.com/rapid7/metasploit-framework

```

## 7.Merlin  
  
创作者：拉塞尔·范·图伊尔 ( @ne0nd0g )  
>   
> “用 Golang 编写的跨平台后利用 HTTP/2 命令与控制服务器和代理。”  
  
  
描述： Merlin 是一款后漏洞利用命令与控制 (C2) 工具，也称为远程访问工具 (RAT)，它使用 HTTP/1.1、HTTP/2 和 HTTP/3 协议进行通信。HTTP/3 是 HTTP/2 与快速 UDP 互联网连接 (QUIC) 协议的组合。该工具是我在一篇题为“检测和预防通过 HTTP/2 进行的 Web 应用程序攻击的实用方法”的论文中对 HTTP/2 进行评估的成果。  

```
https://github.com/Ne0nd0g/merlin

```

## 8.Empire  
  
维护者： BC Security（@BC-SECURITY）  
>   
> “用于协助红队和渗透测试人员的后利用和对手模拟框架。”  
  
  
描述： Empire C2 拥有丰富的高级功能，包括多语言代理（PowerShell、python3、C# 等）、庞大的支持工具库以及多样化的通信机制。它采用模块化设计，可轻松集成插件，并支持可自定义的绕过方式、集成的混淆和加密通信，使其在后漏洞利用活动中非常有效。  

```
https://github.com/BC-SECURITY/EmpireActive Directory

```

## 9.SharpHound  
  
作者： SpecterOps（@SpecterOps）  
  
“BloodHound 的 AC# 数据收集器。”  
  
描述： SharpHound 快速、全面，旨在精确提取红队成员所需的关系数据（组成员身份、信任和权限），以映射网络中的权限提升路径和横向移动。凭借灵活的收集选项以及与BloodHound的无缝集成，它是理解和利用 AD 信任关系的首选工具。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAg3Py86HKiaIMOCoBO5XtiaEVXOcPORw6dG8jotYa9vz6lqbdveu7LJBC0micXsRs4oOpoJ9qMdoJhA/640?wx_fmt=png&from=appmsg "")  

```
https://github.com/SpecterOps/SharpHound

```

## 10.BloodHound.py  
  
作者： Dirk-jan Mollema、Edwin van Vliet 和 Matthijs Gielen（@dirkjanm以及来自Fox-IT（NCC Group ）的其他人）  
>   
> “BloodHound 的基于 Python 的摄取器。”  
  
  
描述：它是一款轻量级、跨平台的传统采集器替代方案，允许远程收集 Active Directory 信息，而无需在目标系统上执行 .NET 二进制文件。它支持多种身份验证方法，并与最新的 BloodHound 版本兼容，是红队成员进行 AD 枚举的多功能选择。  

```
https://github.com/dirkjanm/BloodHound.py

```

## 11.  NetExec（以前称为CrackMapExec）  
  
作者： Marcello（@byt3bl33d3r）维护者： （NeffIsBack、Marshall-Hallenbeck、zblurx、mpgn_x64）  
>   
> “一个强大的网络服务开发工具，旨在自动评估大规模 Windows 和 Active Directory 环境。”  
  
  
描述： NetExec 通过简化验证凭证、执行命令和大规模探测系统，简化了网络操作。它专为速度和灵活性而打造。  

```
https://github.com/Pennyw0rth/NetExec

```

## 12.Certipy  
  
创作者： Oliver Lyak（@ly4k）  
>   
> “一种用于枚举和滥用 Active Directory 证书服务 (AD CS) 的攻击工具。”  
  
  
描述： Certipy 再次成为深入研究 AD 证书服务的首选。它简化了发现错误配置、提取凭据以及发起影子凭据和黄金票证等强力攻击的操作，而且无需大量设置。  

```
https://github.com/ly4k/Certipy

```

## 13.Impacket  
  
作者：SecureAuth  
>   
> “用于处理网络协议的 Python 类集合。”  
  
  
描述：对于注重精准度和控制力的红队成员来说，Impacket 是必备工具。它提供对 Windows 网络协议的低级访问，使其成为创建自定义攻击和自动执行后渗透任务的理想选择。  

```
https://github.com/fortra/impacket

```

## 14.MSLDAP  
  
作者：  SkelSec（@skelsec）  
>   
> “用于审计 MS AD 的 LDAP 库。”  
  
  
描述： MSLDAP 的交互式客户端有助于实时探索 Active Directory 结构，从而更轻松地识别错误配置和潜在攻击向量。无论您是编写复杂查询脚本还是进行实际评估，MSLDAP 都能简化与 AD 环境交互的流程。  

```
https://github.com/skelsec/msldap

```

## 15.GhostPack  
  
作者： GhostPack（@ghostpack），作者：Lee Chagolla-Christensen、Will Shroeder 和 Christopher Maddalena（@leechristensen、@HarmJ0y和@chrismaddalena）  
>   
> GhostPack是一套专为红队行动设计的 C# 工具，专注于 Windows 后期利用、凭证访问和 Active Directory 滥用。  
  
  
描述： GhostPack 汇集了红队武器库中一些最有效、最广泛使用的工具，例如用于防范 Kerberos 滥用的 Rubeus、用于主机侦察的 Seatbelt、用于防范 AD CS 攻击的 Certify 以及用于凭证提取的 SharpDPAPI。每个工具都是模块化的、可编写脚本的，并且在构建时充分考虑了操作安全性，使其成为隐秘攻击的理想选择。它是一款久经考验的工具包，已成为进攻性安全工作流程中不可或缺的一部分。  

```
https://github.com/ghostpack

```

## 16.Octopwn  
  
作者： Octopwn GMBH ( @octopwn )  
>   
> “一个模块化的、基于浏览器的红队平台，将必要的内部测试工具整合到一个界面中。”  
  
  
描述： OctoPwn 将扫描器和攻击工具打包到基于浏览器的 WebAssembly 界面中，该界面部署快速且易于使用。它支持 Nmap、BloodHound 和 Hashcat 数据，非常适合敏捷、模块化的渗透测试，即使在受监控的环境中也能轻松应对。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAg3Py86HKiaIMOCoBO5XtiaE6EuXtaRrUze2bHOGNQDmyCROsKufFnUwv1kjWOuVTdCaKBmjHuEBjw/640?wx_fmt=png&from=appmsg "")  

```
https://octopwn.com/

```

## 网络安全情报攻防站  
  
  
李白你好VIP社区-  
网络安全资源社区  
  
https://www.libaisec.com/  
  
代理访问效果更佳  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAg3Py86HKiaIMOCoBO5XtiaERFA4UgTAETiakfenaibaXnNzW2PfCNbXS00I1OGC5dlnUe4eHanVVfmg/640?wx_fmt=png&from=appmsg "")  
  
  

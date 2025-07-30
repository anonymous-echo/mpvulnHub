#  从CVE 到 PoC：Windows提权漏洞全景地图   
原创 再说安全  再说安全   2024-11-19 16:31  
  
LPE（本地权限提升）漏洞是操作系统或应用程序中由于设计缺陷或编码错误而导致的权限控制失效，它允许攻击者在已经获得低权限访问的情况下，提升权限至更高的级别，例如 root 或 SYSTEM。    
  
LPE对于红队来说，如同攻城掠地后的“登堂入室”，是实现攻击目标的关键一环。获取初始访问权限仅仅是第一步，就好比我们已经潜入了城堡的外围，但真正的目标是控制城堡的核心—系统管理员权限。LPE 漏洞，正是我们获取这把“万能钥匙”的途径。通过利用 LPE 漏洞，我们可以将低权限访问权限提升至 Root 或 SYSTEM 级别，从而完全控制受感染的系统为所欲为。  
  
今天分享的资源来源于一名  
安全研究员 Michael Zhmaylo 收集了一系列公开披露的影响Windows 操作系统的本地权限升级 (LPE) 漏洞的漏洞利用信息。该存储库托管在 Github 上，对于有兴趣了解和减轻权限升级攻击的安全研究人员、渗透测试人员和系统管理员来说，是宝贵的资源。  
  
该集合重点关注 2023 年和 2024 年披露的 LPE 漏洞，其中包含由各个研究人员开发和共享的Poc概念验证漏洞利用代码。虽然并不详尽，但该集合提供了**最新 Windows 版本中权限升级情况**的重要概述。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fkjOR3eVscbQVGQTLUfHz3yASHS8qdibo0PHvDjN722XV8aqSrH7rciaicZS9R9V7FhW9eaZcPfyiaawaQXZRF2x5w/640?wx_fmt=png&from=appmsg "")  
  
该存储库按 CVE 标识符进行组织，提供了一种结构化的方法来导航漏洞。该集合中包含的一些值得注意的 CVE 包括：  
  
**2023:**  
- CVE-2023-21674,CVE-2023-21746,CVE-2023-21752,CVE-2023-21768, CVE-2023-21817  
  
- CVE-2023-21674,CVE-2023-21746,CVE-2023-21752,CVE-2023-21768、CVE-2023-21817  
  
- CVE-2023-23388,CVE-2023-24871,CVE-2023-28218,CVE-2023-28229, CVE-2023-28252  
  
- CVE-2023-23388,CVE-2023-24871,CVE-2023-28218,CVE-2023-28229,CVE-2023-28252  
  
- CVE-2023-29336,CVE-2023-29360,CVE-2023-36003,CVE-2023-36424, CVE-2023-36723  
  
- CVE-2023-29336,CVE-2023-29360,CVE-2023-36003,CVE-2023-36424,CVE-2023-36723  
  
- CVE-2023-36802,CVE-2023-36874  
  
- CVE-2023-36802,CVE-2023-36874  
  
  
**2024:**  
- CVE-2024-20656,CVE-2024-21338,CVE-2024-21345,CVE-2024-21447,  
  
- CVE-2024-26218CVE-2024-20656,CVE-2024-21338  
  
- CVE-2024-21345,CVE-2024-21447,CVE-2024-26218  
  
- CVE-2024-26229,CVE-2024-30051,CVE-2024-30088,CVE-2024-30090  
  
- CVE-2024-35250CVE-2024-26229,CVE-2024-30051,CVE-2024-30088  
  
- CVE-2024-30090,CVE-2024-35250CVE-2024-38054,CVE-2024-38080  
  
- CVE-2024-38100,CVE-2024-6768CVE-2024-38054,CVE-2024-38080,CVE-2024-38100,CVE-2024-6768  
  
  
每个 CVE 文件夹可能包含有关漏洞的详细信息，包括利用代码、技术分析和潜在的缓解策略。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fkjOR3eVscbQVGQTLUfHz3yASHS8qdiboPBUC4UOtY4g4ArbvLibwJEmfapE7QEFqYFia0WYWEhHUTvwVmicTTfDbw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fkjOR3eVscbQVGQTLUfHz3yASHS8qdiboLGXXI5BWOz4PeHsth8eywjr4uTibFFSL0paicR3ian96D8iaIlyk2BVcmg/640?wx_fmt=png&from=appmsg "")  
  
建议该资源可用于：  
- 漏洞研究：  
分析漏洞代码以了解Windows系统中的潜在弱点。  
  
- 渗透测试：  
模拟现实世界的攻击以识别组织安全态势中的漏洞。  
  
- 安全意识培训：  
对 IT 员工和用户进行有关权限升级的风险以及安全最佳实践的重要性的教育。  
  
>> 访问地址：https://github.com/MzHmO/Exploit-Street  
  
  
  
  
如果您觉得文章对您有所帮助，还请您关注我！  
  
  
  
  
欢迎您加群讨论：安全技术交流、HW情报分享讨论群！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fkjOR3eVscaCk1Hrx5ZSFpF9UDIUtfHvQ8b6TeMurEZFtR78CA7581ecq66D1YVLhtaHsyX4D9VbcPYB5UkZ9w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

#  因不满漏洞分级，发现者公布WinServer2025 0day细节   
会杀毒的单反狗  军哥网络安全读报   2025-05-24 01:00  
  
**导****读**  
  
  
  
Akamai 安全团队和微软对未修补的“BadSuccessor”漏洞的严重性存在分歧，在微软拒绝立即发布补丁后，Akamai 公布了 Windows Server 2025 中存在的权限提升漏洞细节。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaHw3LpNt4kY4C8icGmkc2ibAiaibOT4aMgpZNqhCgWGibawxI5hUa8vTDQxVKz9zyeO6HItuQZG1IhbMQQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
“BadSuccessor”是 Windows Server 2025 中一个未修补的权限提升漏洞，允许攻击者攻击 Active Directory 中的任何用户。  
  
  
Akamai 研究员 Yuval Gordon 表示，微软安全响应中心确认了该漏洞的存在，但认为这是一个“中等”严重程度的问题，将在“未来”进行修补。  
  
  
“虽然我们感谢微软的回应，但我们不同意他们对该漏洞的严重性评估。”Gordon 在一篇博客文章中称，该文章包含一段概念验证代码，该代码将一个不起眼的服务账户迁移功能变成了一个重大安全风险。  
  
  
Gordon 表示，漏洞在于委托托管服务账户（dMSA），这是 Server 2025 中引入的一个全新账户类别。dMSA 旨在取代笨重的传统服务账户，但Gordon 发现它们继承了原有账户的所有权限。  
  
  
他提供了技术文档，展示了非特权用户可以采取的步骤来创建被视为合法继承人的全新 dMSA。  
  
  
域控制器只需这样做，就能将我们视为合法继承人。记住：无需更改组成员身份，无需触碰域管理员组，也无需对实际特权帐户进行任何可疑的 LDAP 写入操作。  
  
  
“只需更改两项属性，一个不起眼的新对象便被加冕为继承者——KDC 绝不会质疑其血统；只要存在关联，便会授予特权。我们没有更改任何群组成员身份，没有提升任何现有帐户的权限，也没有触发任何传统的特权提升警报。”他解释道。  
  
  
Akamai 对客户遥测进行了调查，发现在 91% 的环境中，至少有一名非管理员用户已经在组织单位中拥有有问题的Create-Child权限。  
  
  
Gordon 指出，这些权限足以启动 dMSA，但微软降低了严重性，因为攻击者需要“指示提升访问权限的特定权限”。由于 Windows Server 2025 域控制器默认启用 dMSA 支持，Gordon 表示，组织只需将 2025 DC 添加到现有的 Active Directory 林中，就会承担风险。  
  
  
他说，在微软表示不会立即提供补丁后，最终促使 Akamai 发布漏洞细节。 Gordon 表示：“他们将其评估为中等严重程度的漏洞，并表示目前尚未达到立即修复的门槛。”  
  
  
他警告说，该漏洞引入了一种以前未知且影响深远的滥用途径，使任何拥有 OU 的 CreateChild 权限的用户都可以危害域中的任何用户“并获得与执行 DCSync 攻击时使用的复制目录更改特权类似的权力”。  
  
  
Gordon补充道：“此外，我们没有发现任何迹象表明当前的行业实践或工具将CreateChild访问（或者更具体地说，针对dMSA的CreateChild）标记为关键问题。我们认为，这凸显了该问题的隐蔽性和严重性。”  
  
  
在补丁发布前披露信息的决定再次引发了关于负责任披露的争论。社交媒体上，一些研究人员批评Akamai在补丁发布前就公布了攻击补丁的全部细节。另一方面，老派黑客则表示，微软曾多次误诊并拒绝修复严重的安全问题。  
  
  
在没有官方补丁的情况下，Akamai 发布了检测查询、日志记录指南和脚本来定位可以创建 dMSA 的主体。  
  
  
Akamai  
公布的漏洞细节博客：  
  
https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory  
  
  
新闻链接：  
  
https://www.securityweek.com/akamai-microsoft-disagree-on-severity-of-unpatched-badsuccessor-flaw/  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  

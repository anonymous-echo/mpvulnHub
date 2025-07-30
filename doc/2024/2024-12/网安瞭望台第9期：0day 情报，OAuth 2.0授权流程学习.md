#  网安瞭望台第9期：0day 情报，OAuth 2.0授权流程学习   
原创 扬名堂  东方隐侠安全团队   2024-12-04 11:00  
  
网安资讯分享  
  
DAILY NEWS AND KNOWLEDGE  
  
  新鲜资讯&知识 抢先了解    
  
隐侠安全客栈  
  
**国内外要闻**  
  
  
**Veeam 修补服务提供商控制台关键 RCE 漏洞**  
  
      
Veeam 发布了安全更新以解决影响服务提供商控制台（VSPC）的一个关键漏洞，该漏洞可能为在易受攻击的实例上执行远程代码创造条件。此漏洞被追踪为 CVE-2024-42448，其 CVSS 评分高达 9.9（满分 10.0）。该公司指出，该漏洞是在内部测试中发现的。Veeam 在一份公告中称：“从 VSPC 管理代理机器出发，在管理代理在服务器上被授权的情况下，有可能在 VSPC 服务器机器上执行远程代码执行（RCE）。”  
  
      
  
    Veeam 修补的另一个缺陷涉及一个漏洞（CVE-2024-42449，CVSS 评分：7.1），该漏洞可能被滥用来泄露 VSPC 服务器服务账户的 NTLM 哈希值并删除 VSPC 服务器机器上的文件。所发现的这两个漏洞均影响 Veeam 服务提供商控制台 8.1.0.21377 及 7 和 8 版本的所有早期版本，已在 8.1.0.21999 版本中得到修复。Veeam 进一步表示，没有缓解措施来解决这些问题，唯一的解决方案是升级到软件的最新版本。由于 Veeam 产品的漏洞被威胁行为体滥用来部署勒索软件，用户必须尽快采取行动保护其实例。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4Qk78bN0hx8spM0YUkRJeJztq4qFyORf0ibXrepe29OvCia12l9WHKyq1plMgr41Qs2tpmmrWrg1CA/640?wx_fmt=other&from=appmsg "")  
  
  
  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
**SailPoint IdentityIQ 关键漏洞致文件遭未授权访问**  
  
      
SailPoint 的 IdentityIQ 身份与访问管理（IAM）软件被披露存在一个关键安全漏洞，该漏洞可使应用程序目录内存储的内容被未授权访问。此漏洞被追踪为 CVE-2024-10905，CVSS 评分为 10.0，表明其严重程度极高，影响 IdentityIQ 8.2、8.3、8.4 及其他之前的版本。根据美国国家标准与技术研究院（NIST）国家漏洞数据库（NVD）对该漏洞的描述，IdentityIQ “允许对 IdentityIQ 应用程序目录中本应受保护的静态内容进行 HTTP 访问”。该漏洞被归类为对标识虚拟资源的文件名处理不当（CWE-66）的情况，可能会被滥用来读取原本无法访问的文件。  
  
    目前关于该漏洞暂无更多详细信息，SailPoint 也未发布安全公告。受 CVE-2024-10905 影响的具体版本列表如下：8.4 及 8.4p2 之前的所有 8.4 补丁版本；8.3 及 8.3p5 之前的所有 8.3 补丁版本；8.2 及 8.2p8 之前的所有 8.2 补丁版本以及所有之前的版本。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4Qk78bN0hx8spM0YUkRJeJo0oC3z9bVmL0uypAssO7reiaKRTkJRicNrLbeAl6eiacoThVSpP70kkVw/640?wx_fmt=other&from=appmsg "")  
  
  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
**黑客利用损坏的 ZIP 和 Office 文档规避杀毒与邮件防护**  
   
  
      
网络安全研究人员提醒注意一场新颖的网络钓鱼活动，该活动利用损坏的微软 Office 文档和 ZIP 压缩包来绕过邮件防护。ANY.RUN 在 X 平台上的一系列帖子中称：“正在进行的攻击规避了杀毒软件，阻止上传至沙箱，并绕过了 Outlook 的垃圾邮件过滤器，使恶意邮件能够进入收件箱。”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4Qk78bN0hx8spM0YUkRJeJA1cqUHj0At5ib0sSJ59jnXgKz0MYA8p2cTYb9ial1XaYFOy6affibDxZQ/640?wx_fmt=jpeg&from=appmsg "")  
  
    恶意活动包括发送包含 ZIP 压缩包或 Office 附件的邮件，这些附件被故意损坏，以致安全工具无法对其进行扫描。这些邮件旨在以虚假的员工福利和奖金承诺诱使用户打开附件。  
  
    换言之，文件的损坏状态意味着它们不会被邮件过滤器和杀毒软件标记为可疑或恶意。然而，攻击之所以仍能得逞，是因为它利用了 Word、Outlook 和 WinRAR 等程序的内置恢复机制，在恢复模式下重新启动此类损坏文件。  
  
    ANY.RUN 透露，自 2024 年 8 月起，威胁行为体就至少已采用了这种攻击技术，将其描述为一种被利用来规避检测的潜在零日漏洞。这些攻击的最终目的是欺骗用户打开陷阱文档，其中嵌入的二维码，一旦扫描，就会将受害者重定向到用于部署恶意软件的欺诈性网站或用于窃取凭证的虚假登录页面。  
  
    这些发现再次表明，不良行为者如何不断寻找前所未见的技术来绕过邮件安全软件，并确保他们的钓鱼邮件进入目标收件箱。ANY.RUN 表示：“尽管这些文件在操作系统中能成功运行，但由于大多数安全解决方案未能对其文件类型应用适当程序，它们仍未被检测到。由于攻击者利用的内置恢复机制，安全工具无法检测到该文件，但用户应用程序却能无缝处理它。”   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4Qk78bN0hx8spM0YUkRJeJGic5BaL9DYay7VERiaYZTb9ibHib43oTkPX808ic8eibickibMFoibgicfPpX4fQ/640?wx_fmt=jpeg&from=appmsg "")  
  
16日，吉林舒兰灾后住  
  
房重建（修缮）工  
  
  
  
  
**思科预警十年前 ASA WebVPN 漏洞遭利用**  
   
  
      
周一，思科更新了一份公告，警告客户其自适应安全设备（ASA）中存在的一个十年之久的安全漏洞正遭活跃利用。该漏洞被追踪为 CVE-2014-2120（CVSS 评分：4.3），涉及 ASA 的 WebVPN 登录页面输入验证不足的情况，这可能使未经身份验证的远程攻击者对该设备的目标用户进行跨站脚本（XSS）攻击。思科在 2014 年 3 月发布的警报中指出：“攻击者可通过诱使用户访问恶意链接来利用此漏洞。”  
  
    截至 2024 年 12 月 2 日，这家网络设备巨头修订了其公告，指出已察觉到该漏洞在野外“有更多的利用尝试”。  
  
    此前不久，网络安全公司 CloudSEK 披露，AndroxGh0st 背后的威胁行为体正在利用各种面向互联网应用中的大量安全漏洞（包括 CVE-2014-2120）来传播恶意软件。此次恶意活动因整合了 Mozi 僵尸网络而引人注目，这使得 AndroxGh0st 得以进一步扩大规模和范围。  
  
    因此，美国网络安全与基础设施安全局（CISA）上个月将该漏洞添加到其已知被利用漏洞（KEV）目录中，要求联邦民用行政部门（FCEB）机构在 2024 年 12 月 3 日前修复该漏洞。强烈建议思科 ASA 用户保持其安装的设备为最新版本，以获得最佳保护并防范潜在的网络威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4Qk78bN0hx8spM0YUkRJeJibq4ic6mEqY9CRRHEFDa0UdiaZmCF4PsPbb1bnUI6t3lS0xelibbsPzjqg/640?wx_fmt=other&from=appmsg "")  
  
16日，吉林舒兰灾后住  
  
房重建（修缮）工  
  
  
  
作已启  
  
动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
**知识分享**  
  
  
Active Directory攻击方法  
  
  
**1. Kerberoasting（01）**  
  
    原理：Kerberoasting 是一种针对 Kerberos 协议的攻击。攻击者通过获取服务票据（TGS tickets），并尝试离线破解这些票据来获取服务账户的密码。  
  
    防范措施：使用强密码策略，定期更换服务账户密码，并限制服务票据的有效期。  
  
  
**2. Password Spraying（02）**  
  
    原理：密码喷洒是一种暴力破解的变种。攻击者使用少量常见密码尝试登录多个用户账户，以避免触发账户锁定机制。  
  
    防范措施：实施多因素认证（MFA），监控登录失败尝试，并设置合理的账户锁定策略。  
  
  
**3. Local Loop Multicast Name Resolution (LLMNR)**（03）  
  
    原理：LLMNR 是一种本地网络名称解析协议。攻击者利用 LLMNR 的漏洞，通过发送恶意响应来诱骗客户端连接到攻击者控制的机器。  
  
    防范措施：在网络中禁用 LLMNR 和 NetBIOS over TCP/IP，或者使用网络访问控制（NAC）来防止未经授权的连接。  
  
  
**4. Pass - the - hash with Mimikatz（04）**  
  
    原理：Mimikatz 是一种工具，攻击者使用它来获取 Windows 系统中的密码哈希值，并通过传递哈希（Pass - the - hash）技术来冒充合法用户。  
  
    防范措施：使用 Windows Credential Guard 来保护哈希值，定期更新系统和应用程序，并监控系统的异常活动。  
  
  
**5. Hard - coded Credentials（05）**  
  
    原理：硬编码凭证是指开发者在代码中直接写入用户名和密码。攻击者通过获取代码或配置文件来获取这些凭证。  
  
    防范措施：避免在代码中硬编码凭证，使用配置文件或密钥管理系统来存储敏感信息，并确保这些存储方式的安全性。  
  
  
**6. Privilege Escalation（06）**  
  
    原理：特权提升是指攻击者通过利用系统漏洞或配置错误，将其权限从普通用户提升到管理员或系统级别的权限。  
  
    防范措施：定期进行系统漏洞扫描和修复，实施最小权限原则（Least Privilege Principle），并监控系统的权限变化。  
  
  
**7. LDAP Reconnaissance（07）**  
  
    原理：LDAP（轻型目录访问协议）侦察是指攻击者通过查询 LDAP 目录来获取用户、组和其他资源的信息，以便进行进一步的攻击。  
  
    防范措施：限制 LDAP 查询权限，实施访问控制列表（ACL），并监控 LDAP 查询活动。  
  
  
**8. BloodHound Reconnaissance（08）**  
  
    原理：BloodHound 是一种工具，攻击者使用它来分析和可视化 Active Directory 中的关系，以便找到攻击路径。  
  
    防范措施：定期审查和清理 Active Directory 中的关系，限制对 Active Directory 数据的访问，并监控异常的查询活动。  
  
  
**9. NTDS.dit Extraction（09）**  
  
    原理：NTDS.dit 是 Windows 域控制器上存储 Active Directory 数据库的文件。攻击者通过获取该文件来提取用户密码哈希值和其他敏感信息。  
  
    防范措施：保护域控制器的物理和网络安全，定期备份和恢复 NTDS.dit 文件，并监控文件的访问活动。  
  
  
**10. LADP Reconnaissance（10）**  
  
    原理：与 LDAP Reconnaissance 类似，攻击者通过查询 LADP（轻型目录访问协议）来获取用户、组和其他资源的信息。  
  
    防范措施：限制 LADP 查询权限，实施访问控制列表（ACL），并监控 LADP 查询活动。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4Qk78bN0hx8spM0YUkRJeJm13wTDkyb2WfZ5OhWe1yR92tZu0xrEIicaPyTNr9HbncMOjncWeyu0w/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
**OAuth 2.0 的四种授权流程（Flows）**  
  
    OAuth 2.0 是一种广泛使用的授权框架，通过不同的授权流程，可以在保障安全的前提下，实现第三方应用对用户资源的访问。每种流程都有其适用场景和安全考虑，正确选择和实施授权流程对于保护用户数据和系统安全至关重要。  
  
  
**1. Authorization Code（授权码）**  
  
  
流程：  
1. 用户代理（浏览器）：用户通过浏览器访问客户端应用程序（Client），请求访问资源。  
  
1. 客户端：将用户重定向到授权服务器（Authorization Server），并附带客户端 ID 和重定向 URI 等信息。  
  
1. 授权服务器：验证用户身份后，返回一个授权码（Authorization Code）给客户端（通过重定向 URI）。  
  
1. 客户端：收到授权码后，使用授权码向授权服务器请求访问令牌（Access Token）。  
  
1. 授权服务器：验证授权码后，发放访问令牌给客户端。  
  
1. 客户端：使用访问令牌访问资源服务器（Resource Server）获取用户数据。  
  
安全考虑：  
- 授权码只能使用一次，且有效期较短，防止重放攻击。  
  
- 客户端必须保持其客户端密钥（Client Secret）的机密性，防止泄露。  
  
**2. Implicit Code（隐式授权）**  
  
流程：  
1. 用户代理（浏览器）：用户通过浏览器访问客户端应用程序，请求访问资源。  
  
1. 客户端：将用户重定向到授权服务器，并附带客户端 ID 和重定向 URI 等信息。  
  
1. 授权服务器：验证用户身份后，直接返回访问令牌给客户端（通过重定向 URI）。  
  
1. 客户端：使用访问令牌访问资源服务器获取用户数据。  
  
安全考虑：  
- 由于访问令牌直接返回给客户端，没有中间的授权码步骤，存在令牌泄露的风险。  
  
- 适用于无法安全存储客户端密钥的场景，如 JavaScript 客户端。  
  
**3. Client Credentials（客户端凭证）**  
  
流程：  
1. 客户端：使用自己的客户端 ID 和客户端密钥向授权服务器请求访问令牌。  
  
1. 授权服务器：验证客户端凭证后，发放访问令牌给客户端。  
  
1. 客户端：使用访问令牌访问资源服务器获取资源。  
  
安全考虑：  
- 客户端密钥必须严格保密，防止泄露。  
  
- 适用于没有用户参与的场景，如后台服务间的通信。  
  
  
**4. Resource Owner Password（资源所有者密码）**  
  
流程：  
1. 客户端：获取用户的用户名和密码，然后使用这些信息向授权服务器请求访问令牌。  
  
1. 授权服务器：验证用户的用户名和密码后，发放访问令牌给客户端。  
  
1. 客户端：使用访问令牌访问资源服务器获取用户数据。  
  
安全考虑：  
- 客户端必须安全地处理用户的密码，防止泄露。  
  
- 这种方式存在较高的安全风险，因为客户端需要直接处理用户密码，通常只在高度信任的环境下使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4Qk78bN0hx8spM0YUkRJeJGX0EqvISHDLKfzye3JdjVOr11SNWWlm9WZAoV4ETMNGm4aBOsVh7Yw/640?wx_fmt=png&from=appmsg "")  
  
  
知识大陆：内部交流群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4ia9bxBntLSKSlHqNOuicVUcck4sIKJu0aaBFsBJf700WwMLhUNpqz6VlAtLzbJV1hwiawcRwCan8eQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
关注东方隐侠安全团队 一起打造网安江湖  
  
        
  东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  

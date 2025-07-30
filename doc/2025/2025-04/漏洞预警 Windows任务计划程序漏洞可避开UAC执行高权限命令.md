#  漏洞预警| Windows任务计划程序漏洞可避开UAC执行高权限命令   
 SecHub网络安全社区   2025-04-17 01:43  
  
****  
****  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**免责声明**  
  
本文发布的工具和脚本，仅用作测试和学习研究，禁止用于商业用途，不能保证其合法性，准确性，完整性和有效性，请根据情况自行判断。  
  
如果任何单位或个人认为该项目的脚本可能涉嫌侵犯其权利，则应及时通知并提供身份证明，所有权证明，我们将在收到认证文件后删除相关内容。  
  
文中所涉及的技术、思路及工具等相关知识仅供安全为目的的学习使用，任何人不得将其应用于非法用途及盈利等目的，间接使用文章中的任何工具、思路及技术，我方对于由此引起的法律后果概不负责。  
## 🌟简介     
##     涉及 schtasks.exe 二进制文件的 Windows 关键任务计划程序，可能使恶意行为者以系统级别权限执行命令，绕过用户账户控制（UAC）提示并擦除审计日志。  
##     这些漏洞显著提高了 Windows 环境的威胁态势，带来了权限提升、隐蔽系统操作和数据泄露的风险。  
##     问题核心在于 Windows 任务计划程序，这是一个负责自动化任务的必要系统服务。用户和管理员可以创建、修改和管理本地和远程计划任务。研究人员已经发现了多个漏洞，可以利用这些漏洞绕过安全控制并获得系统权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZoRHybzGNHt0loMlzr4F4qqY3icrXmz6JRu8FcLMgz9YsAMDCE0xYedogIZJpeUI67uRHMCStgoWOw/640?wx_fmt=png&from=appmsg "")  
  
## Windows 任务计划程序漏洞  
  
      
最令人担忧的漏洞之一涉及通过使用批登录凭据创建的计划任务绕过用户账户控制（UAC）。  
  
    通常，使用密码（批登录）创建计划任务需要明确的凭据，但攻击者可以利用此过程提升权限而无需用户同意。  
  
    当攻击者使用批登录创建任务时，任务计划程序将代表攻击者以最大权限执行，实际上在执行时授予了 SYSTEM 级别的访问权限。  
  
    此过程绕过了最高的 UAC 设置，通常在执行高权限命令之前会提示用户批准。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZoRHybzGNHt0loMlzr4F4qqmVXCflNqCwktHOF3rQm0SHdkibTFWhX6Z1UibqM6UXqbFvy7icIukIECw/640?wx_fmt=png&from=appmsg "")  
  
    网络安全研究人员已经证明，通过制作带有操纵元数据的恶意 XML 文件，例如填充了 oversized buffers 的作者标签，攻击者可以毒化任务事件日志，甚至溢出安全日志如 Security.evtx  
 。  
  
      
这些技术允许攻击者通过覆盖日志来掩盖行踪，使得检测变得困难。  
  
    此外，漏洞还扩展到远程攻击向量。通过利用 RPC 接口，恶意行为者可以将有毒的 XML 数据注入任务日志，覆盖审计跟踪，甚至破坏整个安全日志，从而有效地抹去恶意活动的证据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZoRHybzGNHt0loMlzr4F4qq2x5n19757icCpDBKy8v5HFWV3XzPUicSRNT8eQUh3xiaeXHYMSQGcy6nA/640?wx_fmt=png&from=appmsg "")  
  
任务元数据和日志条目缺乏严格的验证，使得此类攻击得以实施。  
  
    这些漏洞最严重的后果是低权限用户可以冒充 SYSTEM 或管理员账户。例如，一个拥有低权限账户访问权限的攻击者可以：  
- 使用已知密码创建计划任务，然后通过利用批处理登录漏洞提升至 SYSTEM 权限。  
  
- 使用元数据投毒技术将恶意活动隐藏在日志中。  
  
- 覆盖安全事件日志，包括 Security.evtx  
 ，有效擦除入侵痕迹。  
  
    这种提升权限和日志操作的组合使攻击者能够维持对受侵害系统的持续、隐蔽访问，使得检测和修复变得极其困难。  
  
    这些漏洞威胁到 Windows 环境的核心理念安全。通过利用这些缺陷：- 攻击者可以以 SYSTEM 身份执行任意命令，获得对主机的完全控制。  
  
- 他们可以绕过 UAC 提示，这些提示旨在防止未经授权的权限提升。  
  
- 他们可以操纵或删除审计日志，阻碍事件响应工作。  
  
# 来源  
```
https://cybersecuritynews.com/windows-taskmanager-vulnerabilities/
```  
  
  
  
欢迎关注SecHub网络安全社区，SecHub网络安全社区目前邀请式注册，邀请码获取见公众号菜单【邀请码】  
  
**#**  
  
  
**企业简介**  
  
  
**赛克艾威 - 网络安全解决方案提供商**  
  
****  
       北京赛克艾威科技有限公司（简称：赛克艾威），成立于2016年9月，提供全面的安全解决方案和专业的技术服务，帮助客户保护数字资产和网络环境的安全。  
  
  
安全评估|渗透测试|漏洞扫描|安全巡检  
  
代码审计|钓鱼演练|应急响应|安全运维  
  
重大时刻安保|企业安全培训  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**联系方式**  
  
电话｜010-86460828   
  
官网｜https://sechub.com.cn  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0FW5uwU0BZtn2lmMrLPwpibCeCVbtBFDRkbFb7n7ibhPRxg20spUo9mUIiakmRYABB88Idl81IpGuXfw/640?wx_fmt=gif "")  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwyhlWCYDVqK38BA5dbjKkH7icWmAew7SYRA7ao1bFibialrMvmQ9ib0TBvw/640?wx_fmt=jpeg "")  
  
  
**公众号：**  
sechub安全  
  
**哔哩号：**  
SecHub官方账号  
  
  

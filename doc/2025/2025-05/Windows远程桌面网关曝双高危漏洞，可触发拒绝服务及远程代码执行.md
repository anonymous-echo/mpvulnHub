#  Windows远程桌面网关曝双高危漏洞，可触发拒绝服务及远程代码执行   
 FreeBuf   2025-05-15 10:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ic9g6mOZiaQnNf7kIKxgDT1s1EvkMnwyeGIPOn2INhwzUckC4ove7QDNMbRlM2AZqWQbYfacPicbP6A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软安全响应中心(MSRC)已发布重要安全更新，修复Windows远程桌面网关(RD)服务中的一个高危漏洞(CVE-2025-26677)。该漏洞可能允许未经授权的攻击者触发拒绝服务(DoS)条件，潜在影响企业环境中的远程访问能力。  
  
  
此外，微软还针对RD网关远程代码执行漏洞(CVE-2025-29831)发布了补丁，该漏洞可能破坏系统运行或危及系统完整性。  
  
### Part01  
### 远程桌面网关服务DoS漏洞(CVE-2025-26677)  
  
  
技术分析表明，该漏洞源于远程桌面网关服务中的资源消耗不受控问题，允许未经身份验证的远程攻击者耗尽系统资源，通过网络连接造成服务中断。  
  
  
该漏洞被归类为CWE-400(不受控的资源消耗)。熟悉此事的安全专家解释称："这个漏洞特别令人担忧，因为它不需要用户交互，且未经身份验证的远程攻击者即可利用。依赖远程桌面服务进行日常运营的组织如果被攻击，可能面临严重的运营中断。"  
  
  
微软将该漏洞评为"高危"级别，CVSS基础评分为7.5(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:C)。该评分反映了漏洞的网络攻击向量、低攻击复杂度以及对系统可用性的高影响潜力，但不会影响数据机密性或完整性。  
  
  
多个Windows Server版本受影响，包括Windows Server 2016、Server 2019、Server 2022和最新的Server 2025。微软已发布安全更新(KB5058383、KB5058392、KB5058385和KB5058411)在所有受影响平台上修复此问题。  
  
  
根据微软的可利用性评估，目前认为该漏洞被主动利用的可能性"较低"。但仍强烈建议系统管理员立即应用补丁作为标准安全维护程序的一部分。昆仑实验室的安全研究人员发现了该漏洞，并通过协调漏洞披露报告给微软。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic9g6mOZiaQnNf7kIKxgDT1snjLSzVjEBiaCNmvH6xSP6rjWnoqA6r4beicmGNDvgfu8pCdywqSl3DuQ/640?wx_fmt=png&from=appmsg "")  
  
### Part02  
### 远程桌面网关RCE漏洞(CVE-2025-29831)  
  
  
另一个影响相同服务组件的相关漏洞是CVE-2025-29831，该漏洞可能通过释放后使用(Use After Free)弱点实现远程代码执行。该漏洞CVSS评分为7.5，需要用户交互(管理员用户停止或重启服务)。  
  
  
组织应在维护窗口优先修补这两个漏洞。虽然尚未发现野外利用，但此类网关服务经常被威胁行为者作为网络入口点攻击目标。  
  
  
远程桌面网关服务对组织尤为重要，它们为远程工作人员提供到内部资源的安全连接。该漏洞可能影响已部署启用远程桌面网关角色并暴露在互联网上的Windows Server的组织。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic9g6mOZiaQnNf7kIKxgDT1sJH0G7FedRlrUB00KYtpMYwjia9OwAibVbNSIEKbOOgQMicEB97utWz4vw/640?wx_fmt=png&from=appmsg "")  
  
  
微软安全更新指南指出，当攻击者在服务中"触发资源耗尽"时就会利用CVE-2025-26677，这表明一旦被潜在威胁行为者发现，攻击方法可能相对简单。使用受影响Windows Server版本的组织应立即实施微软的安全更新，并考虑审查网络配置，将远程桌面网关服务的暴露范围限制在可信网络中。  
  
  
**参考来源：**  
  
**Windows Remote Desktop Gateway Vulnerability Let Attackers Trigger Dos Condition**https://cybersecuritynews.com/windows-remote-desktop-gateway-vulnerability/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320343&idx=1&sn=4092a85b3c9cd6eea8dc0dcb48620652&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

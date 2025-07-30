#  恶意软件家族：国家行为者武器化Ivanti VPN零日漏洞   
THN  知机安全   2024-01-13 12:18  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfO8Hf65WOp2pe5ABUsZagJnxt1awGkicIVV5ic0QPVSVo2FW7w5U0fUY1L2OlLYh884OjUEecNTGZlQ/640?wx_fmt=other&from=appmsg "")  
  
  
As many as five different malware families were deployed by suspected nation-state actors as part of post-exploitation activities leveraging two zero-day vulnerabilities in Ivanti Connect Secure (ICS) VPN appliances since early December 2023.  
  
自12月初以来，涉嫌国家行为者利用Ivanti Connect Secure（ICS）VPN设备的两个零日漏洞，部署了多达五个不同的恶意软件家族作为后期利用活动的一部分。  
  
"These families allow the threat actors to circumvent authentication and provide backdoor access to these devices," Mandiant said in an analysis published this week. The Google-owned threat intelligence firm is tracking the threat actor under the moniker **UNC5221**.  
  
“这些家族允许威胁行为者绕过身份验证并提供对这些设备的后门访问，”Mandiant在本周发表的一篇分析中说道。这家属于谷歌所有的威胁情报公司正在追踪以UNC5221为代号的威胁行为者。  
  
The attacks leverage an exploit chain comprising an authentication bypass flaw (CVE-2023-46805) and a code injection vulnerability (CVE-2024-21887) to take over susceptible instances.  
  
这些攻击利用了一个认证绕过漏洞（CVE-2023-46805）和一个代码注入漏洞（CVE-2024-21887）的利用链，以接管易受攻击的实例。  
  
Volexity, which attributed the activity to a suspected Chinese espionage actor named UTA0178, said the twin flaws were used to gain initial access, deploy webshells, backdoor legitimate files, capture credentials and configuration data, and pivot further into the victim environment.  
  
Volexity将这一活动归因于一名疑似的中国间谍行为者，代号为UTA0178，称这两个漏洞被用于获取初始访问权限，部署Webshell，后门合法文件，捕获凭据和配置数据，并进一步深入受害者环境。  
  
According to Ivanti, the intrusions impacted less than 10 customers, indicating that this could be a highly-targeted campaign. Patches for the two vulnerabilities (informally called ConnectAround) are expected to become available in the week of January 22.  
  
根据Ivanti的说法，这些入侵影响不到10个客户，表明这可能是一场高度针对性的攻击活动。这两个漏洞的补丁（非正式称为ConnectAround）预计将在1月22日的那周发布。  
  
Mandiant's analysis of the attacks has revealed the presence of five different custom malware families, besides injecting malicious code into legitimate files within ICS and using other legitimate tools like BusyBox and PySoxy to facilitate subsequent activity.  
  
Mandiant对攻击的分析揭示了五个不同的定制恶意软件家族的存在，除了在ICS中注入恶意代码外，还使用了其他合法工具，如BusyBox和PySoxy，来促进后续活动。  
  
"Due to certain sections of the device being read-only, UNC5221 leveraged a Perl script (sessionserver.pl) to remount the filesystem as read/write and enable the deployment of THINSPOOL, a shell script dropper that writes the web shell LIGHTWIRE to a legitimate Connect Secure file, and other follow-on tooling," the company said.  
  
“由于设备的某些部分是只读的，UNC5221利用Perl脚本（sessionserver.pl）重新挂载文件系统为读/写，并启用THINSPOOL的部署，这是一个Shell脚本投放程序，将Webshell LIGHTWIRE写入合法的Connect Secure文件，以及其他后续工具，”该公司表示。  
  
LIGHTWIRE is one of the two web shells, the other being WIREFIRE, which are "lightweight footholds" designed to ensure persistent remote access to compromised devices. While LIGHTWIRE is written in Perl CGI, WIREFIRE is implemented in Python.  
  
LIGHTWIRE是两个Webshell之一，另一个是WIREFIRE，它们是设计用于确保对被攻击设备的持续远程访问的“轻量级立足点”。LIGHTWIRE是用Perl CGI编写的，而WIREFIRE则是用Python实现的。  
  
Also used in the attacks are a JavaScript-based credential stealer dubbed WARPWIRE and a passive backdoor named ZIPLINE that's capable of downloading/uploading files, establishing a reverse shell, creating a proxy server, and setting up a tunneling server to dispatch traffic between multiple endpoints.  
  
在攻击中还使用了基于JavaScript的凭证窃取器WARPWIRE和名为ZIPLINE的被动后门，该后门能够下载/上传文件，建立反向Shell，创建代理服务器，并设置一个用于在多个端点之间分发流量的隧道服务器。  
  
"This indicates that these are not opportunistic attacks, and UNC5221 intended to maintain its presence on a subset of high priority targets that it compromised after a patch was inevitably released," Mandiant further added.  
  
“这表明这些不是机会主义性的攻击，UNC5221打算在不可避免地发布补丁后，维持对一些高优先级目标的存在，”Mandiant进一步补充道。  
  
UNC5221 has not been linked to any previously known group or a particular country, although the targeting of edge infrastructure by weaponizing zero-day flaws and the use of compromise command-and-control (C2) infrastructure to bypass detection bears all the hallmarks of an advanced persistent threat (APT).  
  
尽管UNC5221尚未与任何先前已知的组织或特定国家联系起来，但通过武器化零日漏洞攻击边缘基础设施，并使用妥协的命令和控制（C2）基础设施来绕过检测，具有高级持久性威胁（APT）的所有特征。  
  
"UNC5221's activity demonstrates that exploiting and living on the edge of networks remains a viable and attractive target for espionage actors," Mandiant said.  
  
“UNC5221的活动表明，利用和生存于网络边缘仍然是间谍行为者的一个可行且有吸引力的目标，”Mandiant表示。  
  

#  恶意软件campaign利用Avast Anti-Rootkit驱动程序的漏洞   
鹏鹏同学  黑猫安全   2024-11-26 02:43  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9ArCOAypgffqq7QO5KFBVojx4liaia3ib4sTibg8bicsr7NrHrgBJSMYxwls3BIyJhFe46ZWwDHU0okIA/640?wx_fmt=png&from=appmsg "")  
  
特里克斯（Trellix）研究人员发现了一场恶意软件campaign，攻击者利用Avast Anti-Rootkit驱动程序（aswArPot.sys）的漏洞，获取目标系统的更深入访问权限，禁用安全解决方案，并获取系统控制。这种危险的策略会损害可靠的内核模式驱动程序，将其变成终止保护进程和感染系统的工具。  
  
攻击者目标了多个产品，包括Avast、ESET、McAfee、Microsoft Defender、SentinelOne、Sophos和Trend Micro。  
  
特里克斯报告中写道：“恶意软件（kill-floor.exe）的感染链开始于将合法的Avast Anti-Rootkit驱动程序（aswArPot.sys）下降到‘C:\Users\Default\AppData\Local\Microsoft\Windows’目录中的‘ntfs.bin’文件中。”  
  
下一步，恶意软件使用Service Control（sc.exe）创建名为‘aswArPot.sys’的服务，并将驱动程序注册用于进一步的操作。驱动程序安装和运行后，恶意软件 gain kernel-level访问权限，提供了终止关键安全进程和控制系统的能力。  
  
这种漏洞的存在表明，攻击者可以使用合法的驱动程序来获取系统的敏感权限，以便进行恶意活动。因此，用户应该尽快更新Avast Anti-Rootkit驱动程序，并采取其他安全措施来保护自己的系统。  
  
Avast Anti-Rootkit驱动程序aswArPot.sys在内核级别运行，使恶意软件能够获得对操作系统的无限制访问。该恶意软件包含一个包含142个硬编码安全进程名称的列表，这些进程与来自各种供应商的产品相关联。  
  
组织应实施BYOVD（Bring Your Own Vulnerable Driver）保护措施，以保护系统免受利用易受攻击驱动程序的攻击。这些攻击利用合法但存在漏洞的驱动程序获得内核级别访问，从而绕过安全措施。部署专家规则以检测和阻止这些驱动程序基于其独特的签名或哈希值是至关重要的。  
  
报告中还包含了此次campaign的入侵指标（IoCs）。  
  

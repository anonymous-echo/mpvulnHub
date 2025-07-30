#  勒索软件Akira突破思科SSL VPN漏洞，横扫110个组织，攻击持续升级   
 关键基础设施安全应急响应中心   2023-09-27 15:49  
  
在黑客利用思科SSL VPN漏洞CVE-2023-20269入侵相关组织，加密Windows、Linux电脑档案后，勒索软件Akira攻击态势持续延烧，上个月成为前10大的勒索软体家族，超过110个组织遭Akira锁定。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6yIf1FIvDhOH9sdjpEzZTnFFuIAh2ibicic3tD3XmCicDDwTJj51Nic1Y7Q0TcWicRbbSOtaEiaeJakeEUbQ/640?wx_fmt=png&wxfrom=13 "")  
  
今年5月研究人员观察到勒索软件Akira采用了过往较为少见的攻击手法，黑客疑似针对尚未采用双因素验证的SSL VPN系统下手，从而入侵受害组织，这样的手法引起不少研究  
人员对于该黑客组织的高度关注。  
  
后来到了8月，恶意软件分析员Aura确认被针对的SSL VPN系统厂牌是思科。  
而且，黑客应该是针对该系统的漏洞下手，绕过双因素验证流程。  
当时，确认有8起勒索软件攻击是透过该厂牌的SSL VPN系统入侵，并且研究发现也有人利用类似手法散布勒索软件LockBit。  
  
这样的发现，在9月上旬得到思科的证实，勒索软件Akira就是利用CVE-2023-20269入侵组织的内部网络环境，漏洞存在于该厂牌的网络资安设备ASA、FTD系列，攻击者可在未经授权的情况下，借由暴力破解攻击找出有效的帐号及密码，甚至有可能透过未经授权的用户，建立无客户端的SSL VPN连线。  
  
最近有新的分析指出，勒索软体黑客组织Akira的攻击行动持续升温。  
今年8月Akira是第4大的勒索软体，仅次于LockBit 3.0、8Base、BlackCat（Alphv），截至9月15日，总共有110个组织受害，这些组织大部分位于美国和英国，但黑客没有偏好特定产业，受害组织涵盖教育、金融、房仲、制造、顾问业者，当中包含大型生产流程质量检验业者Intertek。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6yIf1FIvDhOH9sdjpEzZTnFdY8wOnHN8EXj3DhGUoxNhuf4S28Z8wNuJtwFpG3dHefg3WkpXzDdicg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
研究人员指出，一旦黑客得到内部网络的访问权限，就会使用远程桌面连线工具AnyDesk、RustDesk，以及压缩软件WinRAR来进行后续攻击行动，并且利用系统信息工具PC Hunter及wmiexec横向移动。  
  
此外，为了让档案加密工作能顺利执行，黑客会停用Windows内建的防毒软件实时监控功能，并使用PowerShell下达删除磁盘区阴影复制服务（VSS）的备份档案。  
此外，这些黑客也开发了Linux版的加密程序，可用来加密VMware ESXi虚拟机的档案，进行绑架勒赎。  
  
勒索软体黑客采取寄生攻击（LOLBins）手法，利用企业组织内现成的应用程序，执行攻击行动，来回避系统侦测的情况可说是非常普遍。  
其中，有许多黑客组织，如：  
LockBit、BlackByte以及专门针对SQL Server的勒索软件FreeWorld，滥用远程桌面连线工具AnyDesk来存取受害主机，Akira也不例外。  
  
但值得留意的是，这些黑客还运用另一款开源、跨平台的远程桌面连线工具RustDesk，有可能会架设自己的基础设施架构，或是利用其内建的点对点（P2P）连线功能，让攻击行动变得更为隐密。  
  
  
  
原文来源：E安全  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  

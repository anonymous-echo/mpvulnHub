#  DragonForce操作者利用SimpleHelp漏洞链式攻击某MSP服务商及其客户   
鹏鹏同学  黑猫安全   2025-05-28 01:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicAmjYqia2wT21gZv1kcVjKz11qRQuuP0hibe6sTzsq0BVCvqpHlNW4k1E8jMrLAmgwmrwSZXl5nXtg/640?wx_fmt=png&from=appmsg "")  
  
网络安全公司Sophos研究人员披露，某DragonForce勒索软件运营者利用远程管理软件SimpleHelp中的三个漏洞链（CVE-2024-57727、CVE-2024-57728、CVE-2024-57726）实施入侵，进而通过某托管服务商（MSP）的合法管理通道向其客户网络投放恶意负载。  
  
【漏洞技术分析】  
SimpleHelp是一款面向IT技术人员设计的远程支持软件，可实现计算机的远程控制与运维。此次被利用的三个漏洞构成完整攻击链：  
1. CVE-2024-57727（CVSS 7.5）：未授权路径遍历漏洞，攻击者可下载服务器敏感文件（含使用硬编码密钥加密的管理员密码哈希、LDAP凭证等）  
  
1. CVE-2024-57728（CVSS 7.2）：任意文件上传漏洞，结合管理员凭证可实现远程代码执行（Linux系统通过crontab提权，Windows系统通过覆盖可执行文件）  
  
1. CVE-2024-57726（CVSS 7.2）：权限提升漏洞，低权限技术人员账户可越权获取管理员权限  
  
【时间线】  
- 2025年1月6日：Horizon3向SimpleHelp提交漏洞报告  
  
- 1月13日：SimpleHelp发布5.3.9修补版本  
  
- 1月下旬：Arctic Wolf监测到利用漏洞的攻陷活动（漏洞公开披露一周后）  
  
【攻击手法】  
攻击者通过漏洞组合获取SimpleHelp服务器管理员权限后，利用MSP运维通道向客户终端推送伪装成合法安装包（实际为信息窃取程序）的恶意负载。经Sophos确认，攻击者通过该MSP的远程管理平台实施了以下操作：  
✓ 收集多客户端的设备配置、用户数据及网络拓扑  
✓ 尝试部署勒索软件（部分受Sophos MDR/XDR防护的客户成功拦截）  
✓ 未部署高级防护的客户网络遭实质性入侵  
  
【威胁背景】  
DragonForce勒索组织近期因攻击玛莎百货（Marks & Spencer）、英国合作社（Co-op）和哈罗德百货（Harrods）引发关注。该组织采用"加密+数据窃取"双重勒索模式，运营着基于Telegram/Discord的犯罪 affiliate 计划。网络安全专家评估其核心成员可能是英语母语的青少年黑客群体。  
  

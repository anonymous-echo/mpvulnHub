#  CISA 将 Progress Kemp LoadMaster 漏洞标记为易被攻击利用漏洞   
Rhinoer  犀牛安全   2024-12-22 17:08  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHrI2A3FmlwAu9wEPZbodQY64TBRyDicxWqiaFgYiaE0CfK6bwWkw8PsPrKg/640?wx_fmt=png&from=appmsg "")  
  
美国网络安全和基础设施安全局 (CISA) 在其已知利用漏洞 (KEV) 目录中增加了三个新漏洞，其中包括影响 Progress Kemp LoadMaster 的关键操作系统命令注入。  
  
该漏洞由 Rhino Security Labs 发现，编号为 CVE-2024-1212，已于 2024 年 2 月 21 日发布的更新中得到解决 。然而，这是首次有报告称该漏洞在野遭到积极利用。  
  
该漏洞的描述是：“Progress Kemp LoadMaster 包含一个操作系统命令注入漏洞，允许未经身份验证的远程攻击者通过 LoadMaster 管理界面访问系统，从而执行任意系统命令。”  
  
**CVE-2024-1212（CVSS v3.1 分数：10.0，“严重”）影响 LoadMaster 版本 7.2.48.1 之前、7.2.54.8 之前和 7.2.55.0 之前。**  
  
LoadMaster 是一种应用程序交付控制器 (ADC) 和负载平衡解决方案，大型组织使用它来优化应用程序性能、管理网络流量并确保高服务可用性。  
  
CISA 命令使用该产品的联邦组织在 2024 年 12 月 9 日之前应用可用的更新和缓解措施，否则停止使用它。  
  
目前尚未发布有关主动利用活动的详细信息，并且其在勒索软件活动中的利用状态被标记为未知。  
  
CISA 添加到 KEV 的另外两个漏洞是 CVE-2024-0012 和 CVE-2024-9474，分别是身份验证绕过和 OS 命令注入漏洞，影响 Palo Alto Networks PAN-OS 管理界面。  
  
Progress Software最近修复了LoadMaster 产品中的另一个最高严重性漏洞，该漏洞允许远程攻击者在设备上执行任意命令。  
  
该漏洞被标识为 CVE-2024-7591，被归类为不正确的输入验证问题，允许未经身份验证的远程攻击者使用特制的 HTTP 请求访问 LoadMaster 的管理界面。  
  
CVE-2024-7591 影响 LoadMaster 版本 7.2.60.0 及所有之前的版本，以及 MT Hypervisor 版本 7.1.35.11 及所有之前的版本。  
  
也就是说，希望升级到安全版本的系统管理员应该转向解决 LoadMaster 中两个最高严重性漏洞的版本，即使尚未发现对 CVE-2024-7591 的主动利用。  
  
  
信息来源：  
BleepingComputer  
  

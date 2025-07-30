#  漏洞预警 | Veeam Service Provider Console远程代码执行和信息泄露漏洞   
浅安  浅安安全   2024-12-12 00:00  
  
**0x00 漏洞编号**  
- CVE-2024-42448  
  
- CVE-2024-42449  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Veeam Service Provider Console是Veeam Software提供的一款专为云服务提供商设计的管理平台，该平台支持虚拟、物理或云端环境，旨在帮助云服务提供商更有效地管理其提供的备份即服务和灾难恢复即服务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SW874MUohXn367TXicEqzTqeEt8mxliaHRnyBAg5RhH6pPcVOQc0KJx2en1vrYhibTmY9zpyiayGa62MQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-42448**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
Veeam Service Provider Console存在远程代码执行漏洞，从VSPC管理代理机器上，在管理代理已在服务器上获得授权的条件下，攻击者可利用该漏洞从VSPC管理代理机器在未修补的服务器上执行任意代码，从而可能远程控制受影响的服务器，执行恶意操作，如窃取数据、破坏系统或部署恶意软件等。  
  
CVE-2024-42449  
  
**漏洞类型：**  
信息泄露  
  
**影响：**  
获取敏感信息  
  
**简述：**  
Veeam Service Provider Console存在另一个信息泄露漏洞，在VSPC管理代理在服务器上获得授权的情况下，攻击者可利用该漏洞窃取VSPC服务器服务帐户的NTLM哈希，并使用获得的访问权限删除VSPC服务器上的文件。  
  
**0x04 影响版本**  
- Veeam Service Provider Console <= 8.1.0.21377  
  
**0x05 POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.veeam.com/  
  
  
  
  

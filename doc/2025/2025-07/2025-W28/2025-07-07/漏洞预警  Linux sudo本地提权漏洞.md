> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493630&idx=3&sn=85a8466b2d752154d97df30291f0c2f8

#  漏洞预警 | Linux sudo本地提权漏洞  
浅安  浅安安全   2025-07-07 00:01  
  
**0x00 漏洞编号**  
- CVE-2025-32462  
  
- CVE-2025-32463  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Sudo是一款在类Unix系统中用于允许授权用户以其他用户的安全权限执行命令的工具，广泛应用于系统管理和运维过程中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUiaib8Dmib97zg6lgzjicwe4iayiaTzNh2OJJEDAZ9u5FguWcHRk69uX0x0wZiagmEbHJ3b14oWTuQ9bhRw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-32462**  
  
**漏洞类型：**  
本地提权  
  
**影响：**  
提升权限  
  
**简述：**  
Linux sudo host权限提升漏洞源于sudo的-h（--host）选项错误应用远程主机规则到本地，攻击者可绕过权限提升至root并执行任意代码。本地攻击者可利用该漏洞提升权限至root。  
  
**CVE-2025-32463**  
  
**漏洞类型：**  
本地提权  
  
**影响：**  
提升权限  
  
**简述：**  
Linux sudo chroot权限提升漏洞源于本地低权限用户通过特制的恶意chroot环境触发动态库加载，从而以root权限执行任意代码。  
  
**0x04 影响版本**  
  
CVE-2025-32462  
- 1.9.0 <= sudo <= 1.9.17  
  
- 1.8.8 <= sudo <= 1.8.32  
  
CVE-2025-32463  
- 1.9.14 <= sudo <= 1.9.17  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://www.sudo.ws/  
  
  
  

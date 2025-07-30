#  漏洞预警 | Jenkins任意文件读取漏洞   
浅安  浅安安全   2024-01-27 08:00  
  
**0x00 漏洞编号**  
- # CVE-2024-23897  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Jenkins是一个开源软件项目，是基于Java开发的一种持续集成工具，用于监控持续重复的工作，旨在提供一个开放易用的软件平台，使软件的持续集成变成可能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXLUBKY4FL4EtGicBPs7oYyRCLdExjmDvMROWuZEibdZIFZT9fibALJkOiaLF2l7Jx2icnAcoeKqI4P7Ow/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2024-23897**  
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息****  
  
**简述：**  
Jenkins中存在任意文件读取漏洞，由于其使用args4j库解析CLI命令参数，攻击者可利用相关特性读取Jenkins控制器文件系统上的任意文件，并结合其他功能等可能执行任意代码。  
###   
  
**0x04 影响版本**  
- Jenkins <= 2.441  
  
- Jenkins <= LTS 2.426.2  
  
**0x05 修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.jenkins.io/  
  
  
  

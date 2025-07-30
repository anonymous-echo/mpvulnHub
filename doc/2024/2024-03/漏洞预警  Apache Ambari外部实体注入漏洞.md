#  漏洞预警 | Apache Ambari外部实体注入漏洞   
浅安  浅安安全   2024-03-02 08:01  
  
**0x00 漏洞编号**  
- # CVE-2023-50380  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Ambari是一种基于Web的工具，支持Apache Hadoop集群的供应、管理和监控。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXwCq1ryjzf7MMcj7GbibrGsHpZjFXibn8j3y3uadvdEtiauyNRiaRNm1wunzpTHaSaPV7oia9NhCu3iciag/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2023-50380**  
  
**漏洞类型：**  
XML外部实体注入  
  
**影响：**  
获取敏感数据  
  
**简述：**  
在Apache Ambari中的Oozie Workflow Scheduler存在XML外部实体注入漏洞，由于缺乏正确的用户输入验证，允许低权限用户读取根级文件并提升权限，攻击者可以利用XXE漏洞读取服务器上的任意文件，包括敏感系统文件。  
###   
  
**0x04 影响版本**  
- apache ambari <= 2.7.7  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://ambari.apache.org/  
  
  
  

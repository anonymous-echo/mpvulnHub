#  漏洞预警 | Aviatrix Controller命令注入漏洞   
浅安  浅安安全   2025-01-15 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-50603  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Aviatrix Controller是一款强大的云网络管理平台，提供简化的跨云网络管理、自动化配置、安全策略、流量监控等功能，帮助企业实现更加灵活、安全和高效的云网络架构，特别适用于多云和混合云环境。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVkFdQtD1w6hW1aqBKDvPKCmx5wJu7nib1mBEyt7IIaIg9U368CWQWQnvHic5bylztibI6Kc9ic1Njw2Q/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-50603**  
  
**漏洞类型：**  
命令注入  
  
**影响：**  
执行任意命令  
  
****  
  
**简述：**  
Aviatrix Controller中存在命令注入漏洞，由于对/v1/api下list_flightpath_destination_instances操作中的cloud_type参数或flightpath_connection_test操作中的src_cloud_type参数缺乏适当的输入清理，可能导致命令注入漏洞，未经身份验证的远程攻击者可以构造恶意请求，利用该漏洞执行任意命令。  
  
**0x04 影响版本**  
- Aviatrix Controller < 7.1.4191  
  
- Aviatrix Controller 7.2.x < 7.2.4996  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://aviatrix.com/  
  
  
  

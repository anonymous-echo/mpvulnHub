#  漏洞预警 | JumpServer JINJA2注入代码执行漏洞   
浅安  浅安安全   2024-04-04 09:01  
  
**0x00 漏洞编号**  
- # CVE-2024-29202  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Jumpserver 是一款使用 Python, Django 开发的开源跳板机系统, 为互联网企业提供了认证，授权，审计，自动化运维等功能，基于ssh协议来管理，客户端无需安装agent。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXGQIIlHG6aTeP4zxVCPMbbJFicSnyc1CiaVNgicc49tj8zJiajouqJ2HKXojicFa0lEBhYEvNeLfs4CVg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
****  
**CVE-2024-29202**  
  
**漏洞类型：**  
JINJA2注入代码  
  
**影响：**  
  
执行任意代码  
  
**简述：**  
JumpServer v3.0.0 - v3.10.6版本中存在漏洞，具有低权限用户帐户的攻击者可通过构建恶意playbook模板利用Ansible中的Jinja2模板代码注入漏洞在Celery容器中执行任意代码。由于Celery容器以root权限运行并具有数据库访问权限，因此攻击者可以从所有主机窃取敏感信息或操纵数据库。  
###   
  
**0x04 影响版本**  
- v3.0.0 <= JumpServer <= v3.10.6  
  
**0x05****POC**  
  
https://github.com/jumpserver/jumpserver/security/advisories/GHSA-2vvr-vmvx-73ch  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.jumpserver.org/  
  
  
  

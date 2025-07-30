#  漏洞预警 | IBOS企业协同管理软件SQL注入漏洞   
浅安  浅安安全   2025-04-30 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
IBOS企业协同管理软件是一款基于PHP开发、Yii框架的开源企业协同管理软件，提供沟通协作、知识管理、工作流等六大功能平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVrEfFKWMiaE4oN9JBbTUtaemjNCTLLTowDMPwPHmBQgusibpjFDKnK3micHiahLvKLnd3UTCTPy5rxDw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
IBOS企业协同管理软件的r=main/api/orguser接口存在SQL注入漏洞，未授权的攻击者可以通过该漏洞拼接恶意SQL语句，从而获取数据库敏感信息。  
  
**0x04 影响版本**  
- IBOS企业协同管理软件  
  
**0x05****POC状态**  
- **已公开**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.ibos.com.cn/  
  
  
  

#  漏洞预警 | 灵当CRM任意文件上传和SQL注入漏洞   
浅安  浅安安全   2024-12-30 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
灵当CRM是一款专为中小企业打造的智能客户关系管理工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVt7YFyTQQEfhb7U1ia1Eib9LbzN6IooEiaAu8gmJRoBbalGtmLHyIvibmIAvPanxUHCsPxmIasVyUNAA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件上传  
  
**影响：**  
上传恶意脚本文件  
  
****  
  
**简述：**  
灵当CRM的uploadfile.php接口存在任意文件上传漏洞，未经身份验证的攻击者可以通过该漏洞上传恶意脚本文件，从而控制目标服务器。  
  
漏洞类型：  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
灵当CRM的getMyAmbassador接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用SQL注入漏洞获取数据库中的信息之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
**0x04 影响版本**  
- 灵当CRM  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.51mis.com/  
  
  
  

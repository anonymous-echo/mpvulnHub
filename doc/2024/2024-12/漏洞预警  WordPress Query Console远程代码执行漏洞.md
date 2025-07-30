#  漏洞预警 | WordPress Query Console远程代码执行漏洞   
浅安  浅安安全   2024-12-17 00:00  
  
**0x00 漏洞编号**  
- CVE-2024-50498  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
WordPress Query Console曾是一个为WordPress平台提供查询功能的插件，允许用户在WordPress后台通过插件界面执行各种查询，可能包括数据库查询、REST API查询等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVAKGNs1n6V1Y0PZEHjPRmaICY57VJloVKIAfS2aNM5Qknx6toV5bnat9b6dXdfkJmHI3TRAIsozA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
CVE-2024-50498  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：WordPress Query Console的/index.php?rest_route=/wqc/v1/query接口存在远程代码执行漏洞，未经身份验证的远程攻击者可利用此插件执行任意代码，从而控制目标服务器。**  
  
**0x04 影响版本**  
- WordPress Query Console <= 1.0  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://cn.wordpress.org/plugins/wp-query-console/  
  
  
  

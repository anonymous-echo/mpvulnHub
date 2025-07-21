> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493769&idx=1&sn=89febd1aefe606db1792ffd89f135a01

#  漏洞预警 | SemCms SQL注入漏洞  
浅安  浅安安全   2025-07-21 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-51652  
  
- # CVE-2025-51653  
  
- # CVE-2025-51654  
  
- # CVE-2025-51655  
  
- # CVE-2025-51656  
  
- # CVE-2025-51657  
  
- # CVE-2025-51658  
  
- # CVE-2025-51659  
  
- # CVE-2025-51660  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
SemCms是一套开源外贸企业网站管理系统，主要用于外贸企业，兼容IE、Firefox等主流浏览器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVt8tSfkAvhVxfgiatiacpt4zErW8mV6v7hzNnBe4ricajEXbPXNRtjricvC8BsSomVctFWWHqWvDMusw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-51652**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
SemCms的/admin/SEMCMS_Categories.php  
接口存在SQL注入漏洞，获取授权的攻击者可以通过该漏洞执行任意SQL语句，从而获取数据库敏感信息。  
  
CVE-2025-51653  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
SemCms的/admin/SEMCMS_ct.php  
接口存在SQL注入漏洞，  
获取授权的攻击者可以通过该漏洞执行任意SQL语句，从而获取数据库敏感信息。  
  
CVE-2025-5165  
4  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
SemCms的/admin/  
SEMCMS_Infocategories.php  
接口存在SQL注入漏洞，  
获取授权的攻击者可以通过该漏洞执行任意SQL语句，从而获取数据库敏感信息。  
  
CVE-2025-51655  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
SemCms的/admin/  
SEMCMS_Quanxian.php  
接口存在SQL注入漏洞，  
获取授权的攻击者可以通过该漏洞执行任意SQL语句，从而获取数据库敏感信息。  
  
CVE-2025-51656  
、CVE-2025-51657  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
SemCms的/admin/  
SEMCMS_Link  
.php  
接口存在SQL注入漏洞，  
获取授权的攻击者可以通过该漏洞执行任意SQL语句，从而获取数据库敏感信息。  
  
CVE-2025-51658  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
SemCms的/admin/  
SEMCMS_InquiryView  
.php  
接口存在SQL注入漏洞，  
获取授权的攻击者可以通过该漏洞执行任意SQL语句，从而获取数据库敏感信息。  
  
CVE-2025-5165  
9、CVE-2025-51660  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
SemCms的/admin/  
SEMCMS_Products.php  
接口存在SQL注入漏洞，  
获取授权的攻击者可以通过该漏洞执行任意SQL语句，从而获取数据库敏感信息。  
  
**0x04 影响版本**  
- SemCms <= 5.0  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.sem-cms.com/  
  
  
  

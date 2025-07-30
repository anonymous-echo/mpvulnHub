#  漏洞预警 | WordPress Plugin Tutor SQL注入漏洞   
浅安  浅安安全   2025-01-06 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-10400  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Tutor LMS是一个轻量级、功能丰富且强大的WordPressLMS插件，可以轻松地在线创建和销售课程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXfjAibRSNGWpmwPlJwZg4r8icMMltBZYgW9GclQm8jHtAicPjHY4g8giaj9tPuiaNYKEkWcJLs5ZGyvlA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-10400**  
  
**漏洞类型：**  
SQL注入****  
  
**影响：**  
  
获取敏感信息  
  
  
****  
  
**简述：**  
WordPress插件Tutor LMS的/wp-admin/admin-ajax.php接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- Tutor LMS <= 2.7.6  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://cn.wordpress.org/plugins/tutor/  
  
  
  

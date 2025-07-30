#  漏洞预警 | 妖气山视频管理系统SQL注入漏洞   
浅安  浅安安全   2025-05-26 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
妖气山视频管理系统是一款运用Javaex前端框架与SSM后端框架开发的视频管理软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUbmX0ibArcSDFVV83KXCV08uhtPj2jDqhypQtoBxibKF5XHYdjMZOEiaIGicmPgURcKVEL8Nk7xufnoA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
妖气山视频管理系统的/api/get_media_list_by_filter.json接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 妖气山视频管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://github.com/user-xiangpeng/yaoqishan  
  
  
  

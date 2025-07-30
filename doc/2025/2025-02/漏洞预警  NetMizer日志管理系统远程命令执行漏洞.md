#  漏洞预警 | NetMizer日志管理系统远程命令执行漏洞   
浅安  浅安安全   2025-02-11 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
NetMizer日志管理系统是一款可以记录流经设备的所有会话日志并将其传送到外部的管理中心上的系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUgFcdTclLpaibaNFbexjyNfok47S50jQeiaXgwQhyHdFNLgRrI4w7iau9icVfth12be0ze1PjDzgXJlQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
远程  
命令  
执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
NetMizer日志管理系统的/data/manage/cmd.php接口存在远程命令执行漏洞，由于该接口未做身份验证和参数过滤，未授权的攻击者可以通过此接口执行任意命令获取服务器权限，从而造成数据泄露、服务器被接管等严重的后果。  
  
**0x04 影响版本**  
- NetMizer日志管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.lingzhou.com.cn/  
  
  
  

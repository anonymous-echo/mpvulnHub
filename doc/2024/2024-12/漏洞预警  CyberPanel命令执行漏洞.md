#  漏洞预警 | CyberPanel命令执行漏洞   
浅安  浅安安全   2024-12-24 00:01  
  
**0x00 漏洞编号**  
- # CVE-2024-53376  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
CyberPanel是一个开源的Web控制面板，它提供了一个用户友好的界面，用于管理网站、电子邮件、数据库、FTP账户等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUNl1K8QYt0kne3TvEh7kEBosyE7bsF75WCk1DtQZnpBGFCzkfBbb2MJeueD2ju6bTUuuKSWJdMsA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-53376**  
  
**漏洞类型：**  
命令  
执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
CyberPanel的/websites/submitWebsiteCreation接口存在命令执行漏洞，经过授权的攻击者可以通过此接口执行任意命令获取服务器权限，从而造成数据泄露、服务器被接管等严重的后果。  
  
**0x04 影响版本**  
- CyberPanel < 2.3.8  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://github.com/usmannasir/cyberpanel  
  
  
  

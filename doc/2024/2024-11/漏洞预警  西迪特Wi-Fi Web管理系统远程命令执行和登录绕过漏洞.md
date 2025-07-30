#  漏洞预警 | 西迪特Wi-Fi Web管理系统远程命令执行和登录绕过漏洞   
浅安  浅安安全   2024-11-30 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
西迪特提供的Wireless解决方案为客户提供一套云管理,可靠性高,覆盖范围广的无线组网产品。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVWUkxxltiaJdA3BTAAzJwUKuicibPvENK9YxgwwWvV8Gq5F1N6T62LExfaKl7ZXQn8IbdAicbM6lPBUA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
### 漏洞类型：远程代码执行  
  
  
**影响：**  
执行任意代码  
  
**简述：**  
西迪特Wi-Fi Web管理系统的/cgi-bin/jumpto.php接口存在未授权远程代码执行漏洞，攻击者通过漏洞可以获取服务器权限。  
  
漏洞类型：  
登录绕过  
  
  
**影响：**  
接管服务  
  
**简述：**  
西迪特Wi-Fi Web管理系统的cookie使用硬编码凭据，导致攻击者可以绕过登录进入后台。  
  
**0x04 影响版本**  
- 西迪特Wi-Fi Web管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.cdatatec.com.cn/  
  
  
  

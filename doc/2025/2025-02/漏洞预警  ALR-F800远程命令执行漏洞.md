#  漏洞预警 | ALR-F800远程命令执行漏洞   
浅安  浅安安全   2025-02-13 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
ALR-F800可根据环境进行智能调整和配置，提供业界最佳的以太网供电传输功率和性能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUwXyfYXUesLFq9ZFTycId6dibAmkTX4xbncyrxMUcft7mScESibkZzRZB2HicZm02UcOBzlCkLTQmAw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
远程  
命令  
执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
ALR-F800的/cmd.php接口存在命令执行漏洞，未经授权的攻击者可以执行任意CLI命令，包括修改网络配置和登录凭据。  
  
漏洞类型：  
远程  
命令  
执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
ALR-F800的/cgi-bin/upgrade.cgi和/admin/system.html接口存在命令执行漏洞，经授权的攻击者可以写入恶意文件、执行任意命令。  
  
**0x04 影响版本**  
- ALR-F800  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.alientechnology.com/  
  
  
  

#  漏洞预警 | JeecgBoot表达式注入漏洞   
浅安  浅安安全   2024-11-21 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
JeecgBoot是一款基于代码生成器的低代码开发平台。前后端分离架构 SpringBoot2.x，SpringCloud，Ant Design&Vue，Mybatis-plus，Shiro，JWT，支持微服务。强大的代码生成器让前后端代码一键生成，实现低代码开发。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SW25cvic5s59KsEGyS6fTiaaogPXrsntzHQO87dEEoxdTnicwvibHLUm8wvIaRo5oQWGzJqicZPr2Q7G9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
表达式注入  
  
**影响：**  
执行任意代码  
  
**简述：**  
Jeecg-Boot的/jeecg-boot/jmreport/save接口存在表达式注入漏洞，未经身份验证的攻击者可以通过该漏洞远程注入代码，从而控制目标服务器。  
###   
  
**0x04 影响版本**  
- Jeecg-Boot < 1.8.0  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.jeecg.com/  
  
  
  

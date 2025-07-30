#  漏洞预警 | JEEWMS JDBC反序列化漏洞   
浅安  浅安安全   2025-02-28 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
JEEWMS基于JAVA的仓库管理系统，包含PDA端和WEB端，功能涵盖WMS、OMS、BMS、TMS。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SV5c5fjMPRA8L7bFrkibpMUW5zfvTx0EzgSfXq1p3JdQsULDGic38X1VvEEenMmdEscsTfP1p4HXujA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
反序列化  
  
**影响：**  
执行任意命令  
  
**简述：**  
JEEWMS的/rest/../dynamicDataSourceController.do接口存在JDBC反序列化漏洞，未经身份验证的攻击者可以通过该漏洞远程执行任意代码，从而影响目标服务器正常运行。  
  
**0x04 影响版本**  
- JEEWMS  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.huayi-tec.com/  
  
  
  

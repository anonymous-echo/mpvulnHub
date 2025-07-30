#  漏洞预警 | Cisco ISE反序列化漏洞   
浅安  浅安安全   2025-02-07 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-20124  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
ISE是下一代NAC解决方案，用于在零信任架构内管理终端、用户和设备对网络资源的访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU7yiaA9KHbxNq1iaCtatkAMRdMxh9GQW5qsybAMVCfgV1icAvzV2Y7tKZDV9WTF3l0dMcaKaNR0jllQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-20124**  
  
**漏洞类型：**  
反序列化  
  
**影响：**  
执行任意命令  
  
**简述：**  
Cisco ISE存在反序列化漏洞，由于其对用户提供的Java Byte流处理不当，经过身份验证的远程攻击者可以通过向受影响的API发送制作的序列化Java对象来利用此漏洞，从而在设备上执行任意命令并提高特权。  
  
**0x04 影响版本**  
- Cisco ISE  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.cisco.com/  
  
  
  

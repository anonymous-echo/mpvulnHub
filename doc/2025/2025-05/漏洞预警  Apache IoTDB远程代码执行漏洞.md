#  漏洞预警 | Apache IoTDB远程代码执行漏洞   
浅安  浅安安全   2025-05-19 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-24780  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache IoTDB是一个专为物联网数据存储和处理设计的高效时序数据库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVwWibtHtFlZ66q8fNxV24O0qLWbNkFjxjZ4mGp3yqJB1mbwibkKYJr1dHwyv80wzFr2ib7gMb29dlvw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-24780**  
  
**漏洞类型：**  
代码执行  
  
**影响：**  
执行任意代码  
  
  
  
**简述：**  
Apache IoTDB存在远程代码执行漏洞，攻击者可以通过不可信的URI注册恶意的用户定义函数，进而执行任意代码。  
  
**0x04 影响版本**  
- 1.0.0 <= Apache IoTDB < 1.3.4  
  
**0x05****POC状态**  
- 未公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://iotdb.apache.org/  
  
  
  

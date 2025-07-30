#  漏洞预警 | 7-Zip Mark-of-the-Web绕过漏洞   
浅安  浅安安全   2025-01-25 00:03  
  
**0x00 漏洞编号**  
- CVE-2025-0411  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
7-Zip是一款免费开源文件归档应用程序，具有高压缩比，可用于压缩和解压文件，支持多种存档格式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXN459Lwib0eEka1Qy6f0ahF0Z8hFvS229f2LHHicMiadhmeUNogJib2UWzfAvVMaiaPUuAVCEcNgyfZvg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2025-0411**  
  
**漏洞类型：**  
Mark-of-the-Web绕过  
  
**影响：**  
执行任意代码  
  
**简述：**  
7-Zip存在Mark-of-the-Web绕过漏洞，在于归档文件的处理过程中，当从带有Mark-of-the-Web标记的恶意归档中提取文件时，7-Zip未能将该标记正确传播到提取的文件，攻击者可借此漏洞在当前用户权限下执行任意代码。  
  
**0x04 影响版本**  
- 7-Zip < 24.09  
  
**0x05 POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.7-zip.org/  
  
  
  

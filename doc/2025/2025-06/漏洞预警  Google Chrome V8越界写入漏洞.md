#  漏洞预警 | Google Chrome V8越界写入漏洞   
浅安  浅安安全   2025-06-02 23:00  
  
**0x00 漏洞编号**  
- # CVE-2025-5280  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Google Chrome V8是一个高效的开源JavaScript引擎，用于Chrome浏览器和 Node.js等平台。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/7stTqD182SXxjX8p8WklXuc23v1DKPW7yY83Sic75o0z0rlPgZHmmCPxBNvutPR92HthYPDsg7ia0ODDgsgQYjBQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-5280**  
  
**漏洞类型：越界写入**  
  
**影响：**  
执行任意代码  
  
**简述：**  
Google Chrome的V8引擎中存在越界写入漏洞，攻击者可通过构造恶意HTML页面，诱使受害者访问，从而触发越界写入操作，导致堆内存损坏，使攻击者能够执行任意代码或引发其他安全风险。  
  
**0x04 影响版本**  
- Google Chrome < 137.0.7151.55  
  
**0x05 POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
chrome://settings/help  
  
  
  

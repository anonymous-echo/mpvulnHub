#  漏洞预警 | DocsGPT远程代码执行漏洞   
浅安  浅安安全   2025-03-03 00:01  
  
**0x00 漏洞编号**  
- # CVE-2025-0868  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
DocsGPT是一个AI驱动的文档助手，基于GPT技术，用于智能搜索和解析技术文档，帮助开发者快速获取API说明、代码示例和问题解答。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXokIUEumKMX7rksZVbvbVjJ0Vz3RXhhUlo9BwhTaQxe6TmtW8BZFAAiaHmHOE4y5VN6emnIJJuHvA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-0868**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
DocsGPT的/api/remote接口存在远程代码执行漏洞，未经身份验证的攻击者可以通过该漏洞远程执行任意代码，从而控制目标服务器。  
  
**0x04 影响版本**  
- 0.8.1 <= DocsGPT <= 0.12.0  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://github.com/arc53/DocsGPT  
  
  
  

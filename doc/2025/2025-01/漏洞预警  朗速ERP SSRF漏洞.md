#  漏洞预警 | 朗速ERP SSRF漏洞   
浅安  浅安安全   2025-01-13 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
朗速ERP是一款由朗速科技推出的企业资源计划软件，旨在帮助企业实现资源的高效管理和全面优化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXmJaNdJcVPOibCzCLogHKfI1EQaou5RH7hmwc6XaddzUwTFiap0HM8zIibCUhhOdX9FPrzKAWg5JPMA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SSRF  
  
**影响：**  
上传恶意文件****  
  
**简述：**  
朗速ERP的/Api/UEditor/UEditorAjaxApi.ashx接口存在SSRF漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件，导致网站处于极度不安全状态。  
  
**0x04 影响版本**  
- 朗速ERP  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.lserp.com/  
  
  
  

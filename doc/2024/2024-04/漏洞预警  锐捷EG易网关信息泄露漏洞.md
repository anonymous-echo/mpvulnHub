#  漏洞预警 | 锐捷EG易网关信息泄露漏洞   
浅安  浅安安全   2024-04-20 09:02  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
锐捷EG易网关是一款综合网关产品，集成了先进的软硬件体系构架，并配备了DPI深入分析引擎、行为分析/管理引擎。这款产品能在保证网络出口高效转发的基础上，提供专业的流控功能、出色的URL过滤以及本地化的日志存储/审计服务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXnlC3jOakKJzvt6mcRvjchLw9tUm2n4iciaz6Qa5WkY2uo1D5dTUTGQ5yzAbpoQSCF1sTH3A8uAggw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
信息泄露  
  
**影响：**  
获取敏感信息  
  
**简述：**  
锐捷EG易网关/tool/view/phpinfo.view.php存在信息泄露漏洞，未授权的攻击者可以通过该漏洞获取大量敏感信息。  
###   
  
**0x04 影响版本**  
- 锐捷EG易网关  
  
**0x05****POC**  
  
https://github.com/iamHuFei/HVVault/blob/main/webdev/%E9%94%90%E6%8D%B7/ruijie-eg-tool-view-phpinfo-infoleak.yaml  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.ruijie.com.cn/  
  
  
  

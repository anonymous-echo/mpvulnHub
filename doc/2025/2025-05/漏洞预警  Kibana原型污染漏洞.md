#  漏洞预警 | Kibana原型污染漏洞   
浅安  浅安安全   2025-05-13 00:01  
  
**0x00 漏洞编号**  
- # CVE-2025-25014  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Kibana是开源的分析和可视化平台，与Elasticsearch协同工作。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVfia5ic72rVO3ibe89wGDHnaqsBptofD3BJaBpfty5dcsnKnFsFXI93EehqIYicibXtTib0V52zOxR9Scw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-25014**  
  
**漏洞类型：**  
原型污染  
  
**影响：**  
执行任意代码  
  
**简述：**  
Kibana存在原型污染漏洞，  
攻击者可通过精心构造的HTTP请求，利用Kibana的机器学习和报告端点，可能导致任意代码执行。  
  
**0x04 影响版本**  
- 8.3.0 <= Kibana <= 8.17.5  
  
- Kibana 8.18.0  
  
- Kibana 9.0.0  
  
**0x05 POC状态**  
- **未公开**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.elastic.co/cn/kibana  
  
  
  

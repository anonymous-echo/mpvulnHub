#  漏洞预警 | Apache Airflow pickle反序列化漏洞   
浅安  浅安安全   2024-01-27 08:00  
  
**0x00 漏洞编号**  
- # CVE-2023-50943  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
Apache Airflow是一个开源的工作流自动化平台，Apache Airflow CNCF Kubernetes provider是给Airflow提供Kubernetes支持的工具包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUVDa55czc3eerc9Kib3GiciafINLPUrv6eEYFibib95IIvw0BORbWv0DO2CP3bEKydaMErDnfAAPP8p6w/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2023-50943**  
  
**漏洞类型：**  
反序列化  
  
**影响：**  
数据中毒  
  
**简述：**  
Apache Airflow 2.8.1之前的版本存在反序列化漏洞，允许潜在攻击者绕过“enable_xcom_pickling=False”配置设置的保护来毒害XCom数据，从而导致XCom反序列化后数据中毒。  
###   
  
**0x04 影响版本**  
- Apache Airflow < 2.8.1  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://airflow.apache.org/  
  
  
  

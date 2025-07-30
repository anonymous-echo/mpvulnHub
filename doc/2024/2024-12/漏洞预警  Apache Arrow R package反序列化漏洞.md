#  漏洞预警 | Apache Arrow R package反序列化漏洞   
浅安  浅安安全   2024-12-09 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-52338  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Arrow是一种通用的列式格式和多语言工具箱，用于快速数据交换和内存分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXmqBsiblH0BvyZ49iclLyYb2QOJDGG3ct0OFjiafhOmDUfpy45EOriaYiaibpsdVZicmRxF0O1OT5lQOXiaA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-52338**  
  
**漏洞类型：**  
反序列化  
  
  
**影响：**  
  
执行任意代码  
  
**简述：**  
Apache Arrow R包存在反序列化漏洞，该漏洞源于IPC和Parquet数据读取器在处理元数据时未对输入进行严格验证，攻击者可通过构造恶意的Arrow IPC、Feather或Parquet文件，在元数据中嵌入恶意对象，当应用程序加载这些文件时，unserialize()函数会直接解析元数据，可能触发反序列化漏洞，从而导致任意代码执行。  
  
**0x04 影响版本**  
- 4.0.0 <= Apache Arrow R package <= 16.1.0  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://arrow.apache.org/  
  
  
  
  

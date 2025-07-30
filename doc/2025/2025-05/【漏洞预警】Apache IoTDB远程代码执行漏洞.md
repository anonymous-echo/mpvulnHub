#  【漏洞预警】Apache IoTDB远程代码执行漏洞   
cexlife  飓风网络安全   2025-05-14 14:59  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00PNCONtbUeyO04ONCBBueKkkSBjl5CG6eeiadODXuqnCxMtqBe9IbBKotM0hNqvmxicPOicicUAAGYyw/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
Apache IoTDB是一款专为物联网（IoT）场景设计的高性能时序数据库管理系统由清华大学发起是Apache基金会旗下的Top-Level项目。它采用端边云协同的轻量化架构,支持一体化的物联网时序数据收集、存储、管理与分析Apache IoTDB存在一个远程代码执行漏洞,攻击者可以通过不受信任的URI注册恶意用户定义函数（UDF）,从而实现远程代码执行。  
  
受影响产品或系统:  
  
Apache IoTDB = 20250514  
  
修复方案:  
  
官方已发布最新版,详情见:oss-sec:CVE-2024-24780:Apache IoTDB:Remote Code Execution with untrusted URI of User-defined function  
  
建议用户升级到Apache IoTDB 1.3.4版本  
  
参考链接:  
  
https://www.apache.org/dyn/closer.cgi/iotdb/1.3.4/apache-iotdb-1.3.4-all-bin.zip  
  
补丁名称:Apache IoTDB  
  
补丁链接:https://iotdb.apache.org/  
  
  

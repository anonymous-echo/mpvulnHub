#  Apache修复了Apache Traffic Control中的一个严重SQL注入漏洞   
鹏鹏同学  黑猫安全   2024-12-26 23:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceib8NkJFRuqMpVshxjVgBTJHm9OF4YKxulQy66d9vPkseq23nQErhVsqgpsKH6TUvtRcOKp4Ivnszw/640?wx_fmt=png&from=appmsg "")  
  
Apache软件基金会（ASF）发布了安全更新，以解决Traffic Control中的一个严重安全漏洞，追踪为CVE-2024-45387（CVSS评分9.9）。Traffic Control允许操作员快速和高效地将内容分配给用户。  
  
Traffic Control是一个高度分布式、可扩展和冗余的解决方案，满足从小到大操作员的需求。该漏洞是Traffic Control（<= 8.0.1、>= 8.0.0）中的SQL注入漏洞，它允许拥有特权用户执行任意的SQL命令。“Apache Traffic Control <= 8.0.1、>= 8.0.0中的Traffic Ops SQL注入漏洞允许具有‘admin’、‘federation’、‘operations’、‘portal’或‘steering’角色的privileged用户通过发送特别构造的PUT请求执行对数据库的任意SQL操作。” advisory中reads。“如果您运行受影响的Traffic Ops版本，建议升级到Apache Traffic Control 8.0.2版本。”Traffic Control 7.0.0之前的版本不受该漏洞影响。研究员Yuan Luo从腾讯云鼎安全实验室报告了漏洞。  
  
早些时候，Apache软件基金会发布了一个安全更新，以解决Struts 2中的“可能远程代码执行”漏洞，该漏洞与OGNL技术相关。该远程代码执行漏洞，追踪为CVE-2020-17530，存在于强制OGNL评估中，当评估在原始用户输入的标记属性时。  
  

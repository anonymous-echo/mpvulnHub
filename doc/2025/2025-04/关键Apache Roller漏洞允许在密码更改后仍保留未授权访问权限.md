#  关键Apache Roller漏洞允许在密码更改后仍保留未授权访问权限   
鹏鹏同学  黑猫安全   2025-04-16 03:21  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceibrMwUxrqM0n6Um3h0UCicDcHicTgGQ8icYh3tJVx5IDR5xVtokoxUicGhZHibBmnnBib77nrf5N3tRcJPg/640?wx_fmt=png&from=appmsg "")  
  
Apache Roller开源博客软件曝出高危漏洞（CVE-2025-24859，CVSS评分10.0），该Java开发的博客服务器在6.1.5之前版本存在会话管理缺陷：修改密码后仍可沿用旧会话保持未授权访问。  
  
该漏洞影响Apache Roller 6.1.4及更早版本，当用户或管理员修改密码时，系统未能正确终止现有活跃会话。安全公告指出："攻击者可利用该缺陷，在凭证泄露后通过旧会话维持非法访问权限，即使密码已完成修改。"版本6.1.5通过实施集中式会话管理机制修复该问题，确保密码修改或账户停用时所有会话立即失效。漏洞由研究员Haining Meng提交。  
  
值得注意的是，本月初Apache Parquet Java库刚曝出另一个CVSS 10.0分漏洞（CVE-2025-30065）。这个用于读写Parquet列式存储文件的开源库在1.15.0及更早版本存在反序列化缺陷，攻击者通过篡改文件可实现远程代码执行。该漏洞可追溯至1.8.0版本，影响Hadoop、Spark、Flink等大数据框架及所有使用受影响Parquet版本的自建系统。官方建议用户立即核查技术栈中的潜在风险。  
  
  
  
  

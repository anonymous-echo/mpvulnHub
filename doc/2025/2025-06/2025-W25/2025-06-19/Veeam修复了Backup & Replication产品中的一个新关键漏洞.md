> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTc0NDcyNQ==&mid=2247494051&idx=1&sn=824b2b262ccd14013ff47b1150ee5f2e

#  Veeam修复了Backup & Replication产品中的一个新关键漏洞  
鹏鹏同学  黑猫安全   2025-06-19 01:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce96Px8ssUa5fAWicZo7HcoN6O8GXfM3Yunu3YWxCG9av0NKPhUr45BgevciaRFcYEYEFTq9bz9LdfyQ/640?wx_fmt=png&from=appmsg "")  
  
Veeam已发布安全补丁，修复其Backup & Replication解决方案中一个关键安全漏洞（编号CVE-2025-23121，CVSS评分9.9）。该漏洞可能允许远程攻击者在特定条件下执行任意代码。  
  
厂商发布的公告称："该漏洞允许经过身份验证的域用户在备份服务器上实现远程代码执行（RCE）"。受影响版本包括Backup & Replication 12.3.1.1139及之前所有12.x版本。该漏洞由CODE WHITE GmbH和watchTowr公司的研究人员报告。  
  
Rapid7研究团队的技术分析显示：2025年3月针对CVE-2025-23120的补丁发布后，研究人员发现其可被绕过从而衍生出CVE-2025-23121。Veeam在6月17日的公告中确认，该漏洞CVSS评分为9.9，且与先前漏洞类似，可被经过认证的域用户利用。  
  
"CVE-2025-23121的发现归功于CODE WHITE GmbH和watchTowr的安全研究人员。2025年3月，在Veeam发布CVE-2025-23120补丁后，这些研究人员公开表示该补丁可被绕过。"Rapid7报告指出，"Veeam新公告确认CVE-2025-23121同样需要身份验证，CVSS评分9.9，且利用条件与CVE-2025-23120完全一致。"  
  
Veeam还修复了另一个影响Backup & Replication产品的漏洞（CVE-2025-24286，CVSS评分7.2）。具有备份操作员权限的认证用户可利用该漏洞修改备份任务，进而执行任意代码。该漏洞由趋势科技的Nikolai Skliarenko发现。  
  
第三个被修复的漏洞（CVE-2025-24287，CVSS评分6.1）影响Veeam Agent for Microsoft Windows。公告称："该漏洞允许本地系统用户修改目录内容，从而以提升权限执行任意代码。"该漏洞由CrisprXiang通过趋势科技零日计划提交。  
  
  

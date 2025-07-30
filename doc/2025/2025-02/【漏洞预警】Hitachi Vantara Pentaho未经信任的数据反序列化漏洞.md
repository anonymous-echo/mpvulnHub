#  【漏洞预警】Hitachi Vantara Pentaho未经信任的数据反序列化漏洞   
cexlife  飓风网络安全   2025-02-20 12:53  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01lB6SgX60QOwNKRRHR8LlD9hJTejOlibgeH31s3TXEicAs2Gx2ib87QmV20m8IMRSrmgNkJgUDax0rQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
应用程序在没有充分验证结果数据是否有效的情况下反序列化不受信任的数据,Hitасhi Vаntаrа Pеntаhо Buѕinеѕѕ Anаlуtiсѕ Sеrvеr版本在10.2.0.0和9.3.0.9之前包括 8.3.х,在反序列化不受信任的JSON数据时没有限制解析器只能使用经过批准的类和方法,当开发者对“小工具链”（即在反序列化过程中可能自我执行的一系列实例和方法调用）没有设置任何限制时（即在对象返回给调用者之前）,攻击者有时可以利用它们来执行未经授权的操作。  
  
影响产品及版本:  
  
Hitachi Vantara Pentaho Business Analytics Server  
  
受影响的版本为:  
  
10.0<=Pentaho Data Integration & Analytics<10.2.0.0  
  
1.0<=Pentaho Business Analytics Server<9.3.0.9  
  
攻击场景:  
  
攻击者可能通过上传恶意JSON数据对系统进行攻击  
  
修复建议:  
  
漏洞可能被用于拒绝服务和代码执行攻击,建议用户升级至最新版本  
  
建议措施:  
  
更新系统补丁,限制解析器只能使用经过批准的类和方法,强化输入验证  
  
  
参考链接:  
  
https://support.pentaho.com/hc/en-us/articles/34298351866893--Resolved-Hitachi-Vantara-Pentaho-Business-Analytics-Server-Improper-Neutralization-of-Input-During-Web-Page-Generation-Cross-site-Scripting-Versions-before-10-2-0-0-and-9-3-0-9-including-8-3-x-Impacted-CVE-2024-37360  
  
  
  

#  【漏洞通告】Apache Struts 2远程代码执行漏洞安全风险通告   
 嘉诚安全   2024-12-12 08:46  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Apache Struts 2中存在一个远程代码执行漏洞，漏洞编号为：  
CVE-2024-53677。  
  
  
Apache Struts 2是一个基于MVC设计模式的Web应用框架，可用于创建企业级Java web应用程序。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞  
。Apache Struts 2多个受影响版本中文件上传逻辑存在缺陷，由于在文件上传过程中对用户提供的参数缺乏严格校验，攻击者可以通过操纵文件上传参数执行路径遍历攻击，某些情况下可能导致将恶意文件上传到服务器上的其他位置，从而导致远程代码执行。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Apache Struts 2.0.0 - 2.3.37 (EOL)  
  
Apache Struts 2.5.0 - 2.5.33  
  
Apache Struts 6.0.0 - 6.3.0.2  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可将Apache Struts框架升级到6.4.0或更高版本，并在升级后迁移到新的文件上传机制（即使用Action File Upload Interceptor来处理文件上传），从而防止该漏洞。  
  
下载链接：  
  
https://struts.apache.org/download.cgi  
  
注意：不使用FileUploadInterceptor模块的应用程序不受该漏洞影响。  
  
参考链接：  
  
https://cwiki.apache.org/confluence/display/WW/S2-067  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-53677  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  

#  Fortinet修复了已被积极利用的FortiVoice零日漏洞   
鹏鹏同学  黑猫安全   2025-05-14 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce93JSicR8RMksdROtjxEPC0bVFh9ibib3WAHlb6w3XONtCR4ke1RKfm3ricjHTXYDT2odMqUVczxNic0gA/640?wx_fmt=png&from=appmsg "")  
  
Fortinet发布安全更新，修复了一个已被用于攻击FortiVoice企业电话系统的关键远程代码执行零日漏洞（编号CVE-2025-32756）。该漏洞为栈溢出漏洞，影响FortiVoice、FortiMail、FortiNDR、FortiRecorder和FortiCamera等多款产品。未经身份验证的远程攻击者可通过构造恶意HTTP请求实现任意代码或命令执行。  
  
根据安全公告："FortiVoice、FortiMail等产品中的栈溢出漏洞（CWE-121）可能允许攻击者通过特制HTTP请求执行任意代码。Fortinet已发现该漏洞在针对FortiVoice的野外攻击中被利用。"  
  
攻击者利用该漏洞后，会执行网络扫描、清除崩溃日志，并启用fcgi调试功能以窃取系统或SSH登录凭证。Fortinet安全团队还观察到攻击者在受感染服务器上部署恶意软件、添加凭证窃取定时任务，以及使用脚本扫描受害者网络。  
  
根据Fortinet共享的威胁指标（IoC），攻击源包括六个IP地址：198.105.127.124、43.228.217.173等。另一个关键IoC是受害系统上异常的"fcgi调试"启用状态。用户可通过CLI命令"diag debug application fcgi"检测，若输出显示"general to-file ENABLED"则表明系统可能已遭入侵（该设置默认关闭）。  
  
Fortinet建议临时禁用HTTP/HTTPS管理接口作为缓解措施。  
  
  

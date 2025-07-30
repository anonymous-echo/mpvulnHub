#  近期 Apache Struts 2 严重漏洞开始被利用   
三沐  三沐数安   2024-12-30 11:53  
  
研究人员警告称，恶意攻击利用 Apache Struts 2 中最近修补的严重漏洞，导致远程代码执行 (RCE)。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8h3Oia1MDoibpE3gJDvf5vSk9nPCudEMy1Uny1Vib2juXooRMGR8mIibvmeB5Prkwttu9sM38eXYlsNBg/640?wx_fmt=png&from=appmsg "")  
  
**在 Apache Struts 2 中一个严重漏洞被公开披露后不到一个月，威胁行为者就开始利用该漏洞。**  
  
该问题被标记为 CVE-2024-53677（CVSS 评分为 9.5），是一个文件上传逻辑缺陷，可能使攻击者能够执行路径遍历攻击。  
  
Apache 在其公告中指出：“攻击者可以操纵文件上传参数来实现路径遍历，在某些情况下，这可能导致上传可用于执行远程代码执行的恶意文件。”  
  
本质上，攻击者可以利用此漏洞将恶意文件放置在受限目录中，这可能使他们窃取数据，执行任意代码，并可能完全破坏系统。  
  
云安全公司 Qualys 指出：“Apache Struts 是许多企业 IT 堆栈的核心，推动面向公众的门户、内部生产力应用程序和关键业务工作流。它在高风险环境中的流行意味着像 CVE-2024-53677 这样的漏洞可能会产生深远的影响。 ”  
  
该漏洞影响已停产的 Struts 版本 2.0.0 至 2.3.37 和 2.5.0 至 2.5.33，以及版本 6.0.0 至 6.3.0.2。  
  
Struts 6.4.0 版通过弃用易受攻击的文件上传机制 FileUploadInterceptor 解决了此安全缺陷。Apache 表示，除了更新 Struts 之外，用户还应迁移到不受影响的新机制 ActionFileUploadInterceptor。  
  
然而，该公司警告称，这一变化不向后兼容，用户必须重写他们的操作才能开始使用新机制。  
  
  

#  补丁警报：严重 Apache Struts 漏洞被攻击者积极利用   
Rhinoer  犀牛安全   2024-12-19 03:35  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBkn3xMmExrxXGAGia0vhnnibe51YIKPwicyfibRFKgpvFWfsosxJRM76pQSqjXyicxKMjgZDaISOSoiaU4w/640?wx_fmt=png&from=appmsg "")  
  
攻击者正试图利用最近披露的影响 Apache Struts 的安全漏洞，这可能为远程代码执行铺平道路。  
  
该漏洞的编号为**CVE-2024-53677**  
，CVSS 评分为 9.5（满分 10.0），表明严重程度很高。该漏洞与项目维护人员在 2023 年 12 月解决的另一个严重漏洞（  
CVE-2023-50164  
，CVSS 评分：9.8）有相似之处，该漏洞  
在公开披露后不久也  
遭到了积极利用。  
Apache 建议称：“攻击者可以操纵文件上传参数来实现路径遍历，在某些情况下，这可能导致上传可用于执行远程代码执行的恶意文件。”换句话说，成功利用该漏洞可以允许恶意行为者将任意负载上传到易受攻击的实例，然后可以利用这些负载运行命令，窃取数据或下载其他负载以进行后续利用。该漏洞影响以下版本，并已在 Struts 6.4.0 或更高版本中得到修补 -Struts 2.0.0 - Struts 2.3.37（已终止使用），Struts 2.5.0 - Struts 2.5.33，以及Struts 6.0.0 - Struts 6.3.0.2SANS 技术研究所研究主任约翰内斯·乌尔里希 (Johannes Ullrich) 博士表示，CVE-2023-50164 的不完整补丁可能导致了新的问题，并补充说，已经在野检测到与公开发布的概念验证 (PoC) 相匹配的利用尝试。此时，漏洞利用尝试枚举易受攻击的系统，”Ullrich指出。“接下来，攻击者尝试找到上传的脚本。到目前为止，扫描仅来自 169.150.226[.]162。”  
为了降低风险，建议用户尽快升级到最新版本，并重写代码以使用新的  
Action File Upload机制  
和相关拦截器。  
  
Qualys 威胁研究部门产品经理 Saeed Abbasi表示  
：“Apache Struts 是许多企业 IT 堆栈的核心，推动面向公众的门户网站、内部生产力应用程序和关键业务工作流程。  
它在高风险环境中的流行意味着像 CVE-2024-53677 这样的漏洞可能会产生深远的影响。”  
  
  
信息来源：TheHackerNews  
  

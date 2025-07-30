#  vm2再爆沙箱逃逸漏洞   
ang010ela  嘶吼专业版   2023-04-25 12:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
vm2再爆沙箱逃逸漏洞，CVSS评分9.8。  
  
VM2是nodejs 实现的一个沙箱环境，一般用于测试不受信任的 JavaScript 代码。允许代码部分执行，可以预防对系统资源和外部数据的非授权访问。VM2通过NPM的月下载量超过1600万，被广泛应用于IDE、代码编辑器、FaaS解决方案、渗透测试框架、安全工具和其他JS相关的产品中。  
  
过去几周，多名安全研究人员先后发现了VM2中的多个沙箱逃逸漏洞，分别是Seongil Wi发现的CVE-2023-29017漏洞和SeungHyun Lee发现的CVE-2023-29199、CVE-2023-30547漏洞。攻击者利用这些漏洞可以绕过沙箱环境的限制运行恶意代码。CVE-2023-29017漏洞影响vm2 3.9.14之前版本，VM2已在3.9.15版本中修复了该漏洞。  
# CVE-2023-30547：沙箱逃逸漏洞  
  
CVE-2023-30547漏洞是由来自韩国科学技术院（KAIST）的SeungHyun Lee发现的，该漏洞属于异常处理漏洞，允许攻击者在handleException()内引发未处理的主机异常，CVSS评分9.8分。  
  
handleException()函数负责处理沙箱中的异常以预防主机信息泄露。但如果攻击者设置一个定制的getPrototypeOf()代理处理器来抛出未处理的主机异常，handleException()函数就无法处理该异常。那么攻击者就可以访问主机函数，即绕过沙箱的限制实现逃逸，并可以在主机环境内执行任意代码。  
# PoC  
  
Lee同时在GitHub上发布了该漏洞的PoC代码以证明攻击的可行性，PoC代码如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28X2PtZ9gXwq1EcORXiayJ1orhia3qhrJ0zk2I6C8iaTfpHUa7hJ2zqf2KPWWgJWGDgHjJiaDQbnlciacQ/640?wx_fmt=png "")  
  
在该PoC中，攻击者成功在主机上创建了一个明文pwned的文件。  
  
PoC代码参见：https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244  
# 漏洞影响和补丁  
  
漏洞影响 VM2 3.9.16及之前版本。目前VM2已在v3.9.17版本中修复了该漏洞。建议所有用户和软件开发人员对包含了VM2库的项目进行升级以修改该漏洞。  
  
经与Seongil Wi确认，Seongil Wi发现的漏洞与Lee发现的漏洞之间并无关联。  
  
参考及来源：https://www.bleepingcomputer.com/news/security/new-sandbox-escape-poc-exploit-available-for-vm2-library-patch-now/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28X2PtZ9gXwq1EcORXiayJ1o3xBvvHscGvRyxZlg5xCD46wEN8InyAp1iaunt1xuOuViaG1mpZic8v2Wg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28X2PtZ9gXwq1EcORXiayJ1oviaNvbo40QqtBb1HFQ3ejXI47ibVAx9pPX8vC0sA36aLpMKcHNHdtR8A/640?wx_fmt=png "")  
  
  

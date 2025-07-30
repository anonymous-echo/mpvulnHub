#  DirtyCred：存在8年的Linux kernel漏洞   
 关键基础设施安全应急响应中心   2022-08-29 14:59  
  
研究人员发现存在8年的Linux kernel漏洞——DirtyCred。  
  
美国西北大学研究人员在Linux kernel中发现了一个存在长达8年之久的安全漏洞——DirtyCred，CVE编号为CVE-2022-2588，攻击者利用该漏洞可以将权限提升到最高级别。  
  
**Dirty pipe**  
  
Dirty pipe 是Linux kernel pipe子系统中一个非常严重的安全漏洞，CVE编号为CVE-2022-0847，CVSS评分7.8分。攻击者利用该漏洞可以实现任意可读文件的写入，从而实现权限提升，而且无需处理kernel地址随机化和指针完整性检查的问题。目前，还没有针对该漏洞的利用应对方案。Dirty pipe可以绕过所有的kernel保护措施，但漏洞利用无法实现容器逃逸。  
# DirtyCred  
  
Kernel凭证是kernel文档中定义的kernel中携带特权信息的特征，表示权限和对应的能力。主要分为task凭证(struct cred)和open file凭证(struct file)。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o282TD8LSyxACInPH2KI9WWpXNSMhXCCglSF1982hrwqCOzoTbakl6XHS4Pwkg5zibK99P5nqKKUUkg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
task凭证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o282TD8LSyxACInPH2KI9WWpEaliamzOTUI40LjGxXxzAyORZX1fa9bWt8kzZZj8CsfWCDbHg92oNoA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
open file凭证  
  
在现实中会对凭证对象进行安全检查。DirtyCred是一个kernel利用概念，可以将非特权的Linux kernel凭证与特权kernel凭证进行交换以实现权限提升。CVE编号CVE-2022-2588，DirtyCred的利用攻击也分为task凭证攻击和open file凭证攻击。  
  
task凭证攻击步骤：  
  
释放非特权的凭证；  
  
在释放的内存slot中分配特权凭证；  
  
以特权用户运行；  
  
open file凭证攻击步骤：  
  
在检查后、写入硬盘前释放文件obj，  
  
在释放的内存slot中分配制度的文件obj；  
  
以特权用户运行，写入内容到文件；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o282TD8LSyxACInPH2KI9WWpcDqic0CVvtejJUiaiaZxdfeIyviaYHaKb5s6kFMke1zLDWfaRb3hxfbpkA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
DirtyCred 是一个通用的漏洞利用方法，非常简单和高效。研究人员证明了漏洞利用方法可以实现类似dirty-pipe的能力，可以覆写任意文件来实现权限提升除了覆写kernel堆中的数据域，DirtyCred可以滥用堆内存重用机制来实现权限提升，并实现容器逃逸。此外，漏洞利用继承了dirty pipe的优势，可以无需修改就攻击各种kernel版本。  
  
**PoC参见GitHub：**  
  
https://github.com/markakd/dirtycred  
  
**完整演讲报告参见：**  
  
https://i.blackhat.com/USA-22/Thursday/US-22-Lin-Cautious-A-New-Exploitation-Method.pdf  
  
**参考及来源：**  
  
https://www.blackhat.com/us-22/briefings/schedule/#cautious-a-new-exploitation-method-no-pipe-but-as-nasty-as-dirty-pipe-27169  
  
  
  
原文来源  
：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  

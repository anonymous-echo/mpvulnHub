> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795507&idx=3&sn=b838061f320cd4b062980aa56c512d1f

#  APT36（透明部落） 利用凭证窃取恶意软件攻击印度国防安全部门  
会杀毒的单反狗  军哥网络安全读报   2025-06-23 01:01  
  
**导****读**  
  
  
  
APT36，又名“透明部落”，是一个总部位于巴基斯坦的网络间谍组织，一直通过高度复杂的网络钓鱼活动积极攻击印度国防人员。根据CYFIRMA的调查结果，该组织传播包含恶意PDF附件的网络钓鱼电子邮件，这些附件经过精心设计，伪装成政府官方文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFQA7TpicYvyNkicjBMJPNUwWNZiaWficN4C9ia3o31qJP03qVoeyBo7EhMP5iaGicoibhSk69abAicD9HNiarQ/640?wx_fmt=png&from=appmsg "")  
  
  
当收件人打开其中一个 PDF 文件时，它会显示模糊的背景以及一个模仿国家信息中心 (NIC) 登录界面的按钮。点击此按钮会将用户重定向到一个欺诈性 URL，并开始下载一个包含恶意可执行文件的 ZIP 压缩包，该文件伪装成合法应用程序。  
  
  
该组织传播伪装成官方文档的恶意PDF文件，引导用户访问虚假的NIC登录页面，最终下载伪装的恶意软件，目的是窃取凭证，从而长期访问敏感网络。这凸显了加强电子邮件安全、用户安全意识培训和持续威胁监控的迫切需求。  
  
  
在此次活动中，该组织分发了包含名为“PO-003443125.pdf”的嵌入式 PDF 文件的网络钓鱼电子邮件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFQA7TpicYvyNkicjBMJPNUwW6NlicSXWVXC42PiaMwrhac9x0oIhVUdr5AcD37y4rZDYWELicNp1lRC0A/640?wx_fmt=png&from=appmsg "")  
  
  
打开后，文档会呈现模糊的背景（这是一种刻意为之的策略，旨在营造一种虚假的真实感）、PDF 图标、文件名“PO-003443125.pdf”，以及一条消息：“这是一份受保护的文档。点击下方按钮即可访问内容”。  
  
  
一个醒目的按钮——标有“点击查看文档”——吸引收件人点击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFQA7TpicYvyNkicjBMJPNUwWf2xBg7cbRIo3oS9qleicbuKIGILOMwg2F8bj3890icSssw8rBryNl7aA/640?wx_fmt=png&from=appmsg "")  
  
  
用户点击后将被重定向到恶意 URL“hXXps://superprimeservices[.]com/nishat/order/PO-003443125.pdf.7z”，从而启动“PO-003443125.pdf.7z”档案的下载。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFQA7TpicYvyNkicjBMJPNUwWib2ZMz5aJpW7DKdrRXSAAorRIMHgumGTd6bl97axLosT8XdKW7roZTg/640?wx_fmt=png&from=appmsg "")  
  
  
该存档包含一个名为“PO-003443125.pdf.exe”的恶意可执行文件，该文件伪装成合法的PDF图标。该文件旨在误导用户，执行后可通过未经授权的访问危害目标系统。  
  
  
APT36 对印度构成重大威胁，尤其针对印度国防基础设施。该组织使用先进的网络钓鱼策略和凭证盗窃手段，体现了现代网络间谍活动日益复杂的特点。  
  
  
应对这一挑战需要实施全面、多层次的网络安全框架，包括强大的电子邮件安全措施、持续的用户教育以及高度警惕的威胁检测和响应能力。  
  
  
技术报告：  
  
https://www.cyfirma.com/research/apt36-phishing-campaign-targets-indian-defense-using-credential-stealing-malware/  
  
  
新闻链接：  
  
https://www.cyfirma.com/research/apt36-phishing-campaign-targets-indian-defense-using-credential-stealing-malware/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  

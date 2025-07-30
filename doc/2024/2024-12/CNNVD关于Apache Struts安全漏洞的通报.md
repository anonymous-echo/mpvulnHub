#  CNNVD关于Apache Struts安全漏洞的通报   
原创 CNNVD  CNNVD安全动态   2024-12-12 07:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/g1thw9Goocf2Ufz929a1thwAyKI8uIwUT7yfu4ibROBCthXslE23ia0ibWJVYlkxqulYy37zyiblBfrwib4m7erTkbQ/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/k5xJjBPo8ceEDyDtWwClGjzMFF89SzKxRwqsR5z89FRTn8YhflGDHd440FiafMOgcV0GYmiawnCH2GUGYcaciaG8g/640?&wx_fmt=gif "")  
  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aqTr2WnSRI6o0t7BMQpMu5RC6OgKfSTia0iclOkC3ibiao2LBH88P7F9nDjxDzYq9Y9PicS0OlPseqmQqHfiaM4TVq1w/640?&wx_fmt=gif "")  
  
  
  
  
**漏洞情况******  
  
近日，国家信息安全漏洞库（CNNVD）收到关于Apache Struts安全漏洞（CNNVD-202412-1393、CVE-2024-53677）情况的报送。成功利用漏洞的攻击者，可以操纵文件上传参数来启用路径遍历，进而上传可用于执行远程利用代码的恶意文件。Apache Struts 2.0.0-2.3.37版本、Apache Struts 2.5.0-2.5.33版本、Apache Struts 6.0.0-6.3.0.2版本均受此漏洞影响。目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
## 一漏洞介绍  
  
  
Apache Struts是美国阿帕奇（Apache）软件基金会下属的Jakarta项目中的一个子项目，是一个基于MVC设计的Web应用框架。漏洞源于Apache Struts中的文件上传模块存在逻辑缺陷导致，未经授权的攻击者可以操纵文件上传参数来启用路径遍历，进而上传可用于执行远程利用代码的恶意文件，启用了FileUploadInterceptor 模块的应用受此漏洞影响。  
  
## 二危害影响  
  
  
Apache Struts 2.0.0-2.3.37版本、Apache Struts 2.5.0-2.5.33版本、Apache Struts 6.0.0-6.3.0.2版本均受此漏洞影响。  
  
## 三修复建议  
  
  
目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方升级链接：  
  
https://struts.apache.org/download.cgi  
  
本通报由CNNVD技术支撑单位——深信服科技股份有限公司、北方实验室（沈阳）股份有限公司、贵州蓝天创新科技有限公司、道普信息技术有限公司、塞讯信息技术（上海）有限公司等技术支撑单位提供支持。  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。联系方式: cnnvd@itsec.gov.cn  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/tV4JDvMn6RMFN7ExSt7AEhx1DPNW68Bt8SXrAelC5L01auTNJkN19gJn8zP0hPAhSMHibfRNj70fV2aDD6u681Q/640?&wx_fmt=gif "")  
  
  

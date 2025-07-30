#  CNNVD关于Apache OFBiz安全漏洞的通报   
原创 CNNVD  CNNVD安全动态   2024-11-20 09:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/g1thw9Goocf2Ufz929a1thwAyKI8uIwUT7yfu4ibROBCthXslE23ia0ibWJVYlkxqulYy37zyiblBfrwib4m7erTkbQ/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/k5xJjBPo8ceEDyDtWwClGjzMFF89SzKxRwqsR5z89FRTn8YhflGDHd440FiafMOgcV0GYmiawnCH2GUGYcaciaG8g/640?&wx_fmt=gif "")  
  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aqTr2WnSRI6o0t7BMQpMu5RC6OgKfSTia0iclOkC3ibiao2LBH88P7F9nDjxDzYq9Y9PicS0OlPseqmQqHfiaM4TVq1w/640?&wx_fmt=gif "")  
  
  
  
  
  
**漏洞情况**  
  
近日，国家信息安全漏洞库（CNNVD）收到关于Apache OFBiz安全漏洞(CNNVD-202411-2279、CVE-2024-47208)情况的报送。攻击者可以利用漏洞向目标发送恶意请求，通过服务端请求伪造的方式远程执行任意代码。Apache OFBiz 18.12.17以下版本受此漏洞影响。目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
## 一漏洞介绍  
  
  
Apache OFBiz是美国阿帕奇（Apache）基金会的一套企业资源计划（ERP）系统。该系统提供了一整套基于Java的Web应用程序组件和工具。漏洞源于程序对URL校验不严格，攻击者可通过构造恶意URL绕过校验并注入Groovy 表达式代码或触发服务器端请求伪造（SSRF）攻击，导致远程代码执行。  
  
## 二危害影响  
  
  
Apache OFBiz 18.12.17以下版本受此漏洞影响。  
  
## 三修复建议  
  
  
目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方下载链接如下：  
  
https://ofbiz.apache.org/download.html  
  
本通报由CNNVD技术支撑单位——北京神州绿盟科技有限公司、深信服科技股份有限公司、西安交大捷普网络科技有限公司、数字新时代（山东）数据科技服务有限公司、安恒愿景（成都）信息科技有限公司、网宿科技股份有限公司等技术支撑单位提供支持。  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。联系方式: cnnvd@itsec.gov.cn  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/tV4JDvMn6RMFN7ExSt7AEhx1DPNW68Bt8SXrAelC5L01auTNJkN19gJn8zP0hPAhSMHibfRNj70fV2aDD6u681Q/640?&wx_fmt=gif "")  
  
  

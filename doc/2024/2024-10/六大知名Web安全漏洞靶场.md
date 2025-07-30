#  六大知名Web安全漏洞靶场   
原创 筑梦网安  全栈安全   2024-10-19 15:30  
  
>   
> 如果想搞懂一个漏洞，最好的方法是先编写出这个漏洞，然后利用它，最后修复它。漏洞靶场模拟真实环境，它为网络安全人员提供了一个安全可控的平台，用于发现、评估和测试应用程序、系统或网络设备的安全漏洞。WEB漏洞靶场可帮助安全人员熟悉SQL注入、跨站脚本（XSS）、跨站请求伪造（CSRF）等漏洞利用过程。  
  
# 0. 写在最前  
  
在非授权情况下，对于网站进行渗透测试攻击，是触及法律法规的，所以我们常常需要自己搭建一个漏洞靶场，**避免直接对公网非授权目标进行测试**。  
  
由于漏洞靶场包含了大量的高危安全漏洞，若在公网环境下安装可能会吸引大量扫描请求，遭受黑客攻击。如果是个人或中小型企业，一般**建议使用私网环境或者受控的测试网络来进行安装**。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMI8gpqxGRibUGfddfEFZkJoHV61HQic0fQEw2UHNGiaE1GibxMp9CKx54kHg/640?wx_fmt=png&from=appmsg "")  
  
知名WEB漏洞靶场  
  
以下将要介绍的漏洞靶场对OWASP Top 10的漏洞均有覆盖，大家可以在不同靶场环境中对同一类型的安全漏洞进行渗透尝试，加深对WEB漏洞原理的理解。  
  
博主往期发布了10+篇关于WEB典型安全漏洞原理的技术专栏，感兴趣的可以直接点击跳转阅读，专栏地址：[https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzkyMTYyOTQ5NA==&action=getalbum&album_id=3482464501872574469#wechat_redirect。](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzkyMTYyOTQ5NA==&action=getalbum&album_id=3482464501872574469#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMIQyFoOZ0vCR3zKgPSM9ObVyiboMH0fRicTusUCsWSxjreh0dgma6BaTBw/640?wx_fmt=png&from=appmsg "")  
  
典型WEB漏洞原理  
# 1. Pikachu  
  
Pikachu是一个带有漏洞的Web应用系统，包含了常见的web安全漏洞。如果你是一个Web渗透测试学习人员且正发愁没有合适的靶场进行练习，那么Pikachu可能正合你意。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMImhnuXGK4kBzO3Pj3gDTQBHGicIjmt4msHMTlAwFNozI8ZlGicSvFVJ5Q/640?wx_fmt=png&from=appmsg "")  
  
Pikachu漏洞靶场  
  
**技术栈**：PHP，MYSQL，中间件（如apache,nginx等）  
  
**项目地址**：https://github.com/zhuifengshaonianhanlu/pikachu  
  
**Docker安装**：支持  
# 2. DVWA  
  
Web安全入门必刷的靶场，包含了最常见的web漏洞，界面简单易用，通过设置不同的难度，可更好地理解漏洞的原理及对应的代码防护。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMI8ZatwpJKe3QxypdHlAyEKxSrnVB2IVPIevSiatbibE0tVy0XCTCNdjiag/640?wx_fmt=png&from=appmsg "")  
  
DVWA靶场环境  
  
**技术栈**：PHP，mariadb，中间件（如apache,nginx等）  
  
**项目地址**：https://github.com/digininja/DVWA  
  
**Docker安装**：支持  
# 3. OWASP Benchmark  
  
OWASP Benchmark是一个完全可运行的开源 Web 应用程序，包含3000左右个测试用例，每个测试用例都映射到特定的 CWE，可以通过任何类型的应用程序安全测试 (AST) 工具进行分析。OWASP Benchmark的所有漏洞也都是可利用的，因此它对任何类型的应用程序漏洞检测工具都是公平的测试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMIibnDlib8efuLoxRhiarrfgpkCaH4w05JWyCT46SMrCVnQ446pe86Tg2Mg/640?wx_fmt=png&from=appmsg "")  
  
OWASP Benchmark靶场环境  
  
**技术栈**：JAVA，Mysql，Tomcat  
  
**项目地址**：https://github.com/OWASP-Benchmark/BenchmarkJava  
  
**Docker安装**：支持  
  
若想了解如何通过镜像方式安装运行OWASP Benchmark，可以参阅博主往期文章：  
- [《OWASP Benchmark镜像方式安装、配置及如何生成SAST和DAST工具的评分报告》](http://mp.weixin.qq.com/s?__biz=MzkyMTYyOTQ5NA==&mid=2247484208&idx=2&sn=f34ab9f93e51b09428c6f190384bf869&chksm=c181e569f6f66c7f2daafba86b3e1fa8706d904987750d0435a9cd764ae56d115b60f5c7246f&scene=21#wechat_redirect)  
  
  
# 4. WebGoat  
  
WebGoat是一个由OWASP维护的不安全的web应用程序，旨在供人们学习应用程序安全和渗透测试技术。  
>   
> 注：运行此程序时的计算机极易受到攻击。我们在使用此程序时应该断开与Internet的连接。WebGoat的默认配置绑定到localhost以最小化暴露。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMItv8XVichp58oNQrPricqTp9bY3Aibr8ibRTW3uFibia7Qqno4BLDsWSLRV4g/640?wx_fmt=png&from=appmsg "")  
  
WebGoat靶场环境  
  
**技术栈**：JAVA，Mysql，Tomcat  
  
**项目地址**：https://github.com/WebGoat/WebGoat  
  
**Docker安装**：支持  
# 5. Vulhub  
  
支持一键搭建漏洞测试靶场，只需执行两个简单的命令，你就有了一个易受攻击的环境。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMIwoMiaDaBMxKaNPgCgIpxykJ8RT8PiaZtz3fMibVic4usMxS1eJuG1U3ibJw/640?wx_fmt=png&from=appmsg "")  
  
Vulhub在线靶场  
  
**技术栈**：Python，Java，PHP  
  
**项目地址**：https://github.com/vulhub/vulhub  
  
**在线靶场**：https://vulhub.org  
  
**Docker安装**：支持  
# 6. vulnweb  
  
上面介绍的五个漏洞靶场都有源代码的，我们在学习漏洞原理的同时还可以尝试如何修复漏洞。  
  
vulnweb是AWVS的测试站点，用于扫描效果验证，提供了多场景的公网靶场，常用于漏洞利用演示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMI4R1bxzvoKCR3HF3PwvMLHghK33jRgictkKY98uE2iahfoZnXYXtbC8HA/640?wx_fmt=png&from=appmsg "")  
  
vulnweb  
  
**技术栈**：Apache, PHP, MySQL，Python  
  
**在线靶场**：http://vulnweb.com  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp9o19LTFUh1g6z7PRQ74BMINDI11X0qCLdZcKYLbHX6vDWkjeEBMQdgDIibzD0BXOLHL2Osc1CFicAw/640?wx_fmt=png&from=appmsg "")  
  
  

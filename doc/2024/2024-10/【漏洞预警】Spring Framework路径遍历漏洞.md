#  【漏洞预警】Spring Framework路径遍历漏洞   
cexlife  飓风网络安全   2024-10-18 17:30  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02bUKgyZaYnvc8q4SL6JJRhrzy9X2cFFO6p2NYZia79W2iasvgwyrMEN5lfR23uX8LeEEUcvMib3ygPg/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述：  
VMware Spring Framework是美国威睿（VMware）公司的一套开源的Java、JavaEE应用程序框架，该框架可帮助开发人员构建高质量的应用,VMware发布安全公告,其中公开了一个存在Spring Framework中的路径遍历漏洞,当应用使用WebMvc.fn or WebFlux.fn功能提供静态资源时,允许攻击者通过精心构造的HTTP请求访问或操作服务器上本不应该被访问的文件,该漏洞和CVE-2024-38816原理一致,但输入点不同。  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02bUKgyZaYnvc8q4SL6JJRhV1H9CPb9euMy0yJWg5RUMhK3j6iaaTq3aJRoSaat00HseTlN4QgvOKg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02bUKgyZaYnvc8q4SL6JJRh5N1TKHEoic4zibspDNDzCwqBJeNu6prO1loQEIwyGlCVG7tmSZEUp8vQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02bUKgyZaYnvc8q4SL6JJRh1ATbPwJg8x6MByILCic9mwo6S34dqia6HVkz201qbOAicmw3svuE1cUwQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02bUKgyZaYnvc8q4SL6JJRhfmcvUWd5Dx7REgxecjMxQ8Sf13ric5bEMWRmc2mfo5XLEyib0hCXGkzA/640?wx_fmt=png&from=appmsg "")  
  
**修复建议:**  
**正式防护方案:**官方已经发布了修复补丁,请立即更新到安全版本:Spring Framework >= 5.3.41Spring Framework >= 6.0.25Spring Framework >= 6.1.14**下载链接:**https://github.com/spring-projects/spring-framework/tags**参考链接:**https://spring.io/security/cve-2024-38819  

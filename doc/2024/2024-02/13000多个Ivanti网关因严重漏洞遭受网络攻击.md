#  13000多个Ivanti网关因严重漏洞遭受网络攻击   
 网安百色   2024-02-18 19:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo6TLA19pviaCFfbrwwfDkd81KlLEPjVUhNmpUTv82EJhu2QnczPmf7nU0UicVQhD3icJZp2vicGaWur0w/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6xcM7jUIKuWckeXQK1iamAxRib844sOj55I11KezMUYEdRvGSibDugH8AwIic4NhUa9KRQkGxtuU1D7Rw/640?wx_fmt=jpeg&from=appmsg "")  
  
近日，数千个Ivanti Connect Secure和Policy Secure端点受到多个安全问题的攻击，这些问题在一个多月前首次披露，并由供应商逐步修复。具体漏洞为CVE-2024-22024、CVE-2023-46805、CVE-2024-21887、CVE-2024-21893和CVE-2024/21888。它们的严重程度从高到严重不等，涉及身份验证绕过、服务器端请求伪造、任意命令执行和命令注入问题。  
  
  
报道称，其中一些漏洞在被广泛的威胁行为者大规模利用之前，就已被民族国家行为者利用。从CVE-2024-22024开始，问题是Ivanti Connect Secure、Policy Secure和ZTA网关的SAML组件中存在XXE漏洞，这些漏洞允许授权访问受限资源。  
  
   
  
上周首次披露，但尚未确认有活动漏洞，该供应商建议，如果没有可用的补丁，立即应用可用的安全更新或缓解措施至关重要。  
  
   
  
Akamai今天发布的一份报告提到，针对这一特定缺陷的扫描活动已经开始，在2024年2月11日达到峰值，有240000个请求和80个IP试图发送有效载荷。  
  
   
  
威胁监测服务Shadowserver报告称，其互联网扫描显示，3900多个Ivanti端点易受CVE-2024-22024攻击。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6xcM7jUIKuWckeXQK1iamAxR0m2e85Wuyj2wBJiaPDUzubxRSCSofjj6d3p8SeaFLWZEFWhiaECauzWw/640?wx_fmt=jpeg&from=appmsg "")  
  
该组织发现大约有1000个Ivanti端点仍然容易受到CVE-2024-21887的攻击，这是一个漏洞，通过发送特定的请求，经过身份验证的管理员可以在易受攻击的设备上执行任意命令。  
  
   
  
该漏洞于2024年1月10日首次被披露为零日漏洞，据报道被中国黑客利用，同时还有身份验证绕过问题CVE-2023-46805。  
  
   
  
Macnica的安全研究员Yutaka Sejiyama今天早些时候与BleepingComputer分享了他的Shodan扫描结果，报告称截至2024年2月15日00:15 UTC，有13636台Ivanti服务器尚未为CVE-2024-21893、CVE-2024-21 888、CVE-2023-46805和CVE-2024-21887应用补丁。  
  
   
  
Ivanti早在一个多月前的2024年1月31日就提供了这四个漏洞的安全更新。  
  
   
  
根据研究人员的说法，暴露在互联网上的伊万蒂服务器总数为24239台，这意味着其中一半以上的服务器仍未修补。  
  
   
  
关于2024年2月8日披露并修复的CVE-2024-22024，Sejiyama的研究显示，截至目前，全球修补率为77.3%，5496台服务器暴露在危险的未经授权访问漏洞中。  
  
   
  
不幸的是，影响Ivanti产品的缺陷在短时间内被披露，管理员几乎没有时间准备应用补丁。  
  
这使补救工作复杂化，并增加了Ivanti系统长期易受攻击的风险，为威胁行为者提供了大量潜在受害者。  
  
  
  
  
  
  
  
来源：E安全  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo6M60aLu6MNdy20VjcnyaGECz7d9mYhdbclWg7wibJsickPUrnmNyFcvsjSYUqq5OPVPEXfW1SwkXCw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo57Spb4ibrib8VUZd2ibdF9wHbvr4RwYJ4H2z6571icFIdSZXIpNH2YfW16ETwHh3ict3gtpW3W2fJqDmw/640?wx_fmt=gif "")  
  
长按添加关注，为您保驾护航！  
  
  

